import concurrent.futures
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from app import create_app
from build_release import ROOT_FILES, build
from catalog import PRESETS
from security import local_secret, private_database, private_directory
import test_app as fixtures


class RequestHardeningTests(unittest.TestCase):
    setUp = fixtures.ShopTests.setUp
    tearDown = fixtures.ShopTests.tearDown
    post = fixtures.ShopTests.post
    register = fixtures.ShopTests.register

    def test_origin_rejects_same_site_sibling_even_with_valid_csrf(self):
        self.client.get('/')
        with self.client.session_transaction() as state:
            token = state['csrf']
        for origin in ('https://evil.example', 'http://sub.localhost', 'null',
                       'http://localhost:5001', 'http://localhost@evil.example',
                       'http://localhost:invalid'):
            with self.subTest(origin=origin):
                result = self.client.post('/logout', data={'csrf_token': token}, headers={
                    'Origin': origin, 'Sec-Fetch-Site': 'same-site'})
                self.assertEqual(result.status_code, 403)
        result = self.client.post('/logout', data={'csrf_token': token},
                                  headers={'Origin': 'http://localhost:80'})
        self.assertEqual(result.status_code, 302)

    def test_local_mode_does_not_serve_remote_clients_or_trust_forwarded_ip(self):
        for headers in ({}, {'X-Forwarded-For': '127.0.0.1'}):
            result = self.client.get('/', environ_overrides={'REMOTE_ADDR': '192.0.2.10'},
                                     headers=headers)
            self.assertEqual(result.status_code, 403)

    def test_new_password_minimum_and_legacy_login(self):
        self.post('/register', {'name': 'Tester', 'email': 'short@example.com',
                               'password': 'eight123', 'confirm': 'eight123'})
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM users').fetchone()[0], 0)
            from werkzeug.security import generate_password_hash
            connection.execute('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)',
                               ('Legacy', 'legacy@example.com', generate_password_hash('eight123')))
        result = self.post('/login', {'email': 'legacy@example.com', 'password': 'eight123'})
        self.assertIn('Привет'.encode(), result.data)

    def test_contact_controls_rejected_without_creating_order(self):
        self.register()
        self.post('/cart/add', PRESETS[0])
        self.client.get('/checkout')
        with self.client.session_transaction() as state:
            token = state['checkout_token']
        for phone, address in (('+79991234567\x00', 'Казань, улица 1'),
                               ('+79991234567', 'Казань, улица\x001'),
                               ('abc79991234567', 'Казань, улица 1')):
            self.post('/checkout', {'phone': phone, 'address': address, 'checkout_token': token})
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM orders').fetchone()[0], 0)

    def test_operator_can_revoke_all_logins_without_deleting_accounts(self):
        self.register()
        cookie = self.client.get_cookie('session').value
        result = self.app.test_cli_runner().invoke(args=['revoke-sessions'])
        self.assertEqual(result.exit_code, 0)
        self.client.set_cookie('session', cookie)
        self.assertEqual(self.client.get('/account').status_code, 302)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM users').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM auth_sessions').fetchone()[0], 0)

    def test_old_signing_key_cookie_is_rejected_after_rotation(self):
        self.register()
        cookie = self.client.get_cookie('session').value
        rotated = create_app({'TESTING': True, 'DATABASE': self.path,
                              'SECRET_KEY': os.urandom(32)})
        client = rotated.test_client()
        client.set_cookie('session', cookie)
        self.assertEqual(client.get('/account').status_code, 302)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {'APP_ENV': 'local', 'SECRET_KEY': '',
                                                  'COOKIE_SECURE': '', 'TRUSTED_HOSTS': 'localhost'})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    def app(self, **overrides):
        config = {'TESTING': True, 'SECRET_KEY': os.urandom(32),
                  'DATABASE': str(self.root / 'test.sqlite3')}
        config.update(overrides)
        return create_app(config, instance_path=str(self.root / 'instance'))

    def production(self, **overrides):
        config = dict(APP_ENV='production', SESSION_COOKIE_SECURE=True,
                      TRUSTED_HOSTS=['shop.example'])
        config.update(overrides)
        return self.app(**config)

    def test_tests_do_not_create_real_instance_or_secret(self):
        self.app()
        self.assertFalse((self.root / 'instance').exists())

    def test_production_missing_secret_does_not_reuse_disk_secret(self):
        directory = private_directory(self.root / 'instance')
        local_secret(directory)
        with self.assertRaisesRegex(RuntimeError, 'SECRET_KEY'):
            self.production(SECRET_KEY=None)

    def test_insecure_production_configuration_rejected(self):
        for config in ({'SESSION_COOKIE_SECURE': False}, {'DEBUG': True}, {'TRUSTED_HOSTS': []}):
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                self.production(**config)
        with patch.dict(os.environ, {'COOKIE_SECURE': '0'}), self.assertRaises(RuntimeError):
            self.production()

    def test_invalid_mode_and_network_hosts_in_local_mode_rejected(self):
        for config in ({'APP_ENV': 'typo'}, {'TRUSTED_HOSTS': ['shop.example']}):
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                self.app(**config)

    def test_production_https_cookie_headers_and_host(self):
        client = self.production().test_client()
        response = client.get('/', base_url='https://shop.example')
        self.assertEqual(response.status_code, 200)
        cookie = response.headers['Set-Cookie']
        for value in ('__Host-session=', 'Secure', 'HttpOnly', 'Path=/', 'SameSite=Lax'):
            self.assertIn(value, cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertEqual(response.headers['Strict-Transport-Security'], 'max-age=31536000')
        self.assertEqual(client.get('/', base_url='https://evil.example').status_code, 400)
        self.assertEqual(client.get('/', base_url='http://evil.example').status_code, 400)
        self.assertEqual(client.get('/', base_url='http://shop.example').status_code, 400)
        response = client.get('/', base_url='http://shop.example',
                              headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(response.status_code, 400)

    def test_short_secret_rejected_outside_tests(self):
        with self.assertRaisesRegex(RuntimeError, 'SECRET_KEY'):
            self.app(TESTING=False, SECRET_KEY='too-short')

    def test_local_keys_are_persistent_private_and_unique_per_install(self):
        first = private_directory(self.root / 'first')
        second = private_directory(self.root / 'second')
        key = local_secret(first)
        self.assertEqual(len(key), 64)
        self.assertEqual(key, local_secret(first))
        self.assertNotEqual(key, local_secret(second))
        if os.name == 'posix':
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)
            self.assertEqual((first / 'secret.key').stat().st_mode & 0o777, 0o600)

    def test_concurrent_first_start_observes_one_complete_key(self):
        directory = private_directory(self.root / 'concurrent')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            keys = list(executor.map(lambda _: local_secret(directory), range(16)))
        self.assertEqual(len(set(keys)), 1)
        self.assertEqual(len(keys[0]), 64)
        self.assertEqual(list(directory.glob('.secret-*')), [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX file permissions')
    def test_database_permissions_and_symlink_rejection(self):
        database = self.root / 'private.db'
        database.write_bytes(b'')
        database.chmod(0o644)
        private_database(database)
        self.assertEqual(database.stat().st_mode & 0o777, 0o600)
        link = self.root / 'link.db'
        link.symlink_to(database)
        with self.assertRaises(RuntimeError):
            private_database(link)


class ReleaseTests(unittest.TestCase):
    def test_allowlist_excludes_runtime_data_and_build_is_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ROOT_FILES:
                (root / name).write_text('fixture', encoding='utf-8')
            for directory in ('instance', '.venv', '.idea', 'static', 'tests', 'templates', 'audit'):
                (root / directory).mkdir()
            for path in ('instance/secret.key', 'instance/shop.sqlite3', '.env', '.venv/unsafe.exe'):
                (root / path).write_text('MUST NOT SHIP', encoding='utf-8')
            (root / 'static/app.js').write_text('"use strict";', encoding='utf-8')
            first = build(root, root / 'one.zip')
            second = build(root, root / 'two.zip')
            self.assertEqual(first, second)
            with zipfile.ZipFile(root / 'one.zip') as archive:
                self.assertIn('slopai-secure/static/app.js', archive.namelist())
                for name in archive.namelist():
                    self.assertNotIn(b'MUST NOT SHIP', archive.read(name))
            if os.name == 'posix':
                (root / 'static/secret.js').symlink_to(root / 'instance/secret.key')
                with self.assertRaises(ValueError):
                    build(root, root / 'three.zip')


if __name__ == '__main__':
    unittest.main()
