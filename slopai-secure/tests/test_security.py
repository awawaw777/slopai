import sqlite3
import unittest
from app import create_app
from catalog import PRESETS
import test_app as fixtures


class SecurityTests(unittest.TestCase):
    setUp = fixtures.ShopTests.setUp
    tearDown = fixtures.ShopTests.tearDown
    post = fixtures.ShopTests.post
    register = fixtures.ShopTests.register

    def order(self, address='Казань, Примерная улица, 1'):
        self.register()
        self.post('/cart/add', PRESETS[0])
        self.client.get('/checkout')
        with self.client.session_transaction() as s:
            self.checkout_token = s['checkout_token']
        self.saved_cookie = self.client.get_cookie('session').value
        self.order_payload = {'phone':'+79991234567','address':address,'checkout_token':self.checkout_token}
        self.post('/checkout', self.order_payload)

    def count(self, table):
        # Table name comes only from fixed literals in these tests.
        assert table in ('users','orders','order_receipts','auth_sessions')
        with sqlite3.connect(self.path) as conn:
            return conn.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def test_sqli_login_and_registration_are_data(self):
        self.register()
        self.post('/logout')
        result = self.post('/login', {'email':"' OR 1=1 --",'password':'anything'})
        self.assertIn('Неверный'.encode(), result.data)
        self.assertEqual(self.client.get('/account').status_code,302)
        payload = "Robert'); DROP TABLE users;--"
        self.post('/register', {'name':payload,'email':'second@example.com','password':'safe-password-123','confirm':'safe-password-123'})
        self.assertEqual(self.count('users'),2)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT name FROM users WHERE email=?',('second@example.com',)).fetchone()[0],payload)

    def test_sqli_order_and_malicious_id(self):
        address="Street 1'); DROP TABLE users;--"
        self.order(address)
        self.assertEqual(self.count('users'),1)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT address FROM orders').fetchone()[0],address)
        self.assertEqual(self.post('/orders/1%20OR%201=1/delete',{'confirm':'delete'}).status_code,404)
        self.assertEqual(self.post('/orders/999999999999999999999/delete',{'confirm':'delete'}).status_code,404)
        self.assertEqual(self.count('orders'),1)

    def test_xss_escaped_in_profile_search_and_address(self):
        payload='<script>alert(1)</script>'
        self.post('/register',{'name':payload,'email':'xss@example.com','password':'safe-password-123','confirm':'safe-password-123'})
        page=self.client.get('/account').data
        self.assertNotIn(payload.encode(),page)
        self.assertIn(b'&lt;script&gt;',page)
        page=self.client.get('/',query_string={'q':'\"><img src=x onerror=alert(1)>'}).data
        self.assertNotIn(b'<img src=x',page)
        self.post('/cart/add',PRESETS[0])
        self.client.get('/checkout')
        with self.client.session_transaction() as s:
            token=s['checkout_token']
        page=self.post('/checkout',{'phone':'+79991234567','address':payload,'checkout_token':token}).data
        self.assertNotIn(payload.encode(),page)
        self.assertIn(b'&lt;script&gt;',page)

    def test_delete_owner_confirmation_csrf_and_get(self):
        self.order()
        self.assertEqual(self.client.get('/orders/1/delete').status_code,200)
        self.assertEqual(self.count('orders'),1)
        self.assertEqual(self.client.post('/orders/1/delete',data={'confirm':'delete'}).status_code,400)
        self.assertEqual(self.post('/orders/1/delete',{}).status_code,400)
        other=self.app.test_client()
        self.register('other@example.com',other)
        self.assertEqual(other.get('/orders/1/delete').status_code,404)
        self.assertEqual(self.post('/orders/1/delete',{'confirm':'delete'},other).status_code,404)
        self.assertEqual(self.count('orders'),1)
        result=self.post('/orders/1/delete',{'confirm':'delete'})
        self.assertIn('Заказ удалён'.encode(),result.data)
        self.assertEqual(self.count('orders'),0)
        self.assertEqual(self.post('/orders/1/delete',{'confirm':'delete'}).status_code,404)

    def test_deleted_order_cannot_be_recreated_by_cookie_replay(self):
        self.order()
        self.post('/orders/1/delete',{'confirm':'delete'})
        self.client.set_cookie('session',self.saved_cookie)
        self.post('/checkout',self.order_payload)
        self.assertEqual(self.count('orders'),0)
        self.assertEqual(self.count('order_receipts'),1)
        self.post('/cart/add',PRESETS[0])
        self.client.get('/checkout')
        with self.client.session_transaction() as s:
            token=s['checkout_token']
        self.post('/checkout',dict(self.order_payload,checkout_token=token))
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT id FROM orders').fetchone()[0],2)

    def test_logout_revokes_old_cookie(self):
        self.register()
        old=self.client.get_cookie('session').value
        self.post('/logout')
        self.assertEqual(self.count('auth_sessions'),0)
        self.client.set_cookie('session',old)
        self.assertEqual(self.client.get('/account').status_code,302)

    def test_session_expiry_and_forged_signature(self):
        self.register()
        old=self.client.get_cookie('session').value
        self.client.set_cookie('session','invalid.'+old)
        self.assertEqual(self.client.get('/account').status_code,302)
        self.client.set_cookie('session',old)
        with sqlite3.connect(self.path) as conn:
            conn.execute('UPDATE auth_sessions SET expires_at=0')
        self.assertEqual(self.client.get('/account').status_code,302)

    def test_csrf_unicode_cross_origin_host_and_size(self):
        self.client.get('/')
        self.assertEqual(self.client.post('/login',data={'csrf_token':'тест'}).status_code,400)
        self.assertEqual(self.client.post('/login',data={'password':'x'*40000}).status_code,413)
        self.assertEqual(self.client.get('/',headers={'Host':'attacker.example'}).status_code,400)
        with self.client.session_transaction() as s:
            token=s['csrf']
        self.assertEqual(self.client.post('/logout',data={'csrf_token':token},headers={'Sec-Fetch-Site':'cross-site'}).status_code,403)
        result=self.client.post('/api/quote',data={'csrf_token':'bad'})
        self.assertEqual(result.status_code,400)
        self.assertIn('error',result.json)

    def test_security_headers(self):
        self.register()
        response=self.client.get('/account')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
        self.assertTrue(self.client.get_cookie('session').http_only)
        self.assertEqual(self.client.get_cookie('session').same_site,'Lax')

    def test_external_redirect_blocked(self):
        result=self.post('/login?next=https://evil.example',{'email':'missing@example.com','password':'bad'})
        self.assertNotIn(b'Location: https://evil',result.data)
        self.register()
        self.post('/logout')
        self.client.get('/')
        with self.client.session_transaction() as s:
            token=s['csrf']
        result=self.client.post('/login?next=//evil.example',data={'csrf_token':token,'email':'player@example.com','password':'safe-password-123'})
        self.assertEqual(result.headers['Location'],'/account')

    def test_catalog_help_filters_sorting(self):
        for preset in PRESETS:
            self.assertEqual(self.client.get('/computer/'+preset['id']).status_code,200)
        self.assertEqual(self.client.get('/help').status_code,200)
        self.assertIn('Сборок не найдено'.encode(),self.client.get('/?q=nonexistent').data)
        page=self.client.get('/?purpose=4K&sort=price_asc').data
        self.assertIn(b'ULTRA',page)
        self.assertEqual(self.client.get('/computer/not-found').status_code,404)
        from flask import template_rendered
        captured=[]
        def record(sender,template,context,**extra): captured.append(context)
        with template_rendered.connected_to(record,self.app):
            self.client.get('/?sort=price_asc')
        prices=[c['total'] for c in captured[-1]['cards']]
        self.assertEqual(prices,sorted(prices))

    def test_upgrade_keeps_old_users_and_orders(self):
        self.order()
        old_cookie=self.client.get_cookie('session').value
        with sqlite3.connect(self.path) as conn:
            for table in ('auth_sessions','order_receipts','order_sequence'):
                conn.execute('DROP TABLE '+table)
        upgraded=create_app({'TESTING':True,'DATABASE':self.path,'SECRET_KEY':'test-only'})
        new_client=upgraded.test_client()
        new_client.set_cookie('session',old_cookie)
        self.assertEqual(new_client.get('/account').status_code,302)
        self.assertEqual(self.count('users'),1)
        self.assertEqual(self.count('orders'),1)
        self.assertEqual(self.count('order_receipts'),1)
        self.post('/login',{'email':'player@example.com','password':'safe-password-123'},new_client)
        self.assertIn('Заказ #00001'.encode(),new_client.get('/account').data)

if __name__ == '__main__':
    unittest.main()
