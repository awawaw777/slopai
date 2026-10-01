import os
import sqlite3
import tempfile
import unittest
from app import create_app
from catalog import PRESETS, resolve, price

class ShopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'test.db')
        self.app = create_app({'TESTING': True, 'DATABASE': self.path, 'SECRET_KEY': 'test-only'})
        self.client = self.app.test_client()
    def tearDown(self):
        self.tmp.cleanup()
    def post(self, path, data=None, client=None):
        c = client or self.client
        c.get('/')
        with c.session_transaction() as s:
            token = s['csrf']
        return c.post(path, data={**(data or {}), 'csrf_token': token}, follow_redirects=True)
    def register(self, email='player@example.com', client=None):
        return self.post('/register', {'name': 'Игрок', 'email': email, 'password':'safe-password-123','confirm':'safe-password-123'}, client)
    def test_pages_and_csrf(self):
        for path in ['/', '/configure','/login','/register','/cart']:
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertEqual(self.client.post('/register', data={}).status_code,400)
        self.assertEqual(self.client.get('/missing').status_code,404)
    def test_registration_login_password_hash(self):
        self.assertIn('Привет'.encode(), self.register().data)
        with sqlite3.connect(self.path) as conn:
            stored = conn.execute('SELECT password_hash FROM users').fetchone()[0]
        self.assertTrue(stored.startswith('scrypt:'))
        self.post('/logout')
        result = self.post('/login', {'email':'player@example.com','password':'wrong'})
        self.assertIn('Неверный'.encode(),result.data)
        result = self.post('/login', {'email':'player@example.com','password':'safe-password-123'})
        self.assertIn('Привет'.encode(),result.data)
    def test_duplicate_and_bad_registration(self):
        self.register()
        self.post('/logout')
        self.assertIn('Не удалось создать аккаунт'.encode(),self.register().data)
        result=self.post('/register', {'name':'X','email':'bad','password':'123','confirm':'123'})
        self.assertEqual(result.status_code,200)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],1)
    def test_prices_compatibility_and_tampering(self):
        for preset in PRESETS:
            result = self.post('/api/quote', preset)
            self.assertEqual(result.json['total'],price(resolve(preset)))
            self.assertEqual(result.json['errors'],[])
        result = self.post('/api/quote',dict(PRESETS[0],total=1,price=1))
        self.assertEqual(result.json['total'],price(resolve(PRESETS[0])))
        result = self.post('/api/quote',dict(PRESETS[0],cpu='r7700',gpu='rtx4080s'))
        self.assertGreaterEqual(len(result.json['errors']),3)
        self.post('/cart/add',dict(PRESETS[0],cpu='r7700'))
        with self.client.session_transaction() as s:
            self.assertFalse(s.get('cart'))
        self.assertEqual(self.post('/api/quote',dict(PRESETS[0],cpu='fake')).status_code,400)
    def test_order_and_owner_isolation(self):
        self.post('/cart/add',PRESETS[1])
        self.assertEqual(self.client.get('/checkout').status_code,302)
        self.register()
        self.client.get('/checkout')
        with self.client.session_transaction() as s:
            token=s['checkout_token']
        payload={'phone':'+7 999 123-45-67','address':'Казань, улица Примерная, 1','checkout_token':token}
        result=self.post('/checkout',payload)
        self.assertEqual(result.status_code,200)
        self.assertIn('Заказ #00001'.encode(),result.data)
        self.post('/checkout',payload)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT total FROM orders').fetchone()[0],price(resolve(PRESETS[1])))
        other=self.app.test_client()
        self.register('other@example.com',other)
        page=other.get('/account')
        self.assertNotIn('Заказ #00001'.encode(),page.data)
        self.assertNotIn('Примерная'.encode(),page.data)
    def test_rate_limit(self):
        for _ in range(15):
            self.post('/login',{'email':'a@b.c','password':'bad'})
        self.assertEqual(self.post('/login',{'email':'a@b.c','password':'bad'}).status_code,429)
    def test_cart_limit_and_remove(self):
        for _ in range(6):
            self.post('/cart/add',PRESETS[0])
        with self.client.session_transaction() as s:
            self.assertEqual(len(s['cart']),5)
        self.post('/cart/remove/0')
        with self.client.session_transaction() as s:
            self.assertEqual(len(s['cart']),4)

if __name__ == '__main__': unittest.main()
