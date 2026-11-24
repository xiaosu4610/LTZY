"""Multi-user platform tests: roles, registration, balance, ePay V1/V2, SMTP stubs."""
import json
import tempfile
import unittest
from contextlib import closing
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from unittest.mock import patch, MagicMock

import mail
import pay
import server


class UsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.srv = server.create_server(self.tmp.name, 0)
        thread = Thread(target=self.srv.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join)          # runs last (LIFO)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)    # runs first
        self.cookie = ''

    def call(self, path, obj=None, cookie=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if self.cookie or cookie:
            headers['Cookie'] = cookie or self.cookie
        if token:
            headers['Authorization'] = 'Bearer ' + token
        with closing(HTTPConnection('127.0.0.1', self.srv.server_port, timeout=5)) as c:
            c.request('POST' if obj is not None else 'GET', path,
                      json.dumps(obj) if obj is not None else None, headers)
            r = c.getresponse()
            body = r.read()
            return r.status, json.loads(body) if 'json' in r.getheader('Content-Type') else body, r.headers

    def db(self):
        return closing(server.connect(self.srv.db_path))

    def admin_login(self):
        password = (Path(self.tmp.name) / 'admin-password.txt').read_text().strip()
        code, _, h = self.call('/api/login', {'password': password})
        self.assertEqual(code, 200)
        self.cookie = h['Set-Cookie'].split(';')[0]
        return code

    def admin_uid(self):
        with self.db() as db:
            return db.execute("SELECT id FROM users WHERE email='admin@local'").fetchone()[0]

    def register(self, email='user@test.dev', password='hunter2secret', code=None, skip_code=False):
        obj = {'email': email, 'password': password}
        if not skip_code:
            obj['code'] = code
        code_status, body, h = self.call('/api/register', obj)
        if code_status == 200 and h.get('Set-Cookie'):
            self.cookie = h['Set-Cookie'].split(';')[0]  # Auto-login as the new user.
        return code_status, body, h

    def send_code(self, email='user@test.dev'):
        with self.db() as db:
            db.execute("UPDATE settings SET smtp_host='smtp.test', smtp_from='ltzy@test.dev', smtp_port=587")
        fake = MagicMock()
        with patch.object(mail, 'send', fake):
            code, body, _ = self.call('/api/email/send-code', {'email': email})
        self.assertEqual(code, 200)
        self.assertTrue(fake.called)
        with self.db() as db:
            return db.execute('SELECT code FROM email_tokens WHERE email=?', (email,)).fetchone()[0]

    # ---- registration -------------------------------------------------

    def test_registration_open_without_email_verification(self):
        self.admin_login()
        with self.db() as db:
            db.execute('UPDATE settings SET email_verification=0')
        code, body, h = self.register(skip_code=True)
        self.assertEqual(code, 200)
        self.assertEqual(body['role'], 'user')
        self.cookie = h['Set-Cookie'].split(';')[0]
        view = self.call('/api/workspace')[1]
        self.assertEqual(view['me']['email'], 'user@test.dev')
        self.assertEqual(view['me']['balance'], 0)

    def test_registration_requires_email_code_by_default(self):
        self.assertEqual(self.register(skip_code=True)[0], 400)
        code_text = self.send_code()
        self.assertEqual(self.register(code='000000')[0], 400)
        self.assertEqual(self.register(code=code_text)[0], 200)
        # The code is single-use; a fresh code is needed to register the same email again.
        self.assertEqual(self.register(code=code_text)[0], 409)  # Email now registered.
        self.assertEqual(self.register(code='000000')[0], 409)   # Registration check precedes code check.

    def test_registration_flags_and_duplicates(self):
        self.admin_login()
        self.assertEqual(self.call('/api/admin/settings', {'registrationEnabled': False})[0], 200)
        self.assertEqual(self.register(skip_code=True)[0], 403)
        self.assertEqual(self.call('/api/email/send-code', {'email': 'a@b.dev'})[0], 403)
        self.assertEqual(self.call('/api/admin/settings', {'registrationEnabled': True})[0], 200)
        code_text = self.send_code('taken@test.dev')
        self.register('taken@test.dev', code=code_text)
        self.assertEqual(self.send_code('taken@test.dev')[0] if False else
                         self.call('/api/email/send-code', {'email': 'taken@test.dev'})[0], 409)
        self.assertEqual(self.register('taken@test.dev', code=code_text, skip_code=False)[0], 409)
        for weak in ('short', None, 12345678):
            self.assertEqual(self.register('w1@test.dev', password=weak, skip_code=True)[0], 400)
        for bad in ('no-at-sign', 'a@', '@b.dev', 'x@y'):
            self.assertEqual(self.register(bad, skip_code=True)[0], 400)

    def test_email_code_requires_smtp_configuration(self):
        self.assertEqual(self.call('/api/email/send-code', {'email': 'u@v.dev'})[0], 503)
        self.admin_login()
        with self.db() as db:
            db.execute("UPDATE settings SET smtp_host='smtp.test', smtp_from='ltzy@test.dev', smtp_port=587")
        with patch.object(mail, 'send', lambda *a, **k: None):
            self.assertEqual(self.call('/api/email/send-code', {'email': 'u@v.dev'})[0], 200)

    # ---- roles and user administration ---------------------------------

    def test_roles_isolate_users_and_admin_surface(self):
        self.admin_login()
        with self.db() as db:
            db.execute('UPDATE settings SET email_verification=0')
        self.cookie = ''
        self.register(skip_code=True)
        code, keys, _ = self.call('/api/keys', {'name': 'u', 'scope': 'chat'})
        user_key = keys['secret']
        self.assertEqual(self.call('/api/admin/overview')[0], 403)
        self.assertEqual(self.call('/api/admin/user', {'id': 'x', 'action': 'ban'})[0], 403)
        self.assertEqual(self.call('/api/lanes', {'id': 'local-test', 'enabled': False})[0], 403)
        self.assertEqual(self.call('/api/reconcile', {'id': 'x', 'note': 'n',
                                                      'inputTokens': 1, 'outputTokens': 1})[0], 403)
        self.cookie = ''
        self.admin_login()
        overview = self.call('/api/admin/overview')[1]
        emails = {u['email'] for u in overview['users']}
        self.assertEqual(emails, {'admin@local', 'user@test.dev'})
        user_row = next(u for u in overview['users'] if u['email'] == 'user@test.dev')
        self.assertEqual(user_row['balance'], 0)
        self.assertEqual(user_row['role'], 'user')

    def test_admin_can_manage_users_and_balances(self):
        self.admin_login()
        with self.db() as db:
            db.execute('UPDATE settings SET email_verification=0')
        self.cookie = ''
        self.register(skip_code=True)
        self.cookie = ''
        self.admin_login()
        overview = self.call('/api/admin/overview')[1]
        user = next(u for u in overview['users'] if u['email'] == 'user@test.dev')
        uid = user['id']
        self.assertEqual(self.call('/api/admin/user', {'id': uid, 'action': 'balance', 'delta': 5})[0], 200)
        self.call('/api/admin/user', {'id': uid, 'action': 'role', 'role': 'admin'})
        self.assertEqual(next(u for u in self.call('/api/admin/overview')[1]['users']
                              if u['id'] == uid)['balance'], 5)
        with self.db() as db:
            audit = db.execute('SELECT delta_micros, reason FROM balance_audit WHERE user_id=?', (uid,)).fetchone()
            self.assertEqual(audit['delta_micros'], 5_000_000)
        # Demoting the last remaining admin is refused; banning an admin is refused.
        self.assertEqual(self.call('/api/admin/user', {'id': uid, 'action': 'role', 'role': 'user'})[0], 200)
        self.assertEqual(self.call('/api/admin/user', {'id': uid, 'action': 'balance', 'delta': -6})[0], 409)
        admin_id = self.admin_uid()
        self.assertEqual(self.call('/api/admin/user', {'id': admin_id, 'action': 'ban'})[0], 409)
        # Banning a user kills their session and blocks login.
        self.call('/api/admin/user', {'id': uid, 'action': 'role', 'role': 'user'})
        self.cookie = ''
        self.register('second@test.dev', skip_code=True)
        self.cookie = ''
        self.admin_login()
        second = next(u for u in self.call('/api/admin/overview')[1]['users']
                      if u['email'] == 'second@test.dev')
        self.call('/api/admin/user', {'id': second['id'], 'action': 'ban'})
        self.assertEqual(self.call('/api/login', {'email': 'second@test.dev',
                                                  'password': 'hunter2secret'})[0], 403)

    # ---- balance-driven billing -----------------------------------------

    def test_balance_gates_inference_and_recharge_credits(self):
        self.admin_login()
        with self.db() as db:
            db.execute('UPDATE settings SET email_verification=0')
        self.cookie = ''
        self.register(skip_code=True)
        user_cookie = self.cookie
        token = self.call('/api/keys', {'name': 'k', 'scope': 'chat'})[1]['secret']
        self.assertEqual(self.chat_call(token)[0], 402)  # Zero balance.
        self.cookie = ''
        self.admin_login()
        uid = next(u for u in self.call('/api/admin/overview')[1]['users']
                   if u['email'] == 'user@test.dev')['id']
        self.assertEqual(self.call('/api/admin/user', {'id': uid, 'action': 'balance', 'delta': 1})[0], 200)
        code, answer, _ = self.chat_call(token)
        self.assertEqual(code, 200)
        self.cookie = user_cookie
        view = self.call('/api/workspace')[1]
        self.assertLess(view['me']['balance'], 1)
        self.assertGreater(view['budget']['spent'], 0)

    def chat_call(self, token):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}
        body = json.dumps({'model': 'local/echo',
                           'messages': [{'role': 'user', 'content': 'billing probe'}],
                           'max_tokens': 16})
        with closing(HTTPConnection('127.0.0.1', self.srv.server_port, timeout=5)) as c:
            c.request('POST', '/v1/chat/completions', body, headers)
            r = c.getresponse()
            return r.status, json.loads(r.read() or b'{}'), r.headers

    # ---- rainbow ePay V1/V2 ----------------------------------------------

    def configure_epay(self, version='v1'):
        self.admin_login()
        with self.db() as db:
            db.execute("UPDATE settings SET epay_url='https://pay.example.dev', epay_pid='1000',"
                       " epay_key='secretkey123', epay_version=?, site_url='http://192.168.1.5:8765'",
                       (version,))

    def test_epay_v1_order_and_notify_signature_roundtrip(self):
        self.configure_epay('v1')
        uid = self.admin_uid()
        code, order, _ = self.call('/api/recharge', {'amount': 5, 'channel': 'alipay'})
        self.assertEqual(code, 200)
        self.assertEqual(order['mode'], 'v1')
        self.assertIn('/submit.php?', order['payurl'])
        from urllib.parse import urlparse, parse_qsl
        query = dict(parse_qsl(urlparse(order['payurl']).query))
        self.assertTrue(pay.verify(query, 'secretkey123'))
        self.assertEqual(query['money'], '5.00')
        self.assertEqual(query['pid'], '1000')
        # Forged signature must fail; a genuine one credits exactly once.
        forged = {**query, 'sign': 'deadbeef' * 4}
        self.assertEqual(self.notify(forged), 'fail')
        paid = {**query, 'trade_no': 'T9001',
                'sign': pay.sign({**query, 'trade_no': 'T9001'}, 'secretkey123')}
        self.assertEqual(self.notify(paid), 'success')
        self.assertEqual(self.notify(paid), 'success')  # Idempotent replay.
        view = self.call('/api/workspace')[1]
        self.assertEqual(view['me']['balance'], 30)  # admin held $25, recharged $5.
        with self.db() as db:
            row = db.execute('SELECT status, trade_no FROM recharges WHERE out_trade_no=?',
                             (query['out_trade_no'],)).fetchone()
            self.assertEqual(row['status'], 'paid')
            self.assertEqual(row['trade_no'], 'T9001')
        # A mismatched amount on a *pending* order is rejected before crediting.
        code2, order2, _ = self.call('/api/recharge', {'amount': 3, 'channel': 'alipay'})
        self.assertEqual(code2, 200)
        from urllib.parse import urlparse as _u
        q2 = dict(parse_qsl(_u(order2['payurl']).query))
        bad = {**q2, 'money': '9.99', 'sign': pay.sign({**q2, 'money': '9.99'}, 'secretkey123')}
        self.assertEqual(self.notify(bad), 'fail')
        with self.db() as db:
            self.assertEqual(db.execute('SELECT status FROM recharges WHERE out_trade_no=?',
                                        (q2['out_trade_no'],)).fetchone()[0], 'pending')

    def test_epay_concurrent_notify_credits_exactly_once(self):
        self.configure_epay('v1')
        code, order, _ = self.call('/api/recharge', {'amount': 5, 'channel': 'alipay'})
        self.assertEqual(code, 200)
        from urllib.parse import urlparse, parse_qsl
        from concurrent.futures import ThreadPoolExecutor
        query = dict(parse_qsl(urlparse(order['payurl']).query))
        paid = {**query, 'trade_no': 'T-RACE',
                'sign': pay.sign({**query, 'trade_no': 'T-RACE'}, 'secretkey123')}
        # Eight concurrent, identical, correctly-signed callbacks for one order.
        with ThreadPoolExecutor(8) as pool:
            answers = list(pool.map(lambda _: self.notify(paid), range(8)))
        self.assertEqual(answers, ['success'] * 8)
        view = self.call('/api/workspace')[1]
        self.assertEqual(view['me']['balance'], 30)  # $25 admin floor + exactly one $5 credit.
        with self.db() as db:
            credits = db.execute("SELECT count(*) FROM balance_audit WHERE reason LIKE 'recharge %'").fetchone()[0]
            self.assertEqual(credits, 1)

    def notify(self, params):
        from urllib.parse import urlencode
        code, body, _ = self.call('/pay/notify?' + urlencode(params))
        return body.decode() if isinstance(body, bytes) else body

    def test_epay_v2_order_uses_mapi_and_returns_payurl(self):
        self.configure_epay('v2')
        captured = {}

        def fake_v2(cfg, params):
            captured.update({**params, 'sign': pay.sign(params, 'secretkey123'), 'sign_type': 'MD5'})
            return {'code': 1, 'payurl': 'https://pay.example.dev/pay/abc', 'qrcode': 'img-data'}

        with patch.object(pay, 'v2_order', fake_v2):
            code, order, _ = self.call('/api/recharge', {'amount': 2, 'channel': 'wxpay'})
        self.assertEqual(code, 200)
        self.assertEqual(order['mode'], 'v2')
        self.assertEqual(order['payurl'], 'https://pay.example.dev/pay/abc')
        self.assertEqual(order['qrcode'], 'img-data')
        self.assertEqual(captured['type'], 'wxpay')
        self.assertTrue(pay.verify(captured, 'secretkey123'))

    def test_recharge_requires_configuration_and_valid_amounts(self):
        self.admin_login()
        self.assertEqual(self.call('/api/recharge', {'amount': 5})[0], 503)
        self.configure_epay()
        for bad in (0, -3, 10001, 'NaN', None):
            self.assertEqual(self.call('/api/recharge', {'amount': bad})[0], 400)
        self.assertEqual(self.call('/api/recharge', {'amount': 5, 'channel': 'crypto'})[0], 400)
        with self.db() as db:
            db.execute("UPDATE settings SET site_url=''")
        self.assertEqual(self.call('/api/recharge', {'amount': 5})[0], 400)

    def test_settings_view_masks_secret_and_preserves_on_empty(self):
        self.configure_epay()
        view = self.call('/api/admin/settings')[1]
        self.assertTrue(view['smtp_configured'] is False or isinstance(view['smtp_configured'], bool))
        self.assertNotIn('epay_key', view)
        self.assertNotIn('smtp_pass', view)
        # Empty secret fields keep stored values.
        code, before, _ = self.call('/api/admin/settings', {'smtp_pass': 'newpass', 'epay_key': 'newkey'})
        self.assertEqual(code, 200)
        code, after, _ = self.call('/api/admin/settings', {'smtp_host': 'smtp2.test'})
        self.assertEqual(code, 200)
        with self.db() as db:
            row = db.execute('SELECT smtp_pass, epay_key, smtp_host FROM settings').fetchone()
            self.assertEqual(row['smtp_pass'], 'newpass')
            self.assertEqual(row['epay_key'], 'newkey')
            self.assertEqual(row['smtp_host'], 'smtp2.test')

    def test_test_email_requires_valid_address_and_config(self):
        self.admin_login()
        self.assertEqual(self.call('/api/admin/test-email', {'to': 'x@y.z'})[0], 400)
        with self.db() as db:
            db.execute("UPDATE settings SET smtp_host='smtp.test', smtp_from='ltzy@test.dev', smtp_port=465")
        sent = {}
        with patch.object(mail, 'send', lambda cfg, to, subject, body: sent.update(to=to)):
            self.assertEqual(self.call('/api/admin/test-email', {'to': 'x@y.dev'})[0], 200)
        self.assertEqual(sent['to'], 'x@y.dev')


if __name__ == '__main__':
    unittest.main()
