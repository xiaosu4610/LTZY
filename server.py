"""Local LTZY control plane. Use a private data directory on a loopback interface."""
import argparse
import csv
import hashlib
import io
import json
import mail
import mimetypes
import os
import pay
import re
import secrets
import sqlite3
import time
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import unquote, urlsplit, parse_qsl

WEB = Path(__file__).resolve().parent / 'web'
TTL = 12 * 3600
COOKIE = 'ltzy_session'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
 status TEXT NOT NULL DEFAULT 'active', balance_micros INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys(id TEXT PRIMARY KEY, name TEXT NOT NULL, prefix TEXT NOT NULL,
 digest TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 scope TEXT NOT NULL DEFAULT 'chat', user_id TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), budget_micros INTEGER NOT NULL);
INSERT OR IGNORE INTO settings(id,budget_micros) VALUES(1,25000000);
CREATE TABLE IF NOT EXISTS lane_settings(id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reconciliation_audit(receipt_id TEXT PRIMARY KEY, note TEXT NOT NULL, at TEXT NOT NULL,
 input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY, expires INTEGER NOT NULL, user_id TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, createdAt TEXT NOT NULL, model TEXT NOT NULL, lane TEXT,
 keyId TEXT NOT NULL, status TEXT NOT NULL, settlement TEXT NOT NULL,
 inputTokens INTEGER, outputTokens INTEGER, cost INTEGER, reserved INTEGER NOT NULL,
 latencyMs INTEGER, trace TEXT NOT NULL, price TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS recharges(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, out_trade_no TEXT UNIQUE NOT NULL,
 amount_micros INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', channel TEXT,
 trade_no TEXT, created_at TEXT NOT NULL, paid_at TEXT);
CREATE TABLE IF NOT EXISTS email_tokens(code TEXT PRIMARY KEY, email TEXT NOT NULL,
 purpose TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS balance_audit(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, delta_micros INTEGER NOT NULL,
 reason TEXT NOT NULL, by_user TEXT, at TEXT NOT NULL);
'''

MIGRATIONS = (
    ("ALTER TABLE api_keys ADD COLUMN user_id TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE receipts ADD COLUMN user_id TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE sessions ADD COLUMN user_id TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN registration_enabled INTEGER NOT NULL DEFAULT 1",),
    ("ALTER TABLE settings ADD COLUMN email_verification INTEGER NOT NULL DEFAULT 1",),
    ("ALTER TABLE settings ADD COLUMN smtp_host TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN smtp_port INTEGER NOT NULL DEFAULT 0",),
    ("ALTER TABLE settings ADD COLUMN smtp_user TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN smtp_pass TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN smtp_from TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN epay_url TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN epay_pid TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN epay_key TEXT NOT NULL DEFAULT ''",),
    ("ALTER TABLE settings ADD COLUMN epay_version TEXT NOT NULL DEFAULT 'v1'",),
    ("ALTER TABLE settings ADD COLUMN site_url TEXT NOT NULL DEFAULT ''",),
)


def migrate(db_path, data_dir):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        for (sql,) in MIGRATIONS:
            try:
                db.execute(sql)
            except sqlite3.OperationalError:
                pass  # Column already exists.
        # Existing rows keep working: receipts/keys created before multi-user belong to admin.
        admin = ensure_admin(db, data_dir)
        db.execute("UPDATE api_keys SET user_id=? WHERE user_id=''", (admin['id'],))
        db.execute("UPDATE receipts SET user_id=? WHERE user_id=''", (admin['id'],))
        db.execute("UPDATE sessions SET user_id=? WHERE user_id=''", (admin['id'],))
        # Keep the historic global budget in sync as the admin balance floor.
        budget, = db.execute('SELECT budget_micros FROM settings WHERE id=1').fetchone()
        db.execute('UPDATE users SET balance_micros=max(balance_micros,?) WHERE id=? AND role=?',
                   (budget, admin['id'], 'admin'))
        db.commit()
    finally:
        db.close()


def ensure_admin(db, data_dir):
    """Bootstrap the holder account; its initial password is the generated admin password file."""
    row = db.execute("SELECT * FROM users WHERE role='admin' ORDER BY created_at LIMIT 1").fetchone()
    if row:
        return row
    password_file = Path(data_dir) / 'admin-password.txt'
    if not password_file.is_file():
        bootstrap_password(password_file)
    password = password_file.read_text(encoding='utf-8').strip()
    uid = 'usr_' + secrets.token_hex(10)
    db.execute("INSERT OR IGNORE INTO users VALUES(?,?,?,?,?,?,?)",
               (uid, 'admin@local', hash_password(password), 'admin', 'active',
                25_000_000, datetime.now(timezone.utc).isoformat()))
    db.commit()
    return db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + '$' + hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def verify_password(stored, password):
    try:
        salt, _ = stored.split('$', 1)
    except ValueError:
        return False
    return secrets.compare_digest(hash_password(password, salt), stored)


class Problem(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def connect(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


def key_view(row):
    return {**{k: row[k] for k in ('id','name','prefix','created_at','scope')}, 'revoked': bool(row['revoked'])}


def text(obj, key, size):
    val = obj.get(key)
    if not isinstance(val, str) or not val.strip() or len(val) > size or not val.isprintable():
        raise Problem(400, 'Invalid ' + key)
    return val.strip()


def micros(value):
    try:
        val = Decimal(str(value))
        if not val.is_finite() or not 0 <= val <= 1000000000 or val.as_tuple().exponent < -6:
            raise ValueError()
        return int(val * 1000000)
    except (ValueError, InvalidOperation):
        raise Problem(400, 'Budget must be a USD amount with at most six decimal places')


def bootstrap_password(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(secrets.token_urlsafe(32) + '\n')
    password = path.read_text(encoding='utf-8').strip()
    if not password:
        raise ValueError('Empty admin password file')
    return digest(password)


EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]{2,}$')


def valid_email(value):
    return isinstance(value, str) and len(value) <= 200 and bool(EMAIL_RE.fullmatch(value.strip().lower()))


def settings_row(db):
    return db.execute('SELECT * FROM settings WHERE id=1').fetchone()


def require_admin(me):
    if me['role'] != 'admin':
        raise Problem(403, '需要管理员权限')


def user_view(row):
    return {'id': row['id'], 'email': row['email'], 'role': row['role'],
            'status': row['status'], 'balance': row['balance_micros'] / 1e6,
            'created_at': row['created_at']}


def issue_session(db, user_id):
    token = secrets.token_urlsafe(32)
    db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
    db.execute('INSERT INTO sessions VALUES(?,?,?)', (digest(token), int(time.time()) + TTL, user_id))
    return token


def consume_email_code(db, email, code):
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        raise Problem(400, '请输入 6 位邮箱验证码')
    row = db.execute('SELECT * FROM email_tokens WHERE code=? AND email=? AND purpose=?',
                     (code, email.strip().lower(), 'register')).fetchone()
    if not row or row['used'] or row['expires'] < time.time():
        raise Problem(400, '验证码无效或已过期')
    db.execute('UPDATE email_tokens SET used=1 WHERE code=?', (code,))


def create_user(db, obj, cfg):
    email = obj.get('email')
    if not valid_email(email):
        raise Problem(400, '请输入有效的邮箱地址')
    email = email.strip().lower()
    password = obj.get('password')
    if not isinstance(password, str) or len(password) < 8 or len(password) > 512:
        raise Problem(400, '密码至少需要 8 个字符')
    if not cfg['registration_enabled']:
        raise Problem(403, '注册暂未开放')
    if db.execute('SELECT 1 FROM users WHERE lower(email)=?', (email,)).fetchone():
        raise Problem(409, '该邮箱已注册')
    if cfg['email_verification']:
        consume_email_code(db, email, obj.get('code'))
    uid = 'usr_' + secrets.token_hex(10)
    db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
               (uid, email, hash_password(password), 'user', 'active', 0,
                datetime.now(timezone.utc).isoformat()))
    return db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()


def issue_email_code(db, email, now_ts):
    if not valid_email(email):
        raise Problem(400, '请输入有效的邮箱地址')
    email = email.strip().lower()
    cfg = settings_row(db)
    if not cfg['registration_enabled']:
        raise Problem(403, '注册暂未开放')
    if db.execute('SELECT 1 FROM users WHERE lower(email)=?', (email,)).fetchone():
        raise Problem(409, '该邮箱已注册')
    if not mail.configured(cfg):
        raise Problem(503, '邮件服务尚未配置，请联系管理员')
    code = f'{secrets.randbelow(1000000):06d}'
    db.execute('INSERT INTO email_tokens VALUES(?,?,?,?,0)',
               (code, email, 'register', int(now_ts) + 600))
    try:
        mail.send(cfg, email, 'LTZY 注册验证码',
                  f'你的 LTZY 注册验证码是 {code}，10 分钟内有效。若非本人操作请忽略本邮件。')
    except OSError as exc:
        raise Problem(502, '邮件发送失败，请检查 SMTP 配置或稍后重试') from None
    return code


def handle_pay_notify(db, params):
    """Rainbow-epay async notification: verify MD5, credit exactly once, answer 'success'."""
    cfg = settings_row(db)
    if not pay.verify(params, cfg['epay_key'] or ''):
        return 'fail'
    order = db.execute('SELECT * FROM recharges WHERE out_trade_no=?',
                       (params.get('out_trade_no', ''),)).fetchone()
    if not order or order['status'] == 'paid':
        return 'success'
    if params.get('trade_status', 'TRADE_SUCCESS') != 'TRADE_SUCCESS':
        return 'success'
    if int(Decimal(params.get('money', '0')) * 1000000) != order['amount_micros']:
        return 'fail'
    # The conditional UPDATE is the claim on this order: only the single request
    # that flips pending->paid may credit. Concurrent duplicate callbacks lose the
    # race here and return without touching the balance.
    claimed = db.execute("UPDATE recharges SET status='paid', trade_no=?, paid_at=? WHERE id=? AND status='pending'",
                         (params.get('trade_no', ''), datetime.now(timezone.utc).isoformat(), order['id']))
    if claimed.rowcount != 1:
        return 'success'  # A concurrent notify already settled this order.
    db.execute('UPDATE users SET balance_micros=balance_micros+? WHERE id=?',
               (order['amount_micros'], order['user_id']))
    db.execute('INSERT INTO balance_audit VALUES(?,?,?,?,?,?)',
               ('bal_' + secrets.token_hex(10), order['user_id'], order['amount_micros'],
                'recharge ' + order['out_trade_no'], None, datetime.now(timezone.utc).isoformat()))
    return 'success'


def admin_update_user(db, obj, me):
    uid = text(obj, 'id', 120)
    action = text(obj, 'action', 20)
    target = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not target:
        raise Problem(404, '用户不存在')
    if action == 'balance':
        try:
            delta = Decimal(str(obj.get('delta')))
            if not delta.is_finite() or abs(delta) > 1_000_000 or delta.as_tuple().exponent < -6:
                raise ValueError()
        except (ValueError, InvalidOperation, TypeError):
            raise Problem(400, '调整金额需为最多 6 位小数的美元金额')
        amount = int(delta * 1_000_000)
        if target['balance_micros'] + amount < 0:
            raise Problem(409, '调整后余额不能低于零')
        db.execute('UPDATE users SET balance_micros=balance_micros+? WHERE id=?', (amount, uid))
        db.execute('INSERT INTO balance_audit VALUES(?,?,?,?,?,?)',
                   ('bal_' + secrets.token_hex(10), uid, amount,
                    text(obj, 'reason', 200) if isinstance(obj.get('reason'), str) and obj['reason'].strip() else 'admin adjustment',
                    me['id'], datetime.now(timezone.utc).isoformat()))
    elif action == 'ban':
        if target['role'] == 'admin':
            raise Problem(409, '不能封禁管理员账号')
        db.execute("UPDATE users SET status='banned' WHERE id=?", (uid,))
        db.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
    elif action == 'unban':
        db.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
    elif action == 'role':
        new_role = obj.get('role')
        if new_role not in ('user', 'admin'):
            raise Problem(400, 'Role must be user or admin')
        if target['role'] == 'admin' and new_role == 'user':
            admins, = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()
            if admins <= 1:
                raise Problem(409, '至少保留一位管理员')
        db.execute('UPDATE users SET role=? WHERE id=?', (new_role, uid))
    else:
        raise Problem(400, '未知操作')
    return user_view(db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone())


def admin_settings_view(cfg):
    keys = ('registration_enabled', 'email_verification', 'smtp_host', 'smtp_port', 'smtp_user',
            'smtp_from', 'epay_url', 'epay_pid', 'epay_version', 'site_url')
    view = {k: cfg[k] for k in keys}
    view['emailVerification'] = bool(cfg['email_verification'])
    view['registrationEnabled'] = bool(cfg['registration_enabled'])
    view['smtp_configured'] = mail.configured(cfg)
    view['epay_configured'] = bool(cfg['epay_key'])
    return view


def apply_admin_settings(db, obj):
    cfg = settings_row(db)
    sets = {}
    for key in ('smtp_host', 'smtp_user', 'smtp_from', 'epay_url', 'epay_pid', 'site_url'):
        if key in obj:
            val = obj[key]
            if val is None:
                continue
            if not isinstance(val, str) or len(val) > 300:
                raise Problem(400, 'Invalid ' + key)
            if key == 'site_url' and val and not val.startswith(('http://', 'https://')):
                raise Problem(400, 'site_url must start with http(s)://')
            if key == 'smtp_host' and val and not pay.safe_host(val):
                raise Problem(400, 'Invalid smtp_host')
            sets[key] = val
    if 'smtp_port' in obj:
        port = obj['smtp_port']
        if port is not None:
            if type(port) is not int or not 0 <= port <= 65535:
                raise Problem(400, 'Invalid smtp_port')
            sets['smtp_port'] = port
    if 'smtp_pass' in obj and isinstance(obj['smtp_pass'], str) and obj['smtp_pass']:
        sets['smtp_pass'] = obj['smtp_pass']
    if 'epay_key' in obj and isinstance(obj['epay_key'], str) and obj['epay_key']:
        sets['epay_key'] = obj['epay_key']
    if 'epay_version' in obj:
        if obj['epay_version'] not in ('v1', 'v2'):
            raise Problem(400, 'epay_version must be v1 or v2')
        sets['epay_version'] = obj['epay_version']
    for flag_key, column in (('registrationEnabled', 'registration_enabled'),
                             ('emailVerification', 'email_verification')):
        if flag_key in obj:
            flag = obj[flag_key]
            if not isinstance(flag, bool):
                raise Problem(400, 'Expected boolean ' + flag_key)
            sets[column] = int(flag)
    if not sets:
        return cfg
    assignments = ','.join(f'{k}=?' for k in sets)
    db.execute(f'UPDATE settings SET {assignments} WHERE id=1', tuple(sets.values()))
    return settings_row(db)


class Handler(BaseHTTPRequestHandler):
    timeout = 20
    server_version = 'LTZY'
    sys_version = ''

    def log_message(self, *args):
        pass  # Paths, request headers, payloads and credentials must never be logged.

    def reply(self, code, data, typ='application/json; charset=utf-8', headers=None):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=True, allow_nan=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', typ)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        for k,v in (headers or {}).items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        if self.headers.get_content_type() != 'application/json':
            raise Problem(415, 'Send application/json')
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
            raise Problem(400, 'Invalid content length')
        if len(lengths[0]) > 8 or int(lengths[0]) > 16384:
            raise Problem(413, 'Request is too large')
        try:
            data = json.loads(self.rfile.read(int(lengths[0])).decode('utf-8'), parse_float=Decimal)
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError, RecursionError):
            raise Problem(400, 'Expected a JSON object')
        return data

    def session(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie',''))
            return digest(jar[COOKIE].value)
        except (KeyError,CookieError):
            return ''

    def run(self):
        try:
            host = self.headers.get('Host','').lower()
            if self.headers.get_all('Host') != [self.headers.get('Host')] or host not in self.server.hosts:
                raise Problem(403, 'Unrecognized local host')
            if self.headers.get('Sec-Fetch-Site') == 'cross-site' or any(o != 'http://' + host for o in self.headers.get_all('Origin', [])):
                raise Problem(403, 'Cross-origin requests are not allowed')
            path = urlsplit(self.path).path
            if path.startswith('/v1/'):
                self.server.gateway.dispatch(self, self.server.db_path)
                return
            if path == '/pay/notify':
                self.pay_notify()
                return
            if path.startswith('/api/'):
                with closing(connect(self.server.db_path)) as db:
                    result, headers = self.api(db,path)
                    db.commit()  # Commit before disclosing any key or session.
                if isinstance(result,bytes):
                    self.reply(200,result,'text/csv; charset=utf-8',headers)
                else:
                    self.reply(200,result,headers=headers)
            elif self.command == 'GET':
                rel = unquote(path).lstrip('/') or 'index.html'
                if '\\' in rel or ':' in rel or '\x00' in rel or any(p.startswith('.') for p in rel.split('/')):
                    raise Problem(404,'Not found')
                target = (WEB / rel).resolve()
                if WEB not in target.parents or not target.is_file():
                    raise Problem(404,'Not found')
                typ = {'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml'}.get(target.suffix) or mimetypes.guess_type(target.name)[0]
                self.reply(200,target.read_bytes(),typ or 'application/octet-stream')
            else:
                raise Problem(404,'Not found')
        except Problem as e:
            self.reply(e.code, {'error':{'message':str(e)}})
        except (TimeoutError,ConnectionError):
            self.close_connection = True
        except Exception:
            self.reply(500, {'error':{'message':'Internal service error'}})

    do_GET = do_POST = run

    def pay_notify(self):
        """Gateway-to-server callback: no cookies, plain-text answer."""
        try:
            params = dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))
            with closing(connect(self.server.db_path)) as db:
                # Serialize settlement with any other writer before reading the
                # order status; otherwise two concurrent callbacks can both see
                # 'pending' and credit the same recharge more than once.
                db.execute('BEGIN IMMEDIATE')
                answer = handle_pay_notify(db, params)
                db.commit()
            self.reply(200, answer.encode('utf-8'), 'text/plain; charset=utf-8')
        except Exception:
            self.reply(200, b'fail', 'text/plain; charset=utf-8')

    def viewer(self,db):
        sid = self.session()
        row = db.execute('''SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
                            WHERE s.digest=? AND s.expires>?''',(sid,time.time())).fetchone()
        if not row:
            raise Problem(401,'请先登录')
        if row['status'] != 'active':
            raise Problem(403,'账号已被封禁')
        return row

    def api(self,db,path):
        gw = self.server.gateway
        post = self.command == 'POST'
        obj = self.body() if post else {}
        sid = self.session()
        headers = {}
        db.execute('BEGIN IMMEDIATE' if post else 'BEGIN')
        if path == '/api/public' and not post:
            return gw.snapshot(db,public=True), headers
        if path == '/api/config' and not post:
            cfg = settings_row(db)
            return {'registration': bool(cfg['registration_enabled']),
                    'emailVerification': bool(cfg['email_verification'])}, headers
        if path == '/api/login' and post:
            return self.login(db,obj,sid,headers), headers
        if path == '/api/register' and post:
            user = create_user(db,obj,settings_row(db))
            token = issue_session(db,user['id'])
            headers['Set-Cookie'] = f'{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={TTL}'
            return {'ok':True,'role':user['role']},headers
        if path == '/api/email/send-code' and post:
            with self.server.login_lock:
                failures = self.server.registrations
                now = time.monotonic()
                while failures and now - failures[0] > 600:
                    failures.popleft()
                if len(failures) >= 30:
                    raise Problem(429,'验证码请求过于频繁，请稍后再试')
                code = issue_email_code(db,obj.get('email'),time.time())
                failures.append(now)
            return {'ok':True},headers
        if path == '/api/login':
            raise Problem(405,'Use POST')
        me = self.viewer(db)
        if post and path == '/api/logout':
            db.execute('DELETE FROM sessions WHERE digest=?',(sid,))
            headers['Set-Cookie'] = f'{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
        elif not post and path == '/api/workspace':
            return self.workspace(db,gw,me), headers
        elif not post and path == '/api/usage.csv':
            headers['Content-Disposition'] = 'attachment; filename="ltzy-usage.csv"'
            rows = gw.csv_rows(db) if me['role']=='admin' else gw.csv_rows(db,user_id=me['id'])
            return export_csv(rows),headers
        elif post and path == '/api/keys':
            name = text(obj,'name',80)
            raw = 'ltzy_' + secrets.token_urlsafe(32)
            kid = 'key_' + secrets.token_hex(10)
            scope = obj.get('scope','chat')
            if scope not in ('chat','read'):
                raise Problem(400,'Invalid scope')
            db.execute('INSERT INTO api_keys VALUES(?,?,?,?,?,0,?,?)',
                       (kid,name,raw[:12],digest(raw),datetime.now(timezone.utc).isoformat(),scope,me['id']))
            row = db.execute('SELECT * FROM api_keys WHERE id=?',(kid,)).fetchone()
            return {'secret':raw,'key':key_view(row)},headers
        elif post and path == '/api/keys/revoke':
            if not db.execute('UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=?',
                              (text(obj,'id',120),me['id'])).rowcount:
                raise Problem(404,'密钥不存在')
        elif post and path == '/api/recharge':
            return self.recharge(db,obj,me),headers
        elif not post and path == '/api/recharges':
            rows = db.execute('SELECT * FROM recharges WHERE user_id=? ORDER BY rowid DESC LIMIT 100',
                              (me['id'],)).fetchall()
            return {'orders':[{'id':r['id'],'amount':r['amount_micros']/1e6,'status':r['status'],
                               'channel':r['channel'],'tradeNo':r['trade_no'],
                               'createdAt':r['created_at'],'paidAt':r['paid_at']} for r in rows]},headers
        elif not post and path == '/api/admin/overview':
            require_admin(me)
            users = [user_view(r) for r in db.execute('SELECT * FROM users ORDER BY created_at')]
            for u in users:
                spend, held = db.execute('SELECT coalesce(sum(cost),0),coalesce(sum(reserved),0) FROM receipts WHERE user_id=?',(u['id'],)).fetchone()
                keys, = db.execute('SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked=0',(u['id'],)).fetchone()
                u['spent'] = spend/1e6
                u['keys'] = keys
                u['balance'] = (u['balance']*1e6 - spend - held)/1e6
            return {'users':users,
                    'recharges':[dict(r) for r in db.execute(
                        'SELECT id,out_trade_no AS outTradeNo,amount_micros/1e6 AS amount,status,channel,trade_no AS tradeNo,created_at AS createdAt,paid_at AS paidAt FROM recharges ORDER BY rowid DESC LIMIT 100')]},headers
        elif post and path == '/api/admin/user':
            require_admin(me)
            return admin_update_user(db,obj,me),headers
        elif path == '/api/admin/settings':
            if not post:
                require_admin(me)
                return admin_settings_view(settings_row(db)),headers
            require_admin(me)
            apply_admin_settings(db,obj)
            return admin_settings_view(settings_row(db)),headers
        elif post and path == '/api/admin/test-email':
            require_admin(me)
            to = obj.get('to')
            if not valid_email(to):
                raise Problem(400,'请输入有效的邮箱地址')
            cfg = settings_row(db)
            if not mail.configured(cfg):
                raise Problem(400,'SMTP 尚未配置')
            try:
                mail.send(cfg,to.strip().lower(),'LTZY 测试邮件','这是一封 LTZY 系统设置页发出的测试邮件。收到即说明 SMTP 配置正确。')
            except OSError:
                raise Problem(502,'邮件发送失败，请检查 SMTP 主机、端口与凭据') from None
            return {'ok':True},headers
        elif post and path == '/api/reconcile':
            require_admin(me)
            rid = text(obj,'id',120)
            note = text(obj,'note',240)
            counts = [obj.get(k) for k in ('inputTokens','outputTokens')]
            if any(type(n) is not int or not 0 <= n <= 2147483647 for n in counts):
                raise Problem(400,'Expected nonnegative integer token counts')
            try:
                gw.reconcile(db,rid,*counts)
                db.execute('INSERT INTO reconciliation_audit VALUES(?,?,?,?,?)', (rid,note,datetime.now(timezone.utc).isoformat(),*counts))
            except ValueError:
                raise Problem(409,'Receipt is not pending or usage cannot be reconciled')
        elif post and path == '/api/lanes':
            require_admin(me)
            lid = text(obj,'id',120)
            enabled = obj.get('enabled')
            if not isinstance(enabled,bool):
                raise Problem(400,'Expected boolean enabled')
            lanes = gw.snapshot(db)['lanes']
            lane = next((l for l in lanes if l['id']==lid),None)
            if lane is None:
                raise Problem(404,'Unknown lane')
            if not enabled and lane['enabled'] and not any(l['id']!=lid and l['model']==lane['model'] and l['enabled'] for l in lanes):
                raise Problem(409,'Cannot disable the last enabled lane for this model')
            db.execute('INSERT INTO lane_settings VALUES(?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled',(lid,enabled))
        else:
            raise Problem(404,'Not found')
        return {'ok':True},headers

    def login(self,db,obj,sid,headers):
        with self.server.login_lock:
            failures = self.server.failures
            now = time.monotonic()
            while failures and now - failures[0] > 60:
                failures.popleft()
            if len(failures) >= 10:
                raise Problem(429,'Too many login attempts; retry in one minute')
            email = obj.get('email')
            password = obj.get('password')
            user = None
            if isinstance(email,str) and '@' in email:
                user = db.execute('SELECT * FROM users WHERE lower(email)=?',(email.strip().lower(),)).fetchone()
            elif isinstance(password,str):
                user = db.execute("SELECT * FROM users WHERE email='admin@local'").fetchone()
            if not user or not isinstance(password,str) or not verify_password(user['password_hash'],password):
                failures.append(now)
                raise Problem(401,'邮箱或密码不正确，请重试。')
            if user['status'] != 'active':
                raise Problem(403,'账号已被封禁')
            failures.clear()
        token = issue_session(db,user['id'])
        db.execute('DELETE FROM sessions WHERE expires<=?',(time.time(),))
        headers['Set-Cookie'] = f'{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={TTL}'
        return {'ok':True,'role':user['role'],'email':user['email']}

    def workspace(self,db,gw,me):
        mine = '' if me['role']=='admin' else ' WHERE user_id=?'
        args = () if me['role']=='admin' else (me['id'],)
        view = gw.snapshot(db,user_id=me['id'])
        view['me'] = {'email':me['email'],'role':me['role'],'balance':view['budget']['remaining']}
        for receipt in view['requests']:
            row = db.execute('SELECT note,at,input_tokens AS inputTokens,output_tokens AS outputTokens FROM reconciliation_audit WHERE receipt_id=?',(receipt['id'],)).fetchone()
            if row:
                receipt['audit'] = dict(row)
        view['keys'] = [key_view(r) for r in db.execute(
            'SELECT * FROM api_keys'+mine+' ORDER BY created_at DESC',args)]
        return view

    def recharge(self,db,obj,me):
        cfg = settings_row(db)
        if not cfg['epay_url'] or not cfg['epay_key'] or not cfg['epay_pid']:
            raise Problem(503,'支付通道尚未配置')
        amount = micros(obj.get('amount'))
        if not 10_000 <= amount <= 10_000_000_000:
            raise Problem(400,'充值金额需在 $0.01 and $10000')
        pay_type = obj.get('channel','alipay')
        if pay_type not in ('alipay','wxpay','qqpay'):
            raise Problem(400,'不支持的支付渠道')
        site = (cfg['site_url'] or '').rstrip('/')
        if not site:
            raise Problem(400,'站点公网地址未配置，请在系统设置中填写')
        oid = 'rch_' + secrets.token_hex(10)
        out_trade_no = 'LT' + secrets.token_hex(8)
        db.execute('''INSERT INTO recharges(id,user_id,out_trade_no,amount_micros,status,channel,created_at)
                      VALUES(?,?,?,?,?,?,?)''',
                   (oid,me['id'],out_trade_no,amount,'pending',pay_type,datetime.now(timezone.utc).isoformat()))
        params = pay.pay_params(cfg,out_trade_no,'LTZY credit',f'{amount/1e6:.2f}',
                                site+'/pay/notify',site+'/#billing',pay_type)
        if cfg['epay_version'] == 'v2':
            result = pay.v2_order(cfg,params)
            return {'order':oid,'payurl':result.get('payurl'),
                    'qrcode':result.get('qrcode'),'mode':'v2'}
        return {'order':oid,'payurl':pay.v1_payurl(cfg,params),'mode':'v1'}


def export_csv(rows):
    out = io.StringIO(newline='')
    fields = ['id','createdAt','model','keyId','lane','status','settlement','inputTokens','outputTokens','cost','reserved','latencyMs','price_input','price_output','price_version','price_currency']
    writer = csv.writer(out)
    writer.writerow(fields)
    for row in rows:
        values = [row.get(f,'') for f in fields]
        writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r','\n')) else v for v in values])
    return out.getvalue().encode('utf-8-sig')


class LocalServer(ThreadingHTTPServer):
    def server_close(self):
        super().server_close()
        if getattr(self,'instance_lock',None):
            self.instance_lock.close()


def lock_directory(root):
    # Startup recovery must not classify another live process's requests as interrupted.
    lock = open(root/'instance.lock','a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        lock.close()
        raise RuntimeError('Data directory is locked by another process') from e
    return lock


def create_server(data_dir='.ltzy', port=8000, host='127.0.0.1', gateway_module=None):
    if host not in ('localhost','127.0.0.1'):
        raise ValueError('Local service must bind to localhost or 127.0.0.1')
    if gateway_module is None:
        import gateway as gateway_module
    root = Path(data_dir).resolve()
    if root == WEB or WEB in root.parents:
        raise ValueError('Data directory must not be served as static files')
    root.mkdir(exist_ok=True,parents=True,mode=0o700)
    instance_lock = lock_directory(root)
    try:
        password_digest = bootstrap_password(root/'admin-password.txt')
        db_path = root/'ltzy.sqlite3'
        with closing(connect(db_path)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(SCHEMA)
            if 'scope' not in {r['name'] for r in db.execute('PRAGMA table_info(api_keys)')}:
                db.execute("ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT 'chat' CHECK(scope IN ('read','chat'))")
            gateway_module.init(db)
            db.commit()
        migrate(db_path, root)
        srv = LocalServer((host,port),Handler)
    except BaseException:
        instance_lock.close()
        raise
    srv.instance_lock = instance_lock
    srv.gateway = gateway_module
    srv.db_path = db_path
    srv.password_digest = password_digest
    srv.login_lock = Lock()
    srv.failures = deque()
    srv.registrations = deque()
    srv.hosts = {f'{h}:{srv.server_port}' for h in ('127.0.0.1','localhost')}
    if srv.server_port == 80:
        srv.hosts.update(('127.0.0.1','localhost'))
    return srv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--host', default='127.0.0.1', choices=('127.0.0.1','localhost'))
    parser.add_argument('--data-dir', default='.ltzy')
    args = parser.parse_args()
    with create_server(args.data_dir,args.port,args.host) as srv:
        print(f'LTZY: http://{args.host}:{srv.server_port}/  |  Admin password file: {Path(args.data_dir)/"admin-password.txt"}',flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
