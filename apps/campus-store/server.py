"""Campus Store: SQLite portal and separately authenticated Transit workers.

Python standard library only. There is no local crypto fallback or KMS admin route.
All people/accounts and orders in this private presentation app are fictional.
"""
import base64
import hmac
import http.cookies
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC = Path(__file__).parent / 'static'
CATALOG = [
    dict(id='mug', name='데일리 캠퍼스 머그', category='LIVING', price=14000, color='cream', tag='BEST', description='책상 위 작은 쉼표. 매일 손이 가는 350ml 머그.'),
    dict(id='bag', name='라이브러리 토트백', category='BAGS', price=19000, color='green', tag='EVERYDAY', description='책 한 권과 하루의 계획을 담는 넉넉한 캔버스백.'),
    dict(id='shirt', name='클럽 로고 티셔츠', category='APPAREL', price=29000, color='blue', tag='NEW', description='어느 계절에도 편안한, 캠퍼스의 기본 아이템.'),
    dict(id='notebook', name='아이디어 노트 세트', category='STATIONERY', price=9000, color='pink', tag='SET OF 2', description='떠오른 생각을 놓치지 않도록. 가볍게 들고 다녀요.'),
    dict(id='bottle', name='데스크 텀블러', category='LIVING', price=24000, color='lavender', tag='REUSABLE', description='길어진 공부 시간에도 함께하는 500ml 텀블러.'),
    dict(id='cap', name='위켄드 볼캡', category='APPAREL', price=22000, color='sand', tag='ESSENTIAL', description='강의가 없는 날에도, 가볍게 쓰기 좋은 볼캡.'),
]
PRODUCTS = {p['id']: p for p in CATALOG}
ACCOUNTS = {
    'hana': dict(id='hana', name='김하나', role='customer', label='고객'),
    'minjun': dict(id='minjun', name='이민준', role='customer', label='고객'),
    'shipping': dict(id='shipping', name='배송 담당', role='shipping', label='배송팀'),
    'marketing': dict(id='marketing', name='판매 분석 담당', role='marketing', label='분석팀'),
    'operator': dict(id='operator', name='보호 과정 안내', role='operator', label='발표자'),
}
STATUSES = ['received', 'preparing', 'shipping', 'delivered']
LIMIT = 32768


class APIError(Exception):
    def __init__(self, status, message, kms_status=None, challenge=False):
        super().__init__(message)
        self.status, self.message, self.kms_status = status, message, kms_status
        self.challenge = challenge


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def version(ciphertext):
    match = re.match(r'^kms:v([1-9][0-9]*):', ciphertext or '')
    if not match:
        raise APIError(502, 'KMS 암호문 형식이 올바르지 않습니다.')
    return int(match[1])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def post_json(url, payload, token, cafile):
    """TLS is mandatory. Never return/log upstream response text on error."""
    if not url.startswith('https://'):
        raise APIError(503, '암호화 연결 설정을 확인해 주세요.')
    try:
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx), NoRedirect())
        req = urllib.request.Request(url, data=encoded(payload), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+token}, method='POST')
        with opener.open(req, timeout=8) as response:
            body = response.read(131073)
            if len(body) > 131072:
                raise APIError(502, '보호 서비스 응답이 너무 큽니다.')
            return json.loads(body)
    except urllib.error.HTTPError as error:
        status = error.code if error.code in (400, 401, 403, 409, 413, 429, 503) else 502
        kms_status = error.code
        try:
            # Worker envelopes preserve whether KMS actually returned a status.
            # A worker connection/authentication failure is not a KMS denial.
            body = json.loads(error.read(16384))
            if isinstance(body, dict) and 'kms_status' in body:
                value = body['kms_status']
                kms_status = value if type(value) is int and 100 <= value <= 599 else None
        except (ValueError, OSError):
            pass
        finally:
            error.close()
        raise APIError(status, '보호 서비스 요청이 거부되었거나 처리되지 않았습니다.', kms_status) from None
    except APIError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise APIError(503, '보호 서비스에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.') from None


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS orders (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, items TEXT NOT NULL,
                    amount INTEGER NOT NULL, status TEXT NOT NULL,
                    ciphertext TEXT NOT NULL, previous_ciphertext TEXT,
                    created REAL NOT NULL, updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL NOT NULL,
                    service TEXT NOT NULL, operation TEXT NOT NULL,
                    status INTEGER NOT NULL, order_id TEXT NOT NULL
                );
            ''')
        os.chmod(path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        return DBConnection(db)

    def event(self, service, operation, status, order_id=''):
        with self.connect() as db:
            db.execute('INSERT INTO events(created,service,operation,status,order_id) VALUES (?,?,?,?,?)', (time.time(), service, operation, status, order_id))
            db.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-300 FROM events)')

    def get(self, order_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM orders WHERE id=?', (order_id,)).fetchone()
        if row is None:
            raise APIError(404, '주문을 찾을 수 없습니다.')
        return dict(row)

    def rows(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM orders ORDER BY created DESC')]

    @staticmethod
    def public(row, evidence=False):
        result = {key: row[key] for key in ('id', 'items', 'amount', 'status', 'created', 'updated')}
        result['items'] = json.loads(result['items'])
        result['version'] = version(row['ciphertext'])
        if evidence:
            result.update(ciphertext=row['ciphertext'], has_previous=bool(row['previous_ciphertext']))
        return result


class DBConnection:
    """sqlite3's own context manager does not close the connection."""
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        return self.db
    def __exit__(self, typ, val, tb):
        try:
            self.db.rollback() if typ else self.db.commit()
        finally:
            self.db.close()


class Application:
    def __init__(self, env=None, transport=post_json):
        self.env = dict(os.environ if env is None else env)
        self.mode = self.env.get('STORE_MODE', 'portal')
        self.key = self.env.get('STORE_KEY', 'campus-shipping')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', self.key) or self.key in ('demo', 'k8s-secrets'):
            raise ValueError('a dedicated store key is required')
        if self.mode not in ('portal', 'checkout', 'shipping', 'marketing', 'migration'):
            raise ValueError('unknown mode')
        self.transport = transport
        self.sessions = {}
        self.lock = threading.Lock()
        self.inflight = threading.BoundedSemaphore(24)
        self.db = Database(self.env.get('STORE_DB', '/data/orders.db')) if self.mode == 'portal' else None
        if self.mode == 'portal' and self.env.get('STORE_DEMO_ACCOUNTS') != '1':
            raise ValueError('explicit STORE_DEMO_ACCOUNTS=1 required for presentation accounts')

    def token(self, name):
        try:
            token = Path(self.env[name]).read_text().strip()
        except (OSError, KeyError):
            raise APIError(503, '서비스 자격을 읽을 수 없습니다.') from None
        if not token:
            raise APIError(503, '서비스 자격이 비어 있습니다.')
        return token

    def origin(self):
        value = self.token('STORE_ORIGIN_FILE') if self.env.get('STORE_ORIGIN_FILE') else self.env['STORE_ORIGIN']
        origin = value.rstrip('/')
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise APIError(503, 'HTTPS 접속 주소 설정을 확인해 주세요.')
        return origin

    def worker(self, operation, payload):
        allowed = {'checkout': 'encrypt', 'shipping': 'decrypt', 'marketing': 'decrypt', 'migration': 'rewrap'}
        if operation != allowed.get(self.mode):
            raise APIError(403, '이 서비스에서 지원하지 않는 작업입니다.')
        expected = 'plaintext' if operation == 'encrypt' else 'ciphertext'
        if set(payload) != {expected} or not isinstance(payload[expected], str) or len(payload[expected]) > 24000:
            raise APIError(400, '보호 요청 형식을 확인해 주세요.')
        base = self.env['KMS_TRANSIT_URL'].rstrip('/')
        result = self.transport(base+'/v1/'+operation+'/'+self.key, payload, self.token('KMS_TOKEN_FILE'), self.env['KMS_CA_FILE'])
        # A mistaken marketing grant is reported, but never leaks recovered data.
        if self.mode == 'marketing':
            return {'unexpected_access': True, 'kms_status': 200}
        return result

    def call(self, service, operation, payload, order_id=''):
        base = self.env['STORE_'+service.upper()+'_URL'].rstrip('/')
        try:
            result = self.transport(base+'/'+operation, payload, self.token('STORE_INTERNAL_TOKEN_FILE'), self.env['STORE_WORKER_CA'])
        except APIError as error:
            self.db.event(service, operation, error.kms_status or error.status, order_id)
            raise
        self.db.event(service, operation, 200, order_id)
        return result

    def login(self, account):
        if not isinstance(account, str) or account not in ACCOUNTS:
            raise APIError(400, '시연 계정을 선택해 주세요.')
        session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] > time.time()}
            if len(self.sessions) >= 500:
                raise APIError(429, '열린 시연 세션이 너무 많습니다.')
            self.sessions[session_id] = dict(account=ACCOUNTS[account], csrf=csrf, expires=time.time()+7200)
        return session_id, dict(account=ACCOUNTS[account], csrf=csrf)

    def session(self, session_id):
        with self.lock:
            session = self.sessions.get(session_id)
            if not session or session['expires'] < time.time():
                raise APIError(401, '시연 계정을 선택해 주세요.')
            return session

    @staticmethod
    def require(account, *roles):
        if account['role'] not in roles:
            raise APIError(403, '이 화면을 사용할 권한이 없습니다.')

    def list_orders(self, account):
        rows = self.db.rows()
        if account['role'] == 'customer':
            rows = [r for r in rows if r['owner'] == account['id']]
        return {'orders': [self.db.public(r) for r in rows]}

    def create_order(self, account, payload):
        self.require(account, 'customer')
        if set(payload) != {'items', 'recipient'} or not isinstance(payload['items'], list) or not 1 <= len(payload['items']) <= 6:
            raise APIError(400, '주문할 상품을 선택해 주세요.')
        recipient = payload['recipient']
        limits = {'name': 60, 'phone': 32, 'address': 240}
        if not isinstance(recipient, dict) or set(recipient) != set(limits):
            raise APIError(400, '배송정보를 확인해 주세요.')
        for field, limit in limits.items():
            if not isinstance(recipient[field], str) or not 1 <= len(recipient[field].strip()) <= limit:
                raise APIError(400, '배송정보를 빠짐없이 입력해 주세요.')
        recipient = {k: v.strip() for k, v in recipient.items()}
        items, amount, seen = [], 0, set()
        for item in payload['items']:
            if not isinstance(item, dict) or set(item) != {'id', 'quantity'}:
                raise APIError(400, '상품 형식을 확인해 주세요.')
            product = PRODUCTS.get(item['id']) if isinstance(item['id'], str) else None
            qty = item['quantity']
            if not product or type(qty) is not int or not 1 <= qty <= 9 or item['id'] in seen:
                raise APIError(400, '상품과 수량을 확인해 주세요.')
            seen.add(item['id'])
            items.append(dict(id=product['id'], name=product['name'], quantity=qty, price=product['price']))
            amount += product['price'] * qty
        if len(self.db.rows()) >= 1000:
            raise APIError(409, '시연 주문 한도에 도달했습니다.')
        order_id = 'CS-'+secrets.token_hex(5).upper()
        # Binding prevents swapping a valid ciphertext between different orders.
        protected = dict(order_id=order_id, owner=account['id'], recipient=recipient)
        ciphertext = self.call('checkout', 'encrypt', {'plaintext': base64.b64encode(encoded(protected)).decode()}, order_id).get('ciphertext')
        version(ciphertext)
        now = time.time()
        with self.db.connect() as db:
            db.execute('INSERT INTO orders VALUES (?,?,?,?,?,?,?,?,?)', (order_id, account['id'], json.dumps(items, ensure_ascii=False), amount, 'received', ciphertext, None, now, now))
        return {'order': self.db.public(self.db.get(order_id))}

    def recipient(self, account, order_id):
        self.require(account, 'shipping')
        row = self.db.get(order_id)
        response = self.call('shipping', 'decrypt', {'ciphertext': row['ciphertext']}, order_id)
        try:
            data = json.loads(base64.b64decode(response['plaintext'], validate=True))
            if data['order_id'] != order_id or data['owner'] != row['owner']:
                raise ValueError('binding')
            return {'recipient': data['recipient'], 'kms_status': 200, 'version': version(row['ciphertext'])}
        except (ValueError, KeyError, TypeError):
            raise APIError(502, '주문과 보호 데이터가 일치하지 않습니다.') from None

    def change_status(self, account, order_id, payload):
        self.require(account, 'shipping')
        if set(payload) != {'status'} or payload['status'] not in STATUSES:
            raise APIError(400, '배송 상태를 확인해 주세요.')
        with self.db.connect() as db:
            row = db.execute('SELECT status FROM orders WHERE id=?', (order_id,)).fetchone()
            if not row:
                raise APIError(404, '주문을 찾을 수 없습니다.')
            index = STATUSES.index(row['status'])
            if STATUSES.index(payload['status']) not in (index, min(index+1, 3)):
                raise APIError(409, '다음 배송 단계로만 변경할 수 있습니다.')
            db.execute('UPDATE orders SET status=?,updated=? WHERE id=?', (payload['status'], time.time(), order_id))
        return {'order': self.db.public(self.db.get(order_id))}

    def analytics(self, account):
        self.require(account, 'marketing', 'operator')
        rows = self.db.rows()
        stats = {p['id']: dict(id=p['id'], name=p['name'], quantity=0, amount=0) for p in CATALOG}
        for row in rows:
            for item in json.loads(row['items']):
                stats[item['id']]['quantity'] += item['quantity']
                stats[item['id']]['amount'] += item['quantity']*item['price']
        return dict(count=len(rows), amount=sum(r['amount'] for r in rows), delivered=sum(r['status']=='delivered' for r in rows), products=list(stats.values()))

    def evidence(self, account):
        self.require(account, 'operator')
        with self.db.connect() as db:
            events = [dict(r) for r in db.execute('SELECT created,service,operation,status,order_id FROM events ORDER BY id DESC LIMIT 40')]
        return dict(key=self.key, orders=[self.db.public(r, True) for r in self.db.rows()], events=events,
                    roles={'checkout': ['encrypt'], 'shipping': ['decrypt'], 'marketing': [], 'migration': ['rewrap']})

    def probe(self, account, payload):
        self.require(account, 'marketing', 'operator')
        kind = payload.get('kind', 'marketing')
        if kind not in ('marketing', 'current', 'previous', 'tamper') or (account['role']=='marketing' and kind!='marketing'):
            raise APIError(403, '허용되지 않은 확인 작업입니다.')
        row = self.db.get(payload.get('order_id', ''))
        ciphertext = row['previous_ciphertext'] if kind=='previous' else row['ciphertext']
        if not ciphertext:
            raise APIError(409, '재암호화 이전 암호문이 없습니다. 먼저 보호 버전을 갱신해 주세요.')
        if kind == 'tamper':
            # Mutate one encoded byte without altering the stored record.
            pos = ciphertext.rfind(':')+1
            ciphertext = ciphertext[:pos]+('A' if ciphertext[pos:pos+1]!='A' else 'B')+ciphertext[pos+1:]
        service = 'marketing' if kind=='marketing' else 'shipping'
        try:
            self.call(service, 'decrypt', {'ciphertext': ciphertext}, row['id'])
            status = 200
        except APIError as error:
            status = error.kms_status
        # Keep the operation an observation: a 503 is never labelled an RBAC success.
        outcome = 'allowed' if status == 200 else 'denied' if status == 403 else 'invalid' if status == 400 else 'unavailable'
        return dict(service=service, operation='decrypt', kind=kind, kms_status=status, outcome=outcome, order_id=row['id'], version=version(ciphertext))

    def migrate(self, account):
        self.require(account, 'operator')
        succeeded, failed = [], []
        for row in self.db.rows():
            try:
                response = self.call('migration', 'rewrap', {'ciphertext': row['ciphertext']}, row['id'])
                ciphertext = response.get('ciphertext')
                version(ciphertext)
                with self.db.connect() as db:
                    changed = db.execute('UPDATE orders SET previous_ciphertext=COALESCE(previous_ciphertext,ciphertext),ciphertext=?,updated=? WHERE id=? AND ciphertext=?', (ciphertext, time.time(), row['id'], row['ciphertext'])).rowcount
                    if not changed:
                        raise APIError(409, '다른 갱신과 충돌했습니다.')
                succeeded.append(row['id'])
            except APIError as error:
                failed.append(dict(order_id=row['id'], status=error.kms_status or error.status))
        return dict(updated=len(succeeded), failed=failed, total=len(succeeded)+len(failed))


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'CampusStore'
        def log_message(self, *args):
            pass  # No URL, identity, plaintext, token or request body in access logs.

        def send(self, status, data, content_type='application/json; charset=utf-8', cookie=None, challenge=False):
            body = data if isinstance(data, bytes) else encoded(data)
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            if challenge:
                self.send_header('WWW-Authenticate', 'Basic realm="Campus Store Demo", charset="UTF-8"')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if cookie:
                self.send_header('Set-Cookie', cookie)
            self.end_headers()
            self.wfile.write(body)

        def body(self):
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                raise APIError(400, 'JSON 형식으로 요청해 주세요.')
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                raise APIError(400, '잘못된 요청 길이입니다.')
            if not 0 < length <= LIMIT:
                raise APIError(413, '입력 데이터가 너무 큽니다.')
            try:
                value = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError):
                raise APIError(400, '요청을 읽을 수 없습니다.') from None
            if not isinstance(value, dict):
                raise APIError(400, '요청 형식이 올바르지 않습니다.')
            return value

        def do_GET(self):
            self.dispatch()
        def do_POST(self):
            self.dispatch()

        def dispatch(self):
            self.connection.settimeout(12)
            if not app.inflight.acquire(blocking=False):
                self.send(429, {'error': '요청이 많습니다. 잠시 후 다시 시도해 주세요.'})
                return
            try:
                self.route()
            except APIError as error:
                self.send(error.status, {'error': error.message, 'kms_status': error.kms_status}, challenge=error.challenge)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            except Exception:
                # Never include exception strings which may contain sensitive input.
                self.send(500, {'error': '요청을 처리하지 못했습니다. 다시 시도해 주세요.'})
            finally:
                app.inflight.release()

        def route(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == '/healthz' and self.command == 'GET':
                self.send(200, {'status': 'up', 'mode': app.mode})
                return
            if app.mode != 'portal':
                token = self.headers.get('Authorization','').removeprefix('Bearer ')
                if not hmac.compare_digest(token, app.token('STORE_INTERNAL_TOKEN_FILE')):
                    raise APIError(401, '내부 서비스 인증이 필요합니다.')
                if self.command != 'POST':
                    raise APIError(405, '지원하지 않는 메서드입니다.')
                self.send(200, app.worker(path.lstrip('/'), self.body()))
                return
            origin = app.origin()
            expected_host = urllib.parse.urlsplit(origin).netloc
            if self.headers.get('Host') != expected_host:
                raise APIError(403, '허용되지 않은 접속 주소입니다.')
            if app.env.get('STORE_ACCESS_PASSWORD_FILE'):
                # Only the local reverse proxy reaches this loopback listener.
                if self.headers.get('X-Forwarded-Proto') != 'https':
                    self.send_response(308)
                    self.send_header('Location', origin+'/store/')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                expected = 'Basic '+base64.b64encode(('demo:'+app.token('STORE_ACCESS_PASSWORD_FILE')).encode()).decode()
                if not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
                    raise APIError(401, '발표용 접속 계정과 암호를 입력해 주세요.', challenge=True)
            if app.env.get('STORE_REQUIRE_TAILSCALE') == '1':
                if self.client_address[0] not in ('127.0.0.1', '::1') or not self.headers.get('Tailscale-User-Login'):
                    raise APIError(401, '승인된 사설 HTTPS 경로로 접속해 주세요.')
            prefix = app.env.get('STORE_PREFIX', '/store').rstrip('/')
            # Serve strips its mount prefix; direct requests may retain it.
            if path == prefix:
                path = '/'
            elif path.startswith(prefix+'/'):
                path = path[len(prefix):]
            if self.command == 'GET' and path in ('/', '/index.html', '/app.js', '/style.css'):
                name = 'index.html' if path=='/' else path[1:]
                kind = 'text/html; charset=utf-8' if name.endswith('html') else 'text/javascript; charset=utf-8' if name.endswith('js') else 'text/css; charset=utf-8'
                self.send(200, (STATIC/name).read_bytes(), kind)
                return
            if self.command=='GET' and re.fullmatch(r'/art/(mug|bag|shirt|notebook|bottle|cap)\.svg', path):
                self.send(200, (STATIC/path[1:]).read_bytes(), 'image/svg+xml')
                return
            if self.command == 'POST':
                if self.headers.get('Origin') != origin or self.headers.get('X-Campus-Request') != '1':
                    raise APIError(403, '요청 출처를 확인할 수 없습니다.')
            cookies = http.cookies.SimpleCookie()
            try:
                cookies.load(self.headers.get('Cookie',''))
            except http.cookies.CookieError:
                raise APIError(401, '시연 계정을 다시 선택해 주세요.')
            session_id = cookies['campus_session'].value if 'campus_session' in cookies else ''
            if path == '/api/login' and self.command == 'POST':
                sid, result = app.login(self.body().get('account'))
                with app.lock:
                    app.sessions.pop(session_id, None)
                self.send(200, result, cookie=f'campus_session={sid}; Path={prefix or "/"}; HttpOnly; Secure; SameSite=Strict; Max-Age=7200')
                return
            session = app.session(session_id)
            account = session['account']
            if self.command == 'POST' and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''), session['csrf']):
                raise APIError(403, '세션이 변경되었습니다. 화면을 새로고침해 주세요.')
            if path == '/api/session' and self.command == 'GET':
                result = dict(account=account, csrf=session['csrf'], presentation_accounts=True)
            elif path == '/api/catalog' and self.command == 'GET':
                result = {'products': CATALOG}
            elif path == '/api/orders' and self.command == 'GET':
                result = app.list_orders(account)
            elif path == '/api/orders' and self.command == 'POST':
                result = app.create_order(account, self.body())
            elif path == '/api/analytics' and self.command == 'GET':
                result = app.analytics(account)
            elif path == '/api/evidence' and self.command == 'GET':
                result = app.evidence(account)
            elif path == '/api/probe' and self.command == 'POST':
                result = app.probe(account, self.body())
            elif path == '/api/migrate' and self.command == 'POST':
                self.body()
                result = app.migrate(account)
            elif re.fullmatch(r'/api/orders/CS-[A-F0-9]{10}/(recipient|status)', path) and self.command == 'POST':
                order_id, action = path.split('/')[3:5]
                payload = self.body()
                result = app.recipient(account, order_id) if action=='recipient' else app.change_status(account, order_id, payload)
            else:
                raise APIError(404, '요청한 화면을 찾을 수 없습니다.')
            self.send(200, result)
    return Handler


def main():
    os.umask(0o077)
    app = Application()
    host = app.env.get('STORE_BIND', '127.0.0.1' if app.mode == 'portal' else '0.0.0.0')
    port = int(app.env.get('STORE_PORT', '8300' if app.mode == 'portal' else '8443'))
    server = ThreadingHTTPServer((host, port), handler_for(app))
    server.daemon_threads = True
    if app.mode != 'portal':
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(app.env['STORE_TLS_CERT'], app.env['STORE_TLS_KEY'])
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    elif host not in ('127.0.0.1', '::1'):
        raise ValueError('portal must listen on loopback behind an HTTPS reverse proxy')
    print('Campus Store '+app.mode+' ready', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
