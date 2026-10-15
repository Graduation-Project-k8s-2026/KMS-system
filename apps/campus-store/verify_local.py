#!/usr/bin/env python3
"""End-to-end checks against isolated REAL KMS code; Kubernetes SAR is simulated.

Never reads production kubeconfig, keys, sockets or credentials. Browser tooling
is optional and used only by this development verifier, never by the app image.
"""
import argparse
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import server as store


def serve(handler, servers, cert=None, key=None):
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    httpd.daemon_threads = True
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    servers.append(httpd)
    return httpd


class Client:
    def __init__(self, origin, ca):
        self.origin, self.csrf = origin, ''
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, body=None, expected=200):
        headers = {'Origin': self.origin, 'X-Campus-Request': '1',
                   'X-CSRF-Token': self.csrf, 'Content-Type': 'application/json'}
        req = urllib.request.Request(self.origin+'/store/api'+path,
                                     data=None if body is None else store.encoded(body), headers=headers)
        try:
            response = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
            assert response.status == expected, (path, response.status, expected, result)
        return result

    def login(self, account):
        self.csrf = self.request('/login', {'account': account})['csrf']


def browser_checks(origin, screenshots, credentials=None, strict_tls=False):
    from playwright.sync_api import sync_playwright, expect
    screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=['--no-sandbox'])
        context = browser.new_context(ignore_https_errors=not strict_tls, http_credentials=credentials, locale='ko-KR', viewport={'width': 1440, 'height': 1100})
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))

        def account(name, heading):
            if not page.locator('#accountDialog').is_visible():
                page.locator('#accountButton').click()
            page.locator('[data-action="login"][data-id="'+name+'"]').click()
            page.get_by_role('heading', name=heading).wait_for()

        def shot(name):
            page.locator('img').evaluate_all("images => Promise.all(images.map(img => { img.loading='eager'; return img.decode(); }))")
            expect(page.locator('#toast')).not_to_have_class('toast show')
            page.screenshot(path=str(screenshots/(name+'.png')), full_page=name!='03-shipping')

        # Reproduce a slow initial session check arriving after account selection.
        initial_session = []
        page.route('**/api/session', lambda route: initial_session.append(route))
        page.goto(origin+'/store/')
        account('hana', '매일 함께할 물건들')
        assert initial_session
        initial_session[0].fulfill(status=401,content_type='application/json',body='{"error":"delayed initial session"}')
        page.unroute('**/api/session')
        page.wait_for_timeout(200)
        expect(page.locator('#accountDialog')).not_to_be_visible()
        previous_count = page.evaluate("async () => (await (await fetch('/store/api/orders')).json()).orders.length")
        shot('01-storefront')
        page.get_by_role('button', name='데일리 캠퍼스 머그 장바구니에 담기').click()
        page.get_by_role('button', name='주문하기 →').click()
        page.locator('#sampleButton').click()
        page.locator('#checkoutForm button[type="submit"]').click()
        page.get_by_role('heading', name='기다리는 즐거움, 내 주문').wait_for()
        expect(page.locator('.order-card')).to_have_count(previous_count+1)
        shot('02-orders')
        account('shipping', '배송을 준비하는 공간')
        page.get_by_role('button', name='배송정보 확인').first.click()
        page.locator('.recipient-box').wait_for()
        assert '가상시' in page.locator('#detailBody').inner_text()
        shot('03-shipping')
        page.locator('[data-close="detailDialog"]').click()
        expect(page.locator('#detailBody')).to_have_text('')
        # A slow decrypt response must not restore plaintext after closing.
        pending = []
        page.route('**/api/orders/*/recipient', lambda route: pending.append(route))
        page.get_by_role('button', name='배송정보 확인').first.click()
        page.wait_for_timeout(100)
        assert pending
        page.locator('[data-close="detailDialog"]').click()
        pending[0].fulfill(response=pending[0].fetch())
        page.wait_for_timeout(200)
        assert page.locator('#detailBody').inner_text() == ''
        page.unroute('**/api/orders/*/recipient')
        account('marketing', '숫자로 만나는 스토어')
        page.get_by_role('button', name='분석 서비스로 조회 시도').click()
        page.get_by_text('이 서비스의 조회 권한이 없습니다.').wait_for()
        assert '403' in page.locator('#proofResult').inner_text()
        shot('04-analytics-denied')
        account('operator', '평범한 주문 뒤의 보호 과정')
        page.get_by_role('button', name='현재 암호문 확인').click()
        page.get_by_text('복호화 요청이 허용되었습니다.').wait_for()
        shot('05-evidence')
        account('hana', '매일 함께할 물건들')
        page.set_viewport_size({'width': 390, 'height': 844})
        shot('06-mobile')
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        assert not errors, errors
        browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--browser', action='store_true')
    parser.add_argument('--screenshots', default='/tmp/campus-store-screenshots')
    args = parser.parse_args()
    checks, servers = [], []
    process = None
    with tempfile.TemporaryDirectory(prefix='campus-isolated-') as temp:
        directory = Path(temp)
        with (directory/'fixture.log').open('w') as log:
            try:
                process = subprocess.Popen([args.fixture, '--dir', temp], stdout=log, stderr=log)
                for _ in range(150):
                    if (directory/'ready.json').exists():
                        break
                    if process.poll() is not None:
                        raise RuntimeError('isolated fixture exited; no production services were used')
                    time.sleep(.1)
                ready = json.loads((directory/'ready.json').read_text())
                cert, key = str(directory/'tls.crt'), str(directory/'tls.key')
                internal = directory/'internal.token'
                internal.write_text(secrets.token_urlsafe(40))
                os.chmod(internal, 0o600)
                env = {'STORE_MODE': 'portal', 'STORE_DEMO_ACCOUNTS': '1',
                       'STORE_DB': str(directory/'orders.db'), 'STORE_WORKER_CA': cert,
                       'STORE_INTERNAL_TOKEN_FILE': str(internal)}
                for mode in ('checkout', 'shipping', 'marketing', 'migration'):
                    worker = store.Application(dict(env, STORE_MODE=mode,
                        KMS_TRANSIT_URL=ready['url'], KMS_CA_FILE=cert,
                        KMS_TOKEN_FILE=str(directory/(mode+'.token'))))
                    httpd = serve(store.handler_for(worker), servers, cert, key)
                    env['STORE_'+mode.upper()+'_URL'] = 'https://127.0.0.1:'+str(httpd.server_port)

                app = store.Application(env)
                portal = serve(store.handler_for(app), servers)

                class Proxy(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass
                    def do_GET(self):
                        self.forward()
                    def do_POST(self):
                        self.forward()
                    def forward(self):
                        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                        connection = http.client.HTTPConnection('127.0.0.1', portal.server_port, timeout=15)
                        try:
                            connection.request(self.command, self.path, body=body, headers=dict(self.headers))
                            response = connection.getresponse()
                            self.send_response(response.status)
                            for name, value in response.getheaders():
                                if name.lower() not in ('server', 'date', 'connection'):
                                    self.send_header(name, value)
                            self.end_headers()
                            self.wfile.write(response.read())
                        finally:
                            connection.close()

                proxy = serve(Proxy, servers, cert, key)
                origin = 'https://127.0.0.1:'+str(proxy.server_port)
                app.env['STORE_ORIGIN'] = origin
                client = Client(origin, cert)

                def control(action):
                    return store.post_json(ready['url']+'/lab/'+action, {},
                                           (directory/'control.token').read_text(), cert)

                client.login('hana')
                recipient = {'name': 'LOCAL-FICTIONAL-CUSTOMER', 'phone': '000-0000-0000', 'address': 'LOCAL-FICTIONAL-ADDRESS'}
                order = client.request('/orders', {'items': [{'id': 'mug', 'quantity': 1}, {'id': 'bag', 'quantity': 1}], 'recipient': recipient})['order']
                oid = order['id']
                assert order['version'] == 1 and order['amount'] == 33000
                client.request('/evidence', expected=403)
                client.request('/orders/'+oid+'/recipient', {}, expected=403)
                checks.append('real Transit encrypt v1; server-side price and customer role enforcement')
                client.login('minjun')
                assert not client.request('/orders')['orders']
                client.request('/orders', {'items': [{'id': 'notebook', 'quantity': 2}], 'recipient': recipient})
                checks.append('customer order isolation')
                client.login('shipping')
                assert client.request('/orders/'+oid+'/recipient', {})['recipient'] == recipient
                assert client.request('/orders/'+oid+'/status', {'status': 'preparing'})['order']['status'] == 'preparing'
                checks.append('shipping real Transit decrypt and order status update')
                client.login('marketing')
                assert client.request('/analytics')['count'] == 2
                assert client.request('/probe', {'order_id': oid, 'kind': 'marketing'})['kms_status'] == 403
                checks.append('marketing actual HTTP 403 from KMS middleware with simulated SAR backend')
                client.login('operator')
                wrong_token = directory/'wrong-internal.token'
                wrong_token.write_text('isolated-wrong-token')
                app.env['STORE_INTERNAL_TOKEN_FILE'] = str(wrong_token)
                unavailable = client.request('/probe', {'order_id': oid, 'kind': 'marketing'})
                assert unavailable['outcome'] == 'unavailable' and unavailable['kms_status'] is None
                app.env['STORE_INTERNAL_TOKEN_FILE'] = str(internal)
                checks.append('worker authentication failure not reported as a KMS authorization result')
                assert client.request('/probe', {'order_id': oid, 'kind': 'tamper'})['kms_status'] == 400
                checks.append('tampered ciphertext rejected by real KMS')
                control('rotate')
                assert client.request('/probe', {'order_id': oid, 'kind': 'current'})['kms_status'] == 200
                result = client.request('/migrate', {})
                assert result == {'updated': 2, 'failed': [], 'total': 2}, result
                assert all(o['version'] == 2 for o in client.request('/evidence')['orders'])
                control('minimum2')
                assert client.request('/probe', {'order_id': oid, 'kind': 'previous'})['kms_status'] == 400
                assert client.request('/probe', {'order_id': oid, 'kind': 'current'})['kms_status'] == 200
                checks.append('rotation + rewrap persisted v2 + minimum version rejected v1, accepted v2')
                control('seal')
                assert client.request('/probe', {'order_id': oid, 'kind': 'current'})['outcome'] == 'unavailable'
                control('unseal')
                assert client.request('/probe', {'order_id': oid, 'kind': 'current'})['kms_status'] == 200
                checks.append('isolated seal unavailable and unseal recovery; production KMS untouched')
                assert len(store.Database(directory/'orders.db').rows()) == 2
                for path in directory.glob('orders.db*'):
                    assert b'LOCAL-FICTIONAL' not in path.read_bytes(), path.name
                checks.append('database reopened; test recipient plaintext absent from SQLite and WAL bytes')
                if args.browser:
                    browser_checks(origin, Path(args.screenshots))
                    checks.append('Chromium UI: purchase, shipping, marketing 403, evidence, 390px responsive layout, no JS exceptions')
                output = Path(args.output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({'result': 'PASS', 'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'scope': ready['scope'], 'production_deployment': 'NOT RUN; separate approval required',
                    'browser': args.browser, 'checks': checks}, ensure_ascii=False, indent=2)+'\n')
                print('PASS: '+str(len(checks))+' isolated integration checks; production untouched.')
            finally:
                for httpd in reversed(servers):
                    httpd.shutdown()
                    httpd.server_close()
                if process:
                    process.terminate()
                    process.wait(timeout=10)


if __name__ == '__main__':
    main()
