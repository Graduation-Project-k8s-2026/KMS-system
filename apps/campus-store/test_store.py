import base64
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import http.client

import server


class FakeKMS:
    """Only unit tests use this fake. Production has no fallback mode."""
    def __init__(self):
        self.records = {}
        self.version = 1
        self.fail = False
        self.calls = []

    def __call__(self, url, data, token, ca):
        service, operation = url.split('/')[2], url.split('/')[-1]
        self.calls.append((service, operation))
        if self.fail:
            raise server.APIError(503, 'offline')
        if service == 'marketing':
            raise server.APIError(403, 'denied', 403)
        if operation == 'encrypt':
            ciphertext = f'kms:v{self.version}:'+os.urandom(24).hex()
            self.records[ciphertext] = data['plaintext']
            return {'ciphertext': ciphertext}
        if operation == 'rewrap':
            ciphertext = f'kms:v{self.version}:'+os.urandom(24).hex()
            self.records[ciphertext] = self.records[data['ciphertext']]
            return {'ciphertext': ciphertext}
        if data['ciphertext'] not in self.records:
            raise server.APIError(400, 'invalid', 400)
        return {'plaintext': self.records[data['ciphertext']]}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        p = Path(self.temp.name)
        (p/'internal').write_text('private-test-token')
        self.env = {'STORE_MODE': 'portal', 'STORE_DEMO_ACCOUNTS':'1', 'STORE_DB': str(p/'orders.db'),
                    'STORE_ORIGIN': 'https://store.test', 'STORE_PREFIX': '/store',
                    'STORE_INTERNAL_TOKEN_FILE':str(p/'internal'), 'STORE_WORKER_CA':str(p/'ca')}
        for service in ['checkout', 'shipping', 'marketing', 'migration']:
            self.env['STORE_'+service.upper()+'_URL'] = 'https://'+service
        self.kms = FakeKMS()
        self.app = server.Application(self.env, self.kms)
        self.hana = server.ACCOUNTS['hana']
        self.shipping = server.ACCOUNTS['shipping']
        self.operator = server.ACCOUNTS['operator']

    def tearDown(self):
        self.temp.cleanup()

    def payload(self):
        return {'items':[{'id':'mug','quantity':2}], 'recipient':{'name':'PRIVATE-NAME-123','phone':'PRIVATE-PHONE-456','address':'PRIVATE-ADDRESS-789'}}

    def order(self):
        return self.app.create_order(self.hana,self.payload())['order']

    def test_persistence_no_plaintext_and_server_prices(self):
        order = self.order()
        self.assertEqual(order['amount'],28000)
        self.assertNotIn('ciphertext',order)
        fresh = server.Application(self.env,self.kms)
        self.assertEqual(len(fresh.list_orders(self.hana)['orders']),1)
        for p in Path(self.temp.name).glob('orders.db*'):
            data = p.read_bytes()
            for raw in self.payload()['recipient'].values():
                self.assertNotIn(raw.encode(),data)
        self.assertEqual(fresh.recipient(self.shipping,order['id'])['recipient'],self.payload()['recipient'])

    def test_customer_isolation_and_role_enforcement(self):
        order=self.order()
        self.assertEqual(self.app.list_orders(server.ACCOUNTS['minjun'])['orders'],[])
        for account in [self.hana,server.ACCOUNTS['marketing'],self.operator]:
            with self.assertRaises(server.APIError) as error:
                self.app.recipient(account,order['id'])
            self.assertEqual(error.exception.status,403)
        with self.assertRaises(server.APIError):
            self.app.evidence(self.hana)
        with self.assertRaises(server.APIError):
            self.app.migrate(self.shipping)

    def test_real_denial_observation_not_ui_simulation(self):
        order=self.order()
        proof=self.app.probe(server.ACCOUNTS['marketing'],{'order_id':order['id']})
        self.assertEqual(proof['kms_status'],403)
        self.assertEqual(proof['outcome'],'denied')
        self.assertIn(('marketing','decrypt'),self.kms.calls)
        self.kms.fail=True
        proof=self.app.probe(self.operator,{'order_id':order['id'],'kind':'marketing'})
        self.assertEqual(proof['outcome'],'unavailable')

    def test_crypto_failure_does_not_persist_order(self):
        self.kms.fail=True
        with self.assertRaises(server.APIError):self.order()
        self.assertEqual(self.app.db.rows(),[])

    def test_rotation_rewrap_swaps_only_ciphertext_and_preserves_old(self):
        order=self.order();before=self.app.db.get(order['id'])
        self.kms.version=2
        result=self.app.migrate(self.operator)
        self.assertEqual(result['updated'],1)
        after=self.app.db.get(order['id'])
        self.assertEqual(after['previous_ciphertext'],before['ciphertext'])
        self.assertEqual(server.version(after['ciphertext']),2)
        self.assertEqual(after['items'],before['items'])
        self.assertEqual(self.app.recipient(self.shipping,order['id'])['recipient'],self.payload()['recipient'])
        self.kms.fail=True
        result=self.app.migrate(self.operator)
        self.assertEqual(len(result['failed']),1)
        self.assertEqual(self.app.db.get(order['id'])['ciphertext'],after['ciphertext'])

    def test_order_binding_rejects_swapped_ciphertext(self):
        one=self.order();two=self.order()
        with self.app.db.connect() as db:
            db.execute('UPDATE orders SET ciphertext=? WHERE id=?',(self.app.db.get(one['id'])['ciphertext'],two['id']))
        with self.assertRaises(server.APIError) as error:self.app.recipient(self.shipping,two['id'])
        self.assertEqual(error.exception.status,502)

    def test_status_transition_and_validation(self):
        order=self.order()
        with self.assertRaises(server.APIError):self.app.change_status(self.shipping,order['id'],{'status':'delivered'})
        result=self.app.change_status(self.shipping,order['id'],{'status':'preparing'})
        self.assertEqual(result['order']['status'],'preparing')
        for bad in [0,10,True,1.5]:
            payload=self.payload();payload['items'][0]['quantity']=bad
            with self.assertRaises(server.APIError):self.app.create_order(self.hana,payload)

    def test_worker_fixed_key_and_operation(self):
        env=dict(self.env,STORE_MODE='shipping',KMS_TRANSIT_URL='https://kms.test',KMS_TOKEN_FILE=self.env['STORE_INTERNAL_TOKEN_FILE'],KMS_CA_FILE='/fake/ca')
        app=server.Application(env,self.kms)
        with self.assertRaises(server.APIError):app.worker('encrypt',{'plaintext':'anything'})
        with self.assertRaises(server.APIError):app.worker('decrypt',{'ciphertext':'x','key':'k8s-secrets'})

    def test_http_origin_csrf_sessions_and_xss_safe_assets(self):
        httpd=server.ThreadingHTTPServer(('127.0.0.1',0),server.handler_for(self.app))
        thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
        self.addCleanup(httpd.server_close);self.addCleanup(httpd.shutdown)
        conn=http.client.HTTPConnection('127.0.0.1',httpd.server_port)
        self.addCleanup(conn.close)
        headers={'Host':'store.test','Content-Type':'application/json','Origin':'https://evil.test','X-Campus-Request':'1'}
        conn.request('POST','/store/api/login',json.dumps({'account':'hana'}),headers)
        response=conn.getresponse();self.assertEqual(response.status,403);response.read()
        headers['Origin']='https://store.test'
        conn.request('POST','/store/api/login',json.dumps({'account':'hana'}),headers)
        response=conn.getresponse();self.assertEqual(response.status,200)
        cookie=response.getheader('Set-Cookie');data=json.loads(response.read())
        self.assertIn('HttpOnly',cookie);self.assertIn('Secure',cookie)
        headers['Cookie']=cookie.split(';')[0]
        conn.request('POST','/store/api/orders',json.dumps(self.payload()),headers)
        response=conn.getresponse();self.assertEqual(response.status,403);response.read()
        headers['X-CSRF-Token']=data['csrf']
        conn.request('POST','/store/api/orders',json.dumps(self.payload()),headers)
        response=conn.getresponse();self.assertEqual(response.status,200);response.read()
        conn.request('GET','/store/api/evidence',headers=headers)
        response=conn.getresponse();self.assertEqual(response.status,403);response.read()
        conn.request('GET','/store/',headers={'Host':'store.test'})
        response=conn.getresponse();body=response.read()
        self.assertEqual(response.status,200);self.assertIn('frame-ancestors',response.getheader('Content-Security-Policy'))
        self.assertNotIn(b'private-test-token',body)

    def test_public_https_password_gate_and_origin_reload(self):
        p=Path(self.temp.name)
        (p/'origin').write_text('https://public.test')
        (p/'password').write_text('presentation-test-password')
        self.app.env.update(STORE_ORIGIN_FILE=str(p/'origin'), STORE_ACCESS_PASSWORD_FILE=str(p/'password'))
        httpd=server.ThreadingHTTPServer(('127.0.0.1',0),server.handler_for(self.app))
        threading.Thread(target=httpd.serve_forever,daemon=True).start()
        self.addCleanup(httpd.server_close);self.addCleanup(httpd.shutdown)
        def request(path='/store/', extra=None):
            conn=http.client.HTTPConnection('127.0.0.1',httpd.server_port)
            headers={'Host':'public.test','X-Forwarded-Proto':'https', **(extra or {})}
            conn.request('GET',path,headers=headers)
            response=conn.getresponse();body=response.read();status=response.status;response_headers=dict(response.getheaders());conn.close()
            return status,response_headers,body
        status,headers,_=request(extra={'X-Forwarded-Proto':'http'})
        self.assertEqual(status,308);self.assertEqual(headers['Location'],'https://public.test/store/')
        self.assertNotIn('WWW-Authenticate',headers)
        for extra in [{},{'Authorization':'Basic wrong'},{'Tailscale-User-Login':'forged'}]:
            status,headers,_=request(extra=extra)
            self.assertEqual(status,401);self.assertIn('WWW-Authenticate',headers)
        auth={'Authorization':'Basic '+base64.b64encode(b'demo:presentation-test-password').decode()}
        self.assertEqual(request(extra=auth)[0],200)
        status,headers,_=request('/store/api/session',auth)
        self.assertEqual(status,401);self.assertNotIn('WWW-Authenticate',headers)
        (p/'origin').write_text('https://changed.test')
        self.assertEqual(request(extra=auth)[0],403)
        self.assertEqual(request(extra={**auth,'Host':'changed.test'})[0],200)
        (p/'origin').unlink()
        self.assertEqual(request(extra=auth)[0],503)


if __name__=='__main__':unittest.main()
