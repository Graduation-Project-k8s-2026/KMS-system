#!/usr/bin/env python3
"""Verify the deployed store over public HTTPS (or legacy private loopback).

Creates two fictional orders, updates their shipping state and optionally restarts
only Portal. Uses REAL deployed workers, projected JWTs, KMS and Kubernetes SAR.
Does not rotate keys, change key policies, seal KMS, or read tokens/private keys.
Public mode uses actual TLS and Basic authentication without proxy identity injection.
Legacy private mode uses a synthetic local Serve identity, not a person tailnet login.
"""
import argparse
import base64
import http.client
import http.cookies
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

KUBE = ['sudo', '-n', 'kubectl', '--kubeconfig=/etc/kubernetes/admin.conf']


def kubectl(*args):
    return subprocess.check_output(KUBE+list(args), stderr=subprocess.PIPE)


class Client:
    def __init__(self, origin, password=None):
        self.origin = origin
        self.host = urllib.parse.urlsplit(origin).netloc
        self.cookie, self.csrf = '', ''
        self.password = password

    def request(self, path, body=None, expected=200, identity=True):
        headers = {'Host': self.host, 'Origin': self.origin,
                   'X-Campus-Request': '1', 'X-CSRF-Token': self.csrf,
                   'Cookie': self.cookie, 'Content-Type': 'application/json'}
        if self.password and identity:
            headers['Authorization'] = 'Basic '+base64.b64encode(('demo:'+self.password).encode()).decode()
        elif identity:
            headers['Tailscale-User-Login'] = 'local-deployment-verification'
        connection = http.client.HTTPSConnection(self.host,timeout=20) if self.password else http.client.HTTPConnection('127.0.0.1', 8300, timeout=20)
        try:
            connection.request('GET' if body is None else 'POST', '/store/api'+path,
                               body=None if body is None else json.dumps(body), headers=headers)
            response = connection.getresponse()
            data = json.load(response)
            assert response.status == expected, (path, response.status, expected)
            if response.getheader('Set-Cookie'):
                cookie = http.cookies.SimpleCookie(response.getheader('Set-Cookie'))
                self.cookie = 'campus_session='+cookie['campus_session'].value
            return data
        finally:
            connection.close()

    def login(self, account):
        self.csrf = self.request('/login', {'account': account})['csrf']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', default=str(Path.home()/'kms-lab/campus-store'))
    parser.add_argument('--output', default='docs/demo/evidence/campus-store-live.json')
    parser.add_argument('--restart-portal', action='store_true')
    args = parser.parse_args()
    runtime = Path(args.runtime)
    meta = json.loads((runtime/'deployment.json').read_text())
    public = meta.get('access')=='public'
    if public:
        meta['origin'] = subprocess.check_output(['sudo','-n','cat',meta['origin_file']]).decode().strip()
    result = {'result': 'IN_PROGRESS', 'scope': 'deployed portal + real workers + real KMS + real Kubernetes SAR',
              'browser_identity_scope': 'public HTTPS + actual Basic authentication; no Tailscale headers' if public else 'trusted host loopback with synthetic proxy header; not a person tailnet login',
              'key_policy_changes': False, 'kms_seal_or_restart': False,
              'namespace': 'campus-store', 'image': meta['image'], 'checks': []}
    checks = result['checks']
    client = Client(meta['origin'], (runtime/'access-password').read_text().strip() if public else None)
    client.request('/session', expected=401, identity=False)
    checks.append('public HTTPS rejected missing presentation credentials' if public else 'portal rejected loopback request without trusted proxy identity')

    # Only the host's actual HTTPS response; no fabricated identity over TLS.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    https = {}
    for path in ('/store/', '/'):
        try:
            response = opener.open(meta['origin']+path, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            https[path] = {'status': response.status, 'system_ca_and_hostname_verified': True}
            assert response.status in (200, 401, 403)
    result['https_host_self_access'] = https

    orders_path = runtime/('verification-orders-public.json' if public else 'verification-orders.json')
    orders = json.loads(orders_path.read_text()) if orders_path.exists() else {}
    recipients = {
        'hana': {'name': '시연용 고객 하나', 'phone': '000-0000-0000', 'address': '가상시 캠퍼스로 100, 테스트관 101호'},
        'minjun': {'name': '시연용 고객 민준', 'phone': '000-0000-0000', 'address': '가상시 캠퍼스로 200, 테스트관 202호'},
    }
    for account, item in [('hana', 'mug'), ('minjun', 'bag')]:
        client.login(account)
        if account not in orders:
            orders[account] = client.request('/orders', {'items': [{'id': item, 'quantity': 1}], 'recipient': recipients[account]})['order']['id']
            orders_path.write_text(json.dumps(orders))
            os.chmod(orders_path, 0o600)
        own = client.request('/orders')['orders']
        assert any(o['id'] == orders[account] for o in own)
        assert not any(o['id'] == orders.get('minjun' if account=='hana' else 'hana') for o in own)
        client.request('/orders/'+orders[account]+'/recipient', {}, expected=403)
    checks.append('real Transit encrypt persisted two fictional orders; customer isolation and role denial verified')

    client.login('shipping')
    for account, oid in orders.items():
        assert client.request('/orders/'+oid+'/recipient', {})['recipient'] == recipients[account]
    row = next(o for o in client.request('/orders')['orders'] if o['id']==orders['hana'])
    if row['status']=='received':
        assert client.request('/orders/'+orders['hana']+'/status', {'status': 'preparing'})['order']['status']=='preparing'
    checks.append('real shipping JWT decrypt returned matching fictional recipients and shipping state persisted')

    client.login('marketing')
    assert client.request('/analytics')['count'] >= 2
    denied = client.request('/probe', {'order_id': orders['hana'], 'kind': 'marketing'})
    assert denied['kms_status']==403 and denied['outcome']=='denied'
    checks.append('marketing real KMS + Kubernetes SAR denied decrypt with HTTP 403; aggregate sales still available')

    client.login('operator')
    tampered = client.request('/probe', {'order_id': orders['hana'], 'kind': 'tamper'})
    assert tampered['kms_status']==400
    proof = client.request('/evidence')
    assert proof['key']=='campus-shipping'
    assert all(o['ciphertext'].startswith('kms:v') for o in proof['orders'])
    checks.append('actual stored ciphertext visible in presenter view; tampered copy rejected with HTTP 400')
    result['orders'] = [{'id': o['id'], 'version': o['version']} for o in proof['orders'] if o['id'] in orders.values()]

    # Inspect a copy of bytes inside the app container; never print DB contents.
    script = '''import json,pathlib
needles=[s.encode() for s in %s]
files=list(pathlib.Path('/data').glob('orders.db*'))
assert files
assert all(needle not in p.read_bytes() for p in files for needle in needles)
print(json.dumps({'plaintext_absent':True,'files_checked':len(files)}))
''' % repr([v[k] for v in recipients.values() for k in ('name','address')])
    scan = json.loads(kubectl('-n', 'campus-store', 'exec', 'deployment/portal', '--', 'python3', '-c', script))
    assert scan['plaintext_absent']
    result['database_scan'] = scan
    checks.append('fictional recipient plaintext absent from actual SQLite/WAL files')

    if args.restart_portal:
        before = json.loads(kubectl('-n','campus-store','get','pods','-l','app=campus-portal','-o','json'))['items'][0]['metadata']['uid']
        kubectl('-n', 'campus-store', 'rollout', 'restart', 'deployment/portal')
        kubectl('-n', 'campus-store', 'rollout', 'status', 'deployment/portal', '--timeout=180s')
        after = json.loads(kubectl('-n','campus-store','get','pods','-l','app=campus-portal','-o','json'))['items'][0]['metadata']['uid']
        assert before != after
        client.login('shipping')
        for account, oid in orders.items():
            assert client.request('/orders/'+oid+'/recipient', {})['recipient'] == recipients[account]
        checks.append('Portal Pod replaced; same order IDs and recipient decrypt survived PVC-backed restart')

    deployments = json.loads(kubectl('-n','campus-store','get','deployments','-o','json'))['items']
    assert len(deployments)==5
    result['deployments'] = {d['metadata']['name']: d['status'].get('readyReplicas',0) for d in deployments}
    assert all(n==1 for n in result['deployments'].values())
    before = json.loads((runtime/('serve-before-public.json' if public else 'serve-before.json')).read_text())
    after = json.loads(subprocess.check_output(['sudo','-n','tailscale','serve','status','--json']))
    for host,site in before.get('Web',{}).items():
        if '/' in site['Handlers']:
            assert after['Web'][host]['Handlers']['/'] == site['Handlers']['/']
        if public:
            assert not any(path in after['Web'][host]['Handlers'] for path in ('/store','/store/'))
        else:
            assert after['Web'][host]['Handlers'].get('/store', after['Web'][host]['Handlers'].get('/store/'))['Proxy']=='http://127.0.0.1:8300'
    checks.append('all five deployments ready; original admin route preserved; legacy store route removed' if public else 'all five deployments ready; private store route exists')
    result.update(result='PASS', time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                  external_allowed_and_denied_device_test='NOT RUN', rotation_rewrap_minimum_version='isolated evidence only; production key policies unchanged')
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print('PASS: '+str(len(checks))+' deployed checks; real KMS + real Kubernetes SAR; no KMS key policy change.')


if __name__=='__main__':
    main()
