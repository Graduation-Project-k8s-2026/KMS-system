#!/usr/bin/env python3
"""Publish only Campus Store through public demo HTTPS; preserve KMS admin access.

No domain/account/client VPN required. Temporary tunnel hostnames change on
restart. Installs a dedicated systemd service, then deploys the password-gated app.
"""
import argparse
import base64
import hashlib
import grp
import json
import os
import pwd
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
VERSION = '2026.10.0'
DIGEST = 'e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08'
DOWNLOAD = 'https://github.com/cloudflare/cloudflared/releases/download/'+VERSION+'/cloudflared-linux-arm64'
BIN = '/usr/local/libexec/campus-store-edge'
STATE = '/var/lib/campus-store-edge'
UNIT = 'campus-store-edge.service'
SUDO = [] if os.geteuid()==0 else ['sudo','-n']


def run(args, data=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('command failed: '+args[len(SUDO)]+' (sensitive output suppressed)')
    return result.stdout


def current_origin():
    return run(SUDO+['cat', STATE+'/public/origin']).decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', default=str(Path.home()/'kms-lab/campus-store'))
    parser.add_argument('--status', action='store_true', help='Print current URL and password file path; no changes')
    args = parser.parse_args()
    runtime = Path(args.runtime)
    if args.status:
        print(json.dumps({'url': current_origin()+'/store/', 'username': 'demo', 'password_file': str(runtime/'access-password')}, ensure_ascii=False, indent=2))
        return
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    password_file = runtime/'access-password'
    if not password_file.exists():
        with password_file.open('x') as file:
            os.chmod(password_file, 0o600)
            file.write(secrets.token_urlsafe(24)+'\n')
    password = password_file.read_text().strip()
    if len(password)<24:
        raise RuntimeError('presentation password must have at least 24 characters')

    # Read-only snapshot of unrelated admin routes; never expose those upstreams.
    before = json.loads(run(SUDO+['tailscale','serve','status','--json'])) if shutil.which('tailscale') else {'Web':{}}
    roots = {host: site['Handlers']['/'] for host,site in before.get('Web',{}).items() if '/' in site.get('Handlers',{})}
    (runtime/'serve-before-public.json').write_text(json.dumps(before,indent=2))
    try:
        pwd.getpwuid(10001)
    except KeyError:
        try:
            grp.getgrgid(10001)
        except KeyError:
            run(SUDO+['groupadd','--gid','10001','campus-store-edge'])
        run(SUDO+['useradd','--system','--uid','10001','--gid','10001','--home-dir',STATE,'--no-create-home','--shell','/usr/sbin/nologin','campus-store-edge'])
    run(SUDO+['install','-d','-m','0755',BIN])
    run(SUDO+['install','-d','-o','10001','-g','10001','-m','0750',STATE,STATE+'/public'])
    changed = False
    with tempfile.TemporaryDirectory(prefix='campus-edge-') as temp:
        binary = Path(temp)/'cloudflared'
        existing = subprocess.run(SUDO+['sha256sum',BIN+'/cloudflared'],capture_output=True,text=True)
        if existing.returncode or existing.stdout.split()[0] != DIGEST:
            with urllib.request.urlopen(DOWNLOAD,timeout=60) as response:
                binary.write_bytes(response.read())
            if hashlib.sha256(binary.read_bytes()).hexdigest()!=DIGEST:
                raise RuntimeError('cloudflared release checksum mismatch')
            run(SUDO+['install','-m','0755',str(binary),BIN+'/cloudflared'])
            changed = True
    for source,destination in [(HERE/'public_edge.py',BIN+'/public_edge.py'),(HERE/UNIT,'/etc/systemd/system/'+UNIT)]:
        old = subprocess.run(SUDO+['cmp','-s',str(source),destination])
        changed = changed or old.returncode != 0
        run(SUDO+['install','-m','0644',str(source),destination])
    run(SUDO+['systemctl','daemon-reload'])
    run(SUDO+['systemctl','enable',UNIT])
    run(SUDO+['systemctl','restart' if changed else 'start',UNIT])
    for _ in range(90):
        try:
            origin = current_origin()
            if origin.startswith('https://') and origin.endswith('.trycloudflare.com'):
                break
        except RuntimeError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError('public tunnel did not produce an origin; inspect dedicated systemd service')
    print('Public HTTPS entrance ready; deploying password-gated app.',flush=True)
    subprocess.run([sys.executable,str(HERE/'deploy.py'),'--access','public','--runtime',str(runtime)],cwd=ROOT,check=True)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    auth = 'Basic '+base64.b64encode(('demo:'+password).encode()).decode()
    for _ in range(30):
        try:
            origin = current_origin()
            req = urllib.request.Request(origin+'/store/',headers={'Authorization':auth})
            with opener.open(req,timeout=15) as response:
                if response.status==200 and b'Campus Store' in response.read():
                    break
        except (OSError,urllib.error.URLError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError('public HTTPS not ready; old admin route remains unchanged')
    try:
        opener.open(origin+'/store/',timeout=15)
        raise RuntimeError('public entrance unexpectedly allowed anonymous access')
    except urllib.error.HTTPError as error:
        if error.code!=401:raise

    # Remove only the previous store route after public HTTPS is proven working.
    for site in before.get('Web',{}).values():
        for path in ('/store','/store/'):
            route = site.get('Handlers',{}).get(path)
            if route and route.get('Proxy')=='http://127.0.0.1:8300':
                run(SUDO+['tailscale','serve','--https=443','--set-path='+path,'off'])
    after = json.loads(run(SUDO+['tailscale','serve','status','--json'])) if shutil.which('tailscale') else {'Web':{}}
    if any(after['Web'][host]['Handlers']['/']!=route for host,route in roots.items()):
        raise RuntimeError('existing admin root route changed unexpectedly')
    report = {'access':'public','url':origin+'/store/','username':'demo','password_file':str(password_file),
              'cloudflared_version':VERSION,'cloudflared_sha256':DIGEST,
              'anonymous_status':401,'authenticated_status':200,'tls_verified':True,
              'client_vpn_required':False,'legacy_store_route_removed':True,'existing_admin_routes_preserved':True,
              'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    (runtime/'public-access.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Public Campus Store verified. Username: demo. Password is in '+str(password_file),flush=True)
    print('URL: '+origin+'/store/',flush=True)


if __name__=='__main__':
    main()
