#!/usr/bin/env python3
"""Browser verification over actual public TLS, without a Tailscale identity.

Uses existing temporary Playwright installation or a developer's environment.
Creates one fictional order, captures UI, and never saves credentials in evidence.
"""
import base64
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'apps/campus-store'))
from verify_local import browser_checks


def main():
    runtime = Path.home()/'kms-lab/campus-store'
    meta = json.loads((runtime/'deployment.json').read_text())
    assert meta['access']=='public'
    origin = subprocess.check_output(['sudo','-n','cat',meta['origin_file']]).decode().strip()
    host = urllib.parse.urlsplit(origin).hostname
    addresses = sorted({a[4][0] for a in socket.getaddrinfo(host,443)})
    assert all(ipaddress.ip_address(a).is_global for a in addresses)
    password = (runtime/'access-password').read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    cases = [('missing',{}),('wrong',{'Authorization':'Basic '+base64.b64encode(b'demo:wrong').decode()}),
             ('forged-tailscale',{'Tailscale-User-Login':'forged'})]
    for name,headers in cases:
        try:
            opener.open(urllib.request.Request(origin+'/store/',headers=headers),timeout=15)
            raise AssertionError('unauthorized request allowed: '+name)
        except urllib.error.HTTPError as error:
            assert error.code==401 and error.headers.get('WWW-Authenticate','').startswith('Basic ')
            error.close()
    browser_checks(origin,ROOT/'docs/demo/screenshots/public',{'username':'demo','password':password},strict_tls=True)
    report = {'result':'PASS','time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
              'scope':'actual public HTTPS + Chromium + real KMS; no synthetic proxy headers',
              'tls_certificate_verification':True,'resolved_addresses_are_public':True,
              'client_vpn_required':False,'missing_wrong_and_forged_identity_status':401,
              'checks':['password login','product images','new order + real encryption','shipping + real decryption',
                        'marketing KMS 403','current ciphertext accepted','late response cleared after closing',
                        'mobile 390px without overflow','no JavaScript exceptions']}
    (ROOT/'docs/demo/evidence/public-browser.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: public HTTPS browser flow, real KMS and credential rejection; TLS verified.')


if __name__=='__main__':
    main()
