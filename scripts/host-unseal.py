#!/usr/bin/env python3
"""Enter existing Shamir shares at a local TTY; no initialization or share persistence."""
import argparse
import datetime
import getpass
import http.client
import json
import socket
import sys
import pathlib
import time
from kms_ops import atomic

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=10)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

def request(path, endpoint, body=None):
    c = UnixHTTP(path)
    try:
        c.request('GET' if body is None else 'POST', endpoint,
                  None if body is None else json.dumps(body), {'Content-Type':'application/json'})
        r = c.getresponse()
        data = r.read()
        if r.status != 200: raise RuntimeError('UDS request refused, HTTP '+str(r.status))
        return json.loads(data)
    finally: c.close()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',default='/run/custom-kms/admin/admin.sock');p.add_argument('--timing-file',help='Optional nonsecret successful unseal timing record');a=p.parse_args()
    if not sys.stdin.isatty(): raise RuntimeError('interactive TTY required; never pipe shares')
    s=request(a.socket,'/v1/sys/seal-status')
    if not s.get('initialized') or s.get('migration_required'):raise RuntimeError('existing initialized store required; Init is never called')
    started=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
    def success():
        if a.timing_file:
            record={'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'started_at':started,'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'unsealed':True}
            atomic(pathlib.Path(a.timing_file),json.dumps(record,indent=2))
        print('Unsealed; existing Root verified.')
    for _ in range(5):
        if not s.get('sealed'): success();return
        share=getpass.getpass('Existing Shamir share (hidden): ')
        try:s=request(a.socket,'/v1/sys/unseal',{'share':share})
        finally:share=None
        print('sealed='+str(s.get('sealed')))
    if s.get('sealed'):raise RuntimeError('still sealed; inspect share set locally')
    success()
if __name__=='__main__':
    try:main()
    except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)
