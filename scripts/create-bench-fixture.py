#!/usr/bin/env python3
"""Create a fixed Job and verify its authenticated result; never prints credentials."""
import argparse
import http.cookiejar
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fixture(opener, origin, mode, timeout=930, clock=time.monotonic, sleep=time.sleep):
    def read(path, data=None, headers=None):
        req = urllib.request.Request(origin + path, data=data, headers=headers or {})
        with opener.open(req, timeout=10) as response:
            return json.load(response)

    session = read('/api/session')
    spec = dict(mode=mode, scenario='basic', op='roundtrip', count=10,
                concurrency=1, payload_bytes=1024, duration_seconds=0)
    run = read('/api/jobs', json.dumps(spec).encode(),
               {'Content-Type': 'application/json', 'Origin': origin,
                'X-CSRF-Token': session['csrf_token']})
    run_id = run['run_id']
    if not re.fullmatch('[a-f0-9]{32}', run_id):
        raise ValueError('invalid run ID')
    deadline = clock() + timeout
    while True:
        run = read('/api/jobs/' + run_id)
        if run.get('run_id') != run_id:
            raise ValueError('run mismatch')
        state = run.get('state')
        if state in ('failed', 'cancelled', 'timed_out'):
            raise ValueError('Job failed or cancelled')
        if state == 'succeeded':
            expected_sa = {'transit': 'bench-transit', 'plugin': 'bench-plugin', 'e2e': 'bench-e2e'}[mode]
            if (run.get('upload') != 'stored' or not run.get('submitter_pod_uid')
                    or not run.get('job_uid') or run.get('service_account') != expected_sa):
                raise ValueError('submission binding absent')
            result = read('/api/bench/results/' + run_id)
            if (result.get('run_id') != run_id or result.get('mode') != mode
                    or result.get('errors') != 0 or result.get('success') != 10
                    or result.get('requests') != 10):
                raise ValueError('result mismatch or incomplete run')
            return run_id
        if clock() >= deadline:
            raise TimeoutError('Job verification timeout; run may still exist')
        sleep(2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--origin', required=True)
    p.add_argument('--ca-file')
    p.add_argument('--mode', choices=['transit', 'plugin', 'e2e'], default='transit')
    p.add_argument('--timeout', type=int, default=930)
    a = p.parse_args()
    u = urllib.parse.urlsplit(a.origin)
    if u.scheme != 'https' or not u.netloc or u.path or u.query or u.fragment or u.username:
        p.error('HTTPS origin without path, credentials, query or fragment required')
    if not 1 <= a.timeout <= 1200:
        p.error('timeout must be 1..1200 seconds')
    ctx = ssl.create_default_context(cafile=a.ca_file)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
    run_id = fixture(opener, a.origin, a.mode, a.timeout)
    print('run_id=' + run_id)
    print('state=succeeded; upload=stored; Job/SA/Pod-bound result verified')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('fixture verification failed; inspect tracked runs in the GUI; no credentials logged', file=sys.stderr)
        sys.exit(1)
