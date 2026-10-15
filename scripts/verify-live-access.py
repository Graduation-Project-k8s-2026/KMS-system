#!/usr/bin/env python3
"""Read-only/denied-request checks at the trusted host boundary; not an external-device login test."""
import argparse
import http.client
import importlib.util
import json
import pathlib
import stat
import uuid
from kms_ops import atomic

spec=importlib.util.spec_from_file_location('bench',pathlib.Path(__file__).with_name('benchmark-release.py'));bench=importlib.util.module_from_spec(spec);spec.loader.exec_module(bench)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence',required=True);p.add_argument('--temporary-viewer',action='store_true');a=p.parse_args();client=bench.HostAdmin()
    def call(path='/api/session',method='GET',identity=True,host=None,who=None):
        c=http.client.HTTPConnection('127.0.0.1',8201,timeout=10)
        headers={'Host':host or client.host}
        if identity:headers['Tailscale-User-Login']=who or client.who
        try:
            c.request(method,path,body='{}' if method=='POST' else None,headers=headers);r=c.getresponse();r.read();return r.status
        finally:c.close()
    cases={'authenticated_read':(call(),200),'missing_identity':(call(identity=False),401),'wrong_host':(call(host='wrong.invalid'),403),'missing_csrf':(call('/api/jobs','POST'),403),'unregistered_route':(call('/v1/not-allowed'),404)}
    roles=json.loads(pathlib.Path('/etc/custom-kms/gui/roles.json').read_text())['users']
    viewers=[who for who,role in roles.items() if role=='viewer']
    if viewers:cases['viewer_write']=(call('/api/jobs','POST',who=viewers[0]),403)
    if a.temporary_viewer:
        # Add only a fictional viewer for this local test, then revoke it and
        # restore the original bytes/owner/mode. No real account is modified.
        path=pathlib.Path('/etc/custom-kms/gui/roles.json');original=path.read_bytes();st=path.stat()
        doc=json.loads(original);who='release-check-'+uuid.uuid4().hex+'@invalid.example'
        doc['users'][who]='viewer';candidate=json.dumps(doc).encode()
        try:
            atomic(path,candidate,stat.S_IMODE(st.st_mode),(st.st_uid,st.st_gid))
            cases['temporary_viewer_read']=(call(who=who),200)
            cases['temporary_viewer_write']=(call('/api/jobs','POST',who=who),403)
        finally:
            if path.read_bytes()!=candidate:raise RuntimeError('roles changed concurrently; manual review required')
            atomic(path,original,stat.S_IMODE(st.st_mode),(st.st_uid,st.st_gid))
        cases['revoked_viewer_read']=(call(who=who),403)
    report={'scope':'live trusted-host proxy boundary; identities never output; no role file changes','viewer_configured':bool(viewers),'cases':{k:{'observed':v[0],'expected':v[1],'pass':v[0]==v[1]} for k,v in cases.items()}}
    report['status']='PASS' if all(x['pass'] for x in report['cases'].values()) else 'FAIL'
    atomic(pathlib.Path(a.evidence),json.dumps(report,indent=2),0o644)
    if report['status']!='PASS':raise RuntimeError('live access checks failed; inspect redacted evidence')
    print('Live access checks passed; no permitted write was submitted.')
if __name__=='__main__':main()
