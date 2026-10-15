#!/usr/bin/env python3
"""Run fixed benchmark Jobs through the admin API and retain failures and provenance.
--host-admin uses the documented trusted loopback boundary; it is NOT a Tailscale login test.
"""
import argparse
import datetime
import http.client
import json
import os
import pathlib
import statistics
import sys
import time
import urllib.parse
from kms_ops import atomic, kube

class HostAdmin:
    def __init__(self):
        if os.geteuid()!=0:raise ValueError('host admin requires root')
        dep=kube('get','deployment','kms-admin','-n','kms-system','-o','json')
        env={x['name']:x['value'] for x in dep['spec']['template']['spec']['containers'][0]['env'] if 'value' in x}
        self.origin=env['ADMIN_API_PUBLIC_ORIGIN'];self.host=urllib.parse.urlsplit(self.origin).netloc
        # Roles are host-mounted configuration; never echo identities or CSRF tokens.
        roles=json.loads(pathlib.Path('/etc/custom-kms/gui/roles.json').read_text())['users']
        self.who=next(who for who,role in roles.items() if role=='admin')
        self.token=self.request('/api/session')['csrf_token']
    def request(self,path,body=None):
        c=http.client.HTTPConnection('127.0.0.1',8201,timeout=15)
        headers={'Host':self.host,'Tailscale-User-Login':self.who}
        if body is not None:headers.update({'Origin':self.origin,'X-CSRF-Token':self.token,'Cookie':'kms-csrf='+self.token,'Content-Type':'application/json'})
        try:
            c.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
            r=c.getresponse();data=r.read()
            if r.status not in (200,201,202):raise RuntimeError('admin request HTTP '+str(r.status))
            return json.loads(data)
        finally:c.close()

def execute(client,mode,spec,deadline=930):
    run=client.request('/api/jobs',dict(spec,mode=mode));rid=run['run_id'];end=time.monotonic()+deadline
    while time.monotonic()<end:
        run=client.request('/api/jobs/'+rid)
        if run['state'] in ('succeeded','failed','cancelled','timed_out'):
            row={'run_id':rid,'state':run['state'],'job_uid':run.get('job_uid'),'spec':dict(spec,mode=mode),'result':None}
            if run['state']=='succeeded':
                if run.get('upload')!='stored' or not run.get('submitter_pod_uid') or run.get('service_account')!={'transit':'bench-transit','plugin':'bench-plugin','e2e':'bench-e2e'}[mode]:raise ValueError('result binding mismatch')
                row['result']=client.request('/api/bench/results/'+rid)
                if row['result']['run_id']!=rid or row['result']['mode']!=mode:raise ValueError('result identity mismatch')
            return row
        time.sleep(2)
    return {'run_id':rid,'state':'observation_timeout','spec':dict(spec,mode=mode),'result':None}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--host-admin',action='store_true',required=True);p.add_argument('--provider',choices=['identity','kms-v2'],required=True);p.add_argument('--output',required=True);p.add_argument('--repeats',type=int,default=3);p.add_argument('--count',type=int,default=100);a=p.parse_args()
    if not 3<=a.repeats<=20 or not 1<=a.count<=100000:raise ValueError('invalid repetition/count')
    # Verify provider from actual apiserver configuration; never label by intent alone.
    from kms_ops import flags,load
    manifest=load(pathlib.Path('/etc/kubernetes/manifests/kube-apiserver.yaml').read_bytes())
    f=flags(next(c for c in manifest['spec']['containers'] if c['name']=='kube-apiserver'))
    cfg=f.get('--encryption-provider-config')
    actual='identity'
    if cfg:
        first=load(pathlib.Path(cfg).read_bytes())['resources'][0]['providers'][0]
        if first.get('kms',{}).get('apiVersion')=='v2':actual='kms-v2'
        elif 'identity' not in first:raise ValueError('unsupported provider')
    if actual!=a.provider:raise ValueError('provider label does not match configuration')
    out=pathlib.Path(a.output)
    if out.exists():raise ValueError('output already exists')
    out.mkdir(parents=True,mode=0o755);client=HostAdmin();failed=False
    for iteration in range(1,a.repeats+1):
        for mode in ['transit','plugin','e2e']:
            spec={'scenario':'basic','op':'roundtrip','count':a.count,'concurrency':1,'payload_bytes':1024,'duration_seconds':0}
            row=execute(client,mode,spec)
            row.update(iteration=iteration,encryption_provider=actual,access='trusted-host-loopback-not-tailnet-login',recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            atomic(out/(str(iteration)+'-'+mode+'.json'),json.dumps(row,indent=2),0o644)
            bad=row['state']!='succeeded' or row['result']['errors']!=0
            failed|=bad;print(mode+' '+str(iteration)+' '+row['state'],flush=True)
    if failed:sys.exit(1)
if __name__=='__main__':
    try:main()
    except Exception as e:print('Benchmark stopped: '+str(e),file=sys.stderr);sys.exit(1)
