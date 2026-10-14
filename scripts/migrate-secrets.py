#!/usr/bin/env python3
"""Verify current Secret storage or remove identity only after full rewrite and fresh snapshot.
Secret values are kept in memory and never included in output/evidence.
"""
import argparse
import base64
import importlib.util
import json
import pathlib
import sys
import time
import yaml
from kms_ops import atomic, kube, load, run, sha, wait_stopped

def module(name):
    spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
backup=module('backup-kms');patcher=module('patch-apiserver-kms');verifier=module('verify-etcd-encryption')

def inspect_current():
    # Compare names from a paginated API list with one consistent etcd range.
    # Retry if normal concurrent create/delete changes the set; never ignore mismatches.
    for _ in range(5):
        secrets=[];continuation=''
        import urllib.parse
        while True:
            page=kube('get','--raw','/api/v1/secrets?'+urllib.parse.urlencode({'limit':100,'continue':continuation}))
            secrets.extend(page['items']);continuation=page.get('metadata',{}).get('continue','')
            if not continuation:break
        api_keys={('/registry/secrets/'+s['metadata']['namespace']+'/'+s['metadata']['name']).encode() for s in secrets}
        raw=json.loads(run(backup.ETCD+['get','/registry/secrets/','--prefix','-w','json']))
        verifier.verify(raw)
        etcd_keys={base64.b64decode(x['key'],validate=True) for x in raw.get('kvs',[])}
        if api_keys==etcd_keys:
            return {'status':'PASS','api_read_count':len(secrets),'raw_encrypted_count':len(etcd_keys),'etcd_revision':raw['header']['revision'],'provider':'custom-kms','historical_plaintext_erased':False}
        time.sleep(1)
    raise RuntimeError('Secret set changed or API/etcd differ; retry during quiet period')

def proof():
    doc={'apiVersion':'v1','kind':'Secret','metadata':{'name':'kms-v2-proof','namespace':'kms-bench-e2e'},'stringData':{'sample':'kms-rev2-public-test'}}
    run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','apply','-f','-'],json.dumps(doc).encode())
    got=kube('get','secret','kms-v2-proof','-n','kms-bench-e2e','-o','json')
    if base64.b64decode(got['data']['sample'])!=b'kms-rev2-public-test':raise RuntimeError('proof roundtrip mismatch')
    raw=json.loads(run(backup.ETCD+['get','/registry/secrets/kms-bench-e2e/kms-v2-proof','-w','json']))
    verifier.verify(raw,1)
    if b'kms-rev2-public-test' in base64.b64decode(raw['kvs'][0]['value']):raise RuntimeError('plaintext in raw proof')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['verify','finalize']);p.add_argument('--evidence',required=True);p.add_argument('--backup-dir');a=p.parse_args()
    config=pathlib.Path(patcher.CONFIG);d=load(config.read_bytes());patcher.validate_config(d)
    proof();report=inspect_current()
    if a.action=='finalize':
        if not a.backup_dir:raise ValueError('--backup-dir required')
        out=pathlib.Path(a.backup_dir).resolve()
        if not out.is_relative_to('/var/backups/custom-kms'):raise ValueError('protected backup directory required')
        out.mkdir(parents=True,exist_ok=False,mode=0o700)
        backup.version_check()
        run(backup.ETCD+['snapshot','save',str(out/'etcd.db')],timeout=180)
        run(['/usr/local/bin/etcdutl','snapshot','status',str(out/'etcd.db'),'-w','json'])
        atomic(out/'encryption-config.before.yaml',config.read_bytes())
        report['snapshot_sha256']=sha((out/'etcd.db').read_bytes())
        report['before']=inspect_current()
        d['resources'][0]['providers']=[d['resources'][0]['providers'][0]]
        # Remove manifest first; rewrite config only after kubelet has stopped apiserver.
        # This prevents a crash from silently running an old process/config combination.
        (out/'held').mkdir(mode=0o700);backup.move_out(out,'kube-apiserver.yaml')
        try:
            wait_stopped(['kube-apiserver'])
            atomic(config,yaml.safe_dump(d,sort_keys=False))
        finally:
            backup.restore_manifest(out,'kube-apiserver.yaml')
        end=time.monotonic()+180
        while True:
            try:run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=5s','get','--raw=/readyz']);break
            except RuntimeError:
                if time.monotonic()>end:raise
                time.sleep(2)
        proof();report['after']=inspect_current();report['identity_removed']=True
    else:report['identity_removed']=len(d['resources'][0]['providers'])==1
    atomic(pathlib.Path(a.evidence),json.dumps(report,indent=2));print(json.dumps(report,indent=2))
if __name__=='__main__':
    try:main()
    except Exception:
        print('Migration stopped; no Secret contents logged. Retain KMS provider/keys. Inspect backup held/ manifests if interrupted.',file=sys.stderr);sys.exit(1)
