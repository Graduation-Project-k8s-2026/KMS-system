#!/usr/bin/env python3
"""Rotate the protected KEK once, verify old data, and observe new envelope key IDs.
A state file makes retries resume the same rotation instead of creating another version.
"""
import argparse
import base64
import json
import pathlib
import sys
import time
from kms_ops import atomic,kube,run,sha
import importlib.util

def module(name):
    s=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
backup=module('backup-kms');restore=module('restore-kms')

def envelope():
    return json.loads(run(['/home/ubuntu/kms-tools/kms-verify','--etcd-stdin'],run(backup.ETCD+['get','/registry/secrets/','--prefix','-w','json'])))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backup',required=True);p.add_argument('--state',required=True);p.add_argument('--fixture',required=True);p.add_argument('--evidence',required=True);a=p.parse_args()
    d=pathlib.Path(a.backup);restore.verify_backup(d);state=pathlib.Path(a.state)
    if state.exists():report=json.loads(state.read_text())
    else:
        old=backup.admin('/v1/keys/k8s-secrets')
        archived=json.loads((d/'state.json').read_text())['key_metadata']
        if archived['LatestVersion']!=old['LatestVersion']:raise ValueError('backup must contain current KEK')
        run(['/home/ubuntu/kms-tools/kms-verify','--read',a.fixture])
        snapshot=state.with_suffix('.etcd.db')
        run(backup.ETCD+['snapshot','save',str(snapshot)],timeout=180)
        run(['/usr/local/bin/etcdutl','snapshot','status',str(snapshot),'-w','json'])
        report={'before_key_id':'k8s-secrets:'+str(old['LatestVersion']),'before_version':old['LatestVersion'],'snapshot_sha256':sha(snapshot.read_bytes()),'stage':'intent','started_at':backup.stamp()}
        atomic(state,json.dumps(report,indent=2))
    current=backup.admin('/v1/keys/k8s-secrets')
    if current['LatestVersion']==report['before_version']:
        current=backup.admin('/v1/keys/k8s-secrets/rotate',{})
    if current['LatestVersion']!=report['before_version']+1:raise ValueError('unexpected concurrent rotation; review state')
    new='k8s-secrets:'+str(current['LatestVersion'])
    if not any(v['Version']==report['before_version'] for v in current['Versions']):raise ValueError('previous KEK missing')
    run(['/home/ubuntu/kms-tools/kms-verify','--read',a.fixture,'--require-key-change'])
    old=kube('get','secret','kms-v2-proof','-n','kms-bench-e2e','-o','json')
    if base64.b64decode(old['data']['sample'])!=b'kms-rev2-public-test':raise ValueError('old Secret failed')
    report.update(after_key_id=new,previous_kek_retained=True,previous_plugin_ciphertext_read=True,previous_secret_read=True,stage='waiting-for-apiserver')
    atomic(state,json.dumps(report,indent=2))
    doc={'apiVersion':'v1','kind':'Secret','metadata':{'name':'kms-v2-post-rotation','namespace':'kms-bench-e2e'},'stringData':{'sample':'kms-rev2-public-test'}}
    run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','apply','-f','-'],json.dumps(doc).encode())
    end=time.monotonic()+240
    while True:
        run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','-n','kms-bench-e2e','annotate','secret/kms-v2-post-rotation','kms.local/rotation-poll='+str(time.time_ns()),'--overwrite'])
        counts=envelope()
        if new in counts['key_id_counts']:break
        if time.monotonic()>end:raise RuntimeError('new key not observed in envelope before timeout')
        time.sleep(3)
    report.update(envelope_after=counts,stage='complete',completed_at=backup.stamp())
    atomic(state,json.dumps(report,indent=2));atomic(pathlib.Path(a.evidence),json.dumps(report,indent=2),0o644);print(json.dumps(report,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:print('Rotation stopped: '+str(e),file=sys.stderr);sys.exit(1)
