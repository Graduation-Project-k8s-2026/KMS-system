#!/usr/bin/env python3
"""Boot restored etcd and an isolated API endpoint on loopback ports 12379/16443.
Uses restored keys/config/data only. No kubelet/controllers connect to the restored API.
Stops the two test containers on success/failure, leaving restored files for inspection.
"""
import argparse
import base64
import json
import pathlib
import sys
import time
import urllib.parse
import yaml
from kms_ops import atomic,flags,load,run

def wait_command(args,timeout=180):
    end=time.monotonic()+timeout
    while True:
        try:return run(args,timeout=10)
        except RuntimeError:
            if time.monotonic()>end:raise
            time.sleep(2)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backup',required=True);p.add_argument('--directory',required=True);p.add_argument('--evidence',required=True);a=p.parse_args()
    backup=pathlib.Path(a.backup).resolve();d=pathlib.Path(a.directory).resolve()
    report=json.loads((d/'restore-report.json').read_text())
    if report['backup_id']!=backup.name or not report['etcd_snapshot_restored']:raise ValueError('matching restored backup required')
    run(['/home/ubuntu/kms-tools/kms-verify','--socket',str(d/'run/kms-v2.sock'),'--read','/home/ubuntu/kms-lab/kms-v2-public-proof.json'])
    config=d/'config';cfg=load((config/'etc/kubernetes/encryption-config.yaml').read_bytes())
    providers=cfg['resources'][0]['providers']
    if len(providers)!=1 or providers[0].get('kms',{}).get('name')!='custom-kms':raise ValueError('final KMS-only configuration required')
    providers[0]['kms']['endpoint']='unix://'+str(d/'run/kms-v2.sock')
    atomic(d/'isolated-encryption.yaml',yaml.safe_dump(cfg))
    def container(name):return load((backup/'manifests'/name).read_bytes())['spec']['containers'][0]
    etcd=container('etcd.yaml');api=container('kube-apiserver.yaml')
    # Import the exact backed-up images; no floating pull is performed.
    run(['docker','load','-i',str(backup/'images.tar')],timeout=300)
    ef=flags(etcd)
    for key,value in list(ef.items()):
        if value.startswith('/etc/'):ef[key]=str(config/value.lstrip('/'))
    ef.update({'--data-dir':str(d/'etcd'),'--listen-client-urls':'https://127.0.0.1:12379','--advertise-client-urls':'https://127.0.0.1:12379','--listen-peer-urls':'https://127.0.0.1:12380','--listen-metrics-urls':'http://127.0.0.1:12381'})
    af=flags(api)
    for key,value in list(af.items()):
        if value.startswith('/etc/'):af[key]=str(config/value.lstrip('/'))
    af.update({'--etcd-servers':'https://127.0.0.1:12379','--secure-port':'16443','--bind-address':'127.0.0.1','--advertise-address':'127.0.0.1','--encryption-provider-config':str(d/'isolated-encryption.yaml')})
    # Refuse any original data/UDS/config paths left in the generated arguments.
    for f in [ef,af]:
        if any(v.startswith(('/var/lib/etcd','/etc/kubernetes','/run/custom-kms')) for v in f.values()):raise ValueError('production path remained in isolated arguments')
    names=['kms-drill-etcd-'+d.name,'kms-drill-api-'+d.name];started=[]
    def start(name,c,args,mounts):
        command=['docker','run','-d','--name',name,'--network=host','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs=/tmp:rw,nosuid,nodev,size=32m']
        for path,mode in mounts:command+=['-v',str(path)+':'+str(path)+':'+mode]
        # Official kube-apiserver carries a file capability; its bounding set
        # must retain NET_BIND_SERVICE even when binding a high loopback port.
        # DAC_OVERRIDE matches the production root API access to the 0600 UID10001
        # KMS socket; only the restored directory is mounted here.
        if c['name']=='kube-apiserver':command+=['--cap-add=NET_BIND_SERVICE','--cap-add=DAC_OVERRIDE']
        command+=['--entrypoint',c['name'],c['image'],*[k+'='+v for k,v in args.items()]]
        run(command);started.append(name)
    try:
        start(names[0],etcd,ef,[(config,'ro'),(d/'etcd','rw')])
        etcdctl=['/usr/local/bin/etcdctl','--endpoints=https://127.0.0.1:12379','--cacert='+str(config/'etc/kubernetes/pki/etcd/ca.crt'),'--cert='+str(config/'etc/kubernetes/pki/etcd/healthcheck-client.crt'),'--key='+str(config/'etc/kubernetes/pki/etcd/healthcheck-client.key')]
        wait_command(etcdctl+['endpoint','health'])
        start(names[1],api,af,[(config,'ro'),(d/'run','ro'),(d/'isolated-encryption.yaml','ro')])
        kubeconfig=config/'etc/kubernetes/admin.conf';original=load(kubeconfig.read_bytes())['clusters'][0]['cluster']['server']
        kubectl=['kubectl','--kubeconfig='+str(kubeconfig),'--server=https://127.0.0.1:16443','--tls-server-name='+urllib.parse.urlsplit(original).hostname,'--request-timeout=5s']
        wait_command(kubectl+['get','--raw=/readyz'])
        secrets=json.loads(run(kubectl+['get','secrets','-A','-o','json']))['items']
        expected={'kms-v2-proof','kms-v2-post-rotation'};found=set()
        for s in secrets:
            if s['metadata']['namespace']=='kms-bench-e2e' and s['metadata']['name'] in expected:
                if base64.b64decode(s['data']['sample'])!=b'kms-rev2-public-test':raise ValueError('restored Secret differs')
                found.add(s['metadata']['name'])
        if found!=expected:raise ValueError('restored proof Secrets absent')
        raw=run(etcdctl+['get','/registry/secrets/','--prefix','-w','json'])
        envelope=json.loads(run(['/home/ubuntu/kms-tools/kms-verify','--etcd-stdin'],raw))
        report.update(kms_decrypt_verified=True,etcd_control_plane_recovery_verified=True,restored_secret_read_count=len(secrets),public_proofs_verified=len(found),restored_envelope=envelope,scope='isolated etcd+apiserver+KMS; no restored kubelet/controller-manager/scheduler',production_data_unchanged=True)
        atomic(d/'restore-report.json',json.dumps(report,indent=2));atomic(pathlib.Path(a.evidence),json.dumps(report,indent=2),0o644)
        print('Restored etcd + KMS + API: old Secrets read and encrypted envelopes verified.')
    finally:
        for name in reversed(started):run(['docker','stop',name],timeout=45)
if __name__=='__main__':
    try:main()
    except Exception as e:print('Isolated restore stopped: '+str(e)+'; test data retained, production data not replaced.',file=sys.stderr);sys.exit(1)
