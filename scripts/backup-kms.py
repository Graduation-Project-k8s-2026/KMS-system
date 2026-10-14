#!/usr/bin/env python3
"""Resumable stopped single-node backup. prepare stops services; resume waits for manual unseal.
No original data is deleted. State and manifests are retained on every failure.
"""
import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import time
from kms_ops import atomic, containers, flags, kube, load, run, sha, wait_stopped

ROOT=pathlib.Path('/etc/kubernetes/manifests')
ETCD=['/usr/local/bin/etcdctl','--endpoints=https://127.0.0.1:2379','--cacert=/etc/kubernetes/pki/etcd/ca.crt','--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt','--key=/etc/kubernetes/pki/etcd/healthcheck-client.key']

def admin(endpoint,body=None):
    s=importlib.util.spec_from_file_location('unseal',pathlib.Path(__file__).with_name('host-unseal.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    return m.request('/run/custom-kms/admin/admin.sock',endpoint,body)

def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(d,state,stage):
    state['stage']=stage;state['updated_at']=stamp();state.setdefault('events',[]).append({'stage':stage,'at':state['updated_at']});atomic(d/'state.json',json.dumps(state,indent=2));print('stage='+stage,flush=True)

def move_out(d,name):
    source=ROOT/name;dest=d/'held'/name
    if source.exists() and dest.exists():raise RuntimeError('both live and held manifests exist; inspect before resuming')
    if source.exists():
        atomic(dest,source.read_bytes());source.unlink()
    if not dest.exists():raise RuntimeError('manifest absent in both locations')

def restore_manifest(d,name):
    source=d/'held'/name;dest=ROOT/name
    if source.exists():
        if dest.exists() and dest.read_bytes()!=source.read_bytes():raise RuntimeError('live manifest changed; refusing overwrite')
        if not dest.exists():atomic(dest,source.read_bytes())
        source.unlink()

def version_check():
    d=load((ROOT/'etcd.yaml').read_bytes());image=d['spec']['containers'][0]['image']
    version=image.split(':')[-1].split('-')[0]
    if not version.startswith('3.6.'):raise ValueError('only tested etcd 3.6 restore workflow supported')
    for tool in ['/usr/local/bin/etcdctl','/usr/local/bin/etcdutl']:
        if version not in run([tool,'version']).decode():raise ValueError('etcd tools must match deployed version')
    return version

def prepare(d):
    if (d/'state.json').exists():raise ValueError('backup already started; use resume, never overwrite')
    version=version_check()
    if admin('/v1/sys/seal-status').get('sealed'):raise ValueError('KMS must be unsealed at backup start')
    # No unfinished Jobs may be orphaned by stopping the controller/ingest listener.
    for ns in ['kms-bench','kms-bench-plugin','kms-bench-e2e']:
        for pod in kube('get','pods','-n',ns,'-o','json')['items']:
            if pod.get('status',{}).get('phase') not in ('Succeeded','Failed'):raise ValueError('active benchmark Pod; drain Jobs first')
    deployments=kube('get','deployments','-n','kms-system','-o','json')['items']
    allowed={'kms-admin','kms-prometheus','kms-demo-app'}
    if any(x['metadata']['name'] not in allowed for x in deployments):raise ValueError('unknown workload requires explicit write-quiescence review')
    d.mkdir(parents=True,mode=0o700);os.chmod(d,0o700);(d/'held').mkdir(mode=0o700)
    state={'schema_version':1,'backup_id':d.name,'started_at':stamp(),'etcd_version':version,'replicas':{x['metadata']['name']:x['spec'].get('replicas',1) for x in deployments},'key_metadata':admin('/v1/keys/k8s-secrets'),'complete':False}
    shutil.copytree(ROOT,d/'manifests')
    release=pathlib.Path(__file__).resolve().parents[1]/'docs/release/release-lock.json'
    if release.is_file():shutil.copyfile(release,d/'release-lock.json')
    save(d,state,'stopping-deployments')
    for name in state['replicas']:run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','-n','kms-system','scale','deployment/'+name,'--replicas=0'])
    names=[c['name'] for dep in deployments for c in dep['spec']['template']['spec']['containers']]
    wait_stopped(names)
    # Recheck after the admission endpoint has stopped, closing create/drain race.
    for ns in ['kms-bench','kms-bench-plugin','kms-bench-e2e']:
        if any(p.get('status',{}).get('phase') not in ('Succeeded','Failed') for p in kube('get','pods','-n',ns,'-o','json')['items']):
            raise RuntimeError('Job appeared while draining; resume and retry after completion')
    save(d,state,'stopping-apiserver');move_out(d,'kube-apiserver.yaml');wait_stopped(['kube-apiserver'])
    # Seal synchronously stops rotation and rejects further Transit/management writes.
    admin('/v1/sys/seal',{});save(d,state,'snapshot')
    run(ETCD+['snapshot','save',str(d/'etcd.db')],timeout=180)
    summary=json.loads(run(['/usr/local/bin/etcdutl','snapshot','status',str(d/'etcd.db'),'-w','json']))
    atomic(d/'etcd-status.json',json.dumps(summary,indent=2))
    save(d,state,'stopping-kms');move_out(d,'kms-static-pod.yaml')
    core=load((d/'held/kms-static-pod.yaml').read_bytes())['spec']['containers'][0]['name'];wait_stopped([core])
    save(d,state,'copying-stopped-data')
    run(['tar','--numeric-owner','-C','/var/lib/custom-kms','-czf',str(d/'kms-data.tar.gz'),'keys','admin-data','core-audit','prometheus'],timeout=300)
    paths=['etc/custom-kms','etc/kubernetes/pki','etc/kubernetes/admin.conf']
    if pathlib.Path('/etc/kubernetes/encryption-config.yaml').exists():paths.append('etc/kubernetes/encryption-config.yaml')
    run(['tar','--numeric-owner','-C','/','-czf',str(d/'configuration-private.tar.gz'),*paths],timeout=180)
    images=sorted({c['image'] for dep in deployments for c in dep['spec']['template']['spec']['containers']}|{c['image'] for f in (d/'manifests').glob('*.yaml') for c in load(f.read_bytes())['spec']['containers']})
    # Bench images are configured on admin and do not run continuously.
    for dep in deployments:
        for c in dep['spec']['template']['spec']['containers']:
            images.extend(e['value'] for e in c.get('env',[]) if e['name']=='ADMIN_API_BENCH_IMAGE')
    images=sorted(set(images));state['images']=images
    run(['ctr','-n','k8s.io','images','export',str(d/'images.tar'),*images],timeout=300)
    checks={f.name:sha(f.read_bytes()) for f in d.iterdir() if f.is_file() and f.name!='state.json'}
    atomic(d/'checksums.json',json.dumps(checks,indent=2));state['complete']=True;state['snapshot_at']=stamp()
    save(d,state,'awaiting-unseal');restore_manifest(d,'kms-static-pod.yaml')
    print('KMS restarted sealed. Run scripts/host-unseal.py at your TTY, then backup-kms.py resume --directory '+str(d),flush=True)

def resume(d):
    state=json.loads((d/'state.json').read_text())
    restore_manifest(d,'kms-static-pod.yaml')
    end=time.monotonic()+150
    while True:
        try:
            if not admin('/v1/sys/seal-status').get('sealed'):break
        except (OSError,RuntimeError):pass
        if time.monotonic()>end:raise RuntimeError('manual unseal pending; run host-unseal.py, then resume again')
        time.sleep(2)
    run(['/home/ubuntu/kms-tools/kms-verify'])
    restore_manifest(d,'kube-apiserver.yaml')
    end=time.monotonic()+180
    while True:
        try:run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','--request-timeout=5s','get','--raw=/readyz']);break
        except RuntimeError:
            if time.monotonic()>end:raise
            time.sleep(2)
    for name,replicas in state['replicas'].items():
        run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','-n','kms-system','scale','deployment/'+name,'--replicas='+str(replicas)])
        run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','-n','kms-system','rollout','status','deployment/'+name,'--timeout=150s'],timeout=160)
    state['recovered_at']=stamp();save(d,state,'resumed' if state['complete'] else 'resumed-incomplete-backup')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','resume','status']);p.add_argument('--directory',required=True);a=p.parse_args()
    if os.geteuid()!=0:raise ValueError('root required')
    d=pathlib.Path(a.directory).resolve()
    if not d.is_relative_to('/var/backups/custom-kms') or d==pathlib.Path('/var/backups/custom-kms'):raise ValueError('use dedicated /var/backups/custom-kms/<ID>')
    if a.action=='prepare':prepare(d)
    elif a.action=='resume':resume(d)
    else:print((d/'state.json').read_text())
if __name__=='__main__':
    try:main()
    except Exception as e:
        print('STOP: '+str(e)+'; original data retained. Check <directory>/state.json and held/. Resume: sudo python3 scripts/backup-kms.py resume --directory <directory>. If sealed, first run host-unseal.py.',file=sys.stderr);sys.exit(1)
