#!/usr/bin/env python3
"""Restore a verified backup into a NEW directory; optional isolated KMS container.
Never touches production data or manifests. Existing shares must be entered interactively.
"""
import argparse
import json
import os
import pathlib
import sys
import tarfile
from kms_ops import atomic, flags, load, run, sha


def verify_backup(backup):
    state=json.loads((backup/'state.json').read_text())
    if not state.get('complete'):raise ValueError('backup was not completed')
    checks=json.loads((backup/'checksums.json').read_text())
    for name,digest in checks.items():
        if pathlib.Path(name).name!=name:raise ValueError('invalid checksum path')
        if sha((backup/name).read_bytes())!=digest:raise ValueError('backup checksum mismatch')
    return state

def extract(archive,dest):
    with tarfile.open(archive) as t:
        # No links/devices accepted: restore credentials must remain within the fixture.
        for m in t.getmembers():
            if not (m.isfile() or m.isdir()) or pathlib.PurePosixPath(m.name).is_absolute() or '..' in pathlib.PurePosixPath(m.name).parts:
                raise ValueError('unsafe archive member')
        t.extractall(dest,filter='data')
        # data filter deliberately strips ownership; restore original numeric IDs
        # only after every member was validated as an in-tree regular file/directory.
        for m in t.getmembers():os.chown(dest/m.name,m.uid,m.gid)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backup',required=True);p.add_argument('--directory',required=True);p.add_argument('--start-kms',action='store_true');p.add_argument('--resume',action='store_true');a=p.parse_args()
    if os.geteuid()!=0:raise ValueError('root required')
    backup=pathlib.Path(a.backup).resolve();dest=pathlib.Path(a.directory).resolve();state=verify_backup(backup)
    if not dest.is_relative_to('/var/backups/custom-kms-restores') or (dest.exists() and not a.resume):raise ValueError('new directory under /var/backups/custom-kms-restores required')
    if a.resume:
        report=json.loads((dest/'restore-report.json').read_text())
        if report['backup_id']!=state['backup_id']:raise ValueError('resume backup mismatch')
    else:
        dest.mkdir(parents=True,mode=0o700);extract(backup/'kms-data.tar.gz',dest/'data');extract(backup/'configuration-private.tar.gz',dest/'config')
    pod=load((backup/'manifests/kms-static-pod.yaml').read_bytes());c=pod['spec']['containers'][0]
    uid=c.get('securityContext',{}).get('runAsUser',10001);gid=c.get('securityContext',{}).get('runAsGroup',10001)
    for root in [dest/'data',dest/'run']:
        root.mkdir(exist_ok=True)
        for path in [root,*root.rglob('*')]:os.chown(path,uid,gid)
    etcd=load((backup/'manifests/etcd.yaml').read_bytes())['spec']['containers'][0];f=flags(etcd)
    args=['/usr/local/bin/etcdutl','snapshot','restore',str(backup/'etcd.db'),'--data-dir='+str(dest/'etcd'),'--name='+f['--name'],'--initial-cluster='+f['--initial-cluster'],'--initial-advertise-peer-urls='+f['--initial-advertise-peer-urls'],'--bump-revision=1000000000','--mark-compacted']
    if state['etcd_version'] not in run(['/usr/local/bin/etcdutl','version']).decode():raise ValueError('restore tool version mismatch')
    if not a.resume:run(args,timeout=180)
    report={'backup_id':state['backup_id'],'checksum_verified':True,'etcd_snapshot_restored':True,'etcd_control_plane_recovery_verified':False,'revision_bump':1000000000,'mark_compacted':True,'kms_decrypt_verified':False}
    atomic(dest/'restore-report.json',json.dumps(report,indent=2))
    if a.start_kms:
        name='kms-restore-'+dest.name
        if len(name)>100 or not all(x.isalnum() or x in '-_' for x in name):raise ValueError('invalid restore directory name')
        env={x['name']:x['value'] for x in c.get('env',[]) if 'value' in x}
        env.update(KMS_DATA_DIR='/restore/keys',KMS_AUDIT_DIR='/restore/audit',KMS_ADMIN_SOCKET='/restore/run/admin.sock',KMS_V2_SOCKET='/restore/run/kms-v2.sock',KMS_TRANSIT_ADDR='127.0.0.1:0',KMS_METRICS_ADDR='',KMS_AUTO_UNSEAL='false')
        (dest/'data/restore-audit').mkdir(mode=0o700,exist_ok=True);os.chown(dest/'data/restore-audit',uid,gid)
        args=['docker','run','-d','--name',name,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user='+str(uid)+':'+str(gid),'--tmpfs=/tmp:rw,nosuid,nodev,size=16m']
        mounts={dest/'data/keys':'/restore/keys',dest/'data/restore-audit':'/restore/audit',dest/'run':'/restore/run',dest/'config/etc/custom-kms':'/etc/custom-kms',dest/'config/etc/kubernetes/pki':'/etc/kubernetes/pki'}
        # Preserve every original config mount path without exposing its contents.
        volumes={v['name']:v.get('hostPath',{}).get('path') for v in pod['spec']['volumes']}
        for mount in c.get('volumeMounts',[]):
            host=volumes.get(mount['name'])
            if host and host.startswith('/etc/'):
                restored=dest/'config'/host.lstrip('/')
                if not restored.exists():raise ValueError('required configuration absent from backup')
                mounts[restored]=mount['mountPath']
        for host,container in mounts.items():args+=['-v',str(host)+':'+container+(':ro' if host.is_relative_to(dest/'config') else '')]
        for key,value in env.items():args+=['-e',key+'='+value]
        args+=[c['image']];run(args,timeout=120)
        report['container']=name;atomic(dest/'restore-report.json',json.dumps(report,indent=2))
        print('Isolated KMS started with network=none. Enter existing shares using:')
        print('sudo python3 scripts/host-unseal.py --socket '+str(dest/'run/admin.sock'))
        print('Then: sudo /home/ubuntu/kms-tools/kms-verify --socket '+str(dest/'run/kms-v2.sock')+' --read /home/ubuntu/kms-lab/kms-v2-public-proof.json')
        print('Stop after verification: sudo docker stop '+name)
    print('Snapshot restored in separate directory; production manifests/data unchanged.')
if __name__=='__main__':
    try:main()
    except Exception as e:print('Restore stopped: '+str(e),file=sys.stderr);sys.exit(1)
