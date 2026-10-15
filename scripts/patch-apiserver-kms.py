#!/usr/bin/env python3
"""Prepare an idempotent apiserver patch outside the watched directory; --apply commits it.
Never removes providers. Requires an existing verified backup and live RPC gate on apply.
"""
import argparse
import copy
import json
import os
import pathlib
import socket
import stat
import sys
import yaml
from kms_ops import atomic, flags, load, run, sha

CONFIG = '/etc/kubernetes/encryption-config.yaml'
SOCKET_DIR = '/run/custom-kms/kmsv2'
FLAG = '--encryption-provider-config'

def merge_named(items, expected, field='name'):
    if not isinstance(items, list) or any(not isinstance(x, dict) or field not in x for x in items):
        raise ValueError('invalid named list')
    names = [x[field] for x in items]
    if len(names) != len(set(names)): raise ValueError('duplicate named entry')
    for wanted in expected:
        matches = [x for x in items if x[field] == wanted[field]]
        if matches:
            if matches[0] != wanted: raise ValueError('conflicting existing mount/volume')
        else:
            if field == 'name' and 'mountPath' in wanted and any(x.get('mountPath') == wanted['mountPath'] for x in items):
                raise ValueError('mount path already occupied')
            items.append(wanted)

def patch(document):
    d = copy.deepcopy(document)
    if not isinstance(d, dict) or d.get('kind') != 'Pod': raise ValueError('Pod required')
    spec = d['spec']
    cs = spec['containers']
    if not isinstance(cs, list) or len([c for c in cs if c.get('name') == 'kube-apiserver']) != 1:
        raise ValueError('exactly one kube-apiserver container required')
    c = next(c for c in cs if c['name'] == 'kube-apiserver')
    f = flags(c)
    if FLAG in f and f[FLAG] != CONFIG: raise ValueError('existing provider requires explicit migration')
    if FLAG not in f: c['command'].append(FLAG+'='+CONFIG)
    merge_named(c.setdefault('volumeMounts', []), [
        {'name':'kms-encryption-config','mountPath':CONFIG,'readOnly':True},
        {'name':'kms-v2-socket','mountPath':SOCKET_DIR,'readOnly':True}])
    merge_named(spec.setdefault('volumes', []), [
        {'name':'kms-encryption-config','hostPath':{'path':CONFIG,'type':'File'}},
        {'name':'kms-v2-socket','hostPath':{'path':SOCKET_DIR,'type':'Directory'}}])
    return d

def validate_config(d):
    expected = {'apiVersion':'v2','name':'custom-kms','endpoint':'unix://'+SOCKET_DIR+'/kms-v2.sock','timeout':'3s'}
    if d.get('apiVersion') != 'apiserver.config.k8s.io/v1' or d.get('kind') != 'EncryptionConfiguration':
        raise ValueError('unexpected encryption configuration')
    resources = d.get('resources')
    if not isinstance(resources,list) or len(resources)!=1 or resources[0].get('resources')!=['secrets']:
        raise ValueError('existing resources require migration review')
    providers = resources[0].get('providers')
    if providers not in [[{'kms':expected}], [{'kms':expected},{'identity':{}}]]:
        raise ValueError('existing providers require migration review')

def check_access(d):
    c = next(c for c in d['spec']['containers'] if c['name']=='kube-apiserver')
    sc = {**d['spec'].get('securityContext',{}),**c.get('securityContext',{})}
    uid, gid = sc.get('runAsUser',0), sc.get('runAsGroup',0)
    if not isinstance(uid,int) or not isinstance(gid,int): raise ValueError('invalid UID/GID')
    # Inspect the running image default when runAsUser is absent; fail closed if not numeric/root.
    image = json.loads(run(['crictl','--runtime-endpoint=unix:///run/containerd/containerd.sock','inspecti',c['image']]))
    image_user = image.get('info',{}).get('imageSpec',{}).get('config',{}).get('User','')
    if 'runAsUser' not in sc and image_user not in ('','0','0:0','root'):
        raise ValueError('non-root image default must be made explicit for access check')
    path = pathlib.Path(SOCKET_DIR+'/kms-v2.sock')
    if not stat.S_ISSOCK(path.stat().st_mode): raise ValueError('KMS socket missing')
    pid=os.fork()
    if pid==0:
        try:
            os.setgroups(sc.get('supplementalGroups', []));os.setgid(gid);os.setuid(uid)
            s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(str(path));s.close()
            os._exit(0)
        except Exception: os._exit(1)
    if os.waitpid(pid,0)[1]: raise ValueError('apiserver UID/GID cannot access socket')
    return {'uid':uid,'gid':gid,'socket_connect':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',default='/etc/kubernetes/manifests/kube-apiserver.yaml')
    p.add_argument('--output',required=True);p.add_argument('--backup-dir',required=True)
    p.add_argument('--apply',action='store_true');p.add_argument('--probe',default='/home/ubuntu/kms-tools/kms-verify')
    a=p.parse_args();src=pathlib.Path(a.manifest);out=pathlib.Path(a.output);backup=pathlib.Path(a.backup_dir)
    if out.resolve().is_relative_to(src.parent.resolve()) or backup.resolve().is_relative_to(src.parent.resolve()):
        raise ValueError('candidate and backup must be outside watched directory')
    raw=src.read_bytes();d=load(raw);candidate=patch(d);validate_config(load(pathlib.Path(CONFIG).read_bytes()))
    rendered=yaml.safe_dump(candidate,sort_keys=False).encode();assert patch(load(rendered))==candidate
    out.parent.mkdir(parents=True,exist_ok=True,mode=0o700);atomic(out,rendered)
    # Structural diff deliberately excludes unrelated manifest content and credentials.
    report={'original_sha256':sha(raw),'candidate_sha256':sha(rendered),'changed':candidate!=d,
            'changes':['add '+FLAG+'='+CONFIG,'merge kms-encryption-config and kms-v2-socket mounts/volumes'],
            'candidate':str(out),'backup':str(backup/'kube-apiserver.original.yaml'),
            'recovery':'Keep KMS provider and keys after encrypted writes; restore a compatible KMS image. Original manifest is only safe before encrypted writes.'}
    if a.apply:
        if os.geteuid()!=0:raise ValueError('root required')
        if not (backup/'etcd.db').is_file() or not (backup/'kms-data.tar.gz').is_file():raise ValueError('etcd and consistent KMS backup required')
        state=json.loads((backup/'state.json').read_text())
        if not state.get('complete'):raise ValueError('incomplete backup')
        checks=json.loads((backup/'checksums.json').read_text())
        for name in ['etcd.db','kms-data.tar.gz']:
            if sha((backup/name).read_bytes())!=checks.get(name):raise ValueError('backup checksum mismatch')
        report['access']=check_access(candidate)
        run([a.probe])
        original=backup/'kube-apiserver.original.yaml'
        if candidate!=d and original.exists() and original.read_bytes()!=raw:raise ValueError('backup already belongs to another input')
        if not original.exists():atomic(original,raw)
        atomic(backup/'apiserver-patch.json',json.dumps(report,indent=2))
        if src.read_bytes()!=raw:raise ValueError('manifest changed since review')
        if candidate!=d:atomic(src,rendered,stat.S_IMODE(src.stat().st_mode))
    print(json.dumps(report,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:print('Patch refused: '+str(e),file=sys.stderr);sys.exit(1)
