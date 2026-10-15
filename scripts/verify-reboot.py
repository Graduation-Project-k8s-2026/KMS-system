#!/usr/bin/env python3
"""Record/verify a real host boot-ID change, old ciphertext/Secrets and saved bench results.
Does not initiate reboot or input shares. KMS must be unsealed before check.
"""
import argparse
import base64
import datetime
import json
import pathlib
import sys
from kms_ops import atomic,kube,run,sha

def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def audit_snapshot(root):
    result = {}
    for file in sorted(root.rglob('*')):
        if file.is_file():
            size = file.stat().st_size
            with file.open('rb') as stream:
                result[str(file.relative_to(root))] = {'bytes': size, 'sha256': sha(stream.read(size))}
    return result

def verify_audit(root, records):
    for name, record in records.items():
        relative = pathlib.Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid audit path')
        file = root / relative
        with file.open('rb') as stream:
            if sha(stream.read(record['bytes'])) != record['sha256']:
                raise ValueError('old audit content absent/changed')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','check']);p.add_argument('--state',required=True);p.add_argument('--evidence');p.add_argument('--unseal-timing');a=p.parse_args()
    path=pathlib.Path(a.state);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();bench=pathlib.Path('/var/lib/custom-kms/admin-data/bench')
    audits = {'core': pathlib.Path('/var/lib/custom-kms/core-audit'), 'admin': pathlib.Path('/var/lib/custom-kms/admin-data/audit')}
    if a.action=='prepare':
        if path.exists():raise ValueError('state already exists')
        state={'before_boot_id':boot,'prepared_at':stamp(),'bench_hashes':{f.name:sha(f.read_bytes()) for f in bench.iterdir() if f.is_file()}}
        if not state['bench_hashes']:raise ValueError('no persistent results to verify')
        state['audit_hashes'] = {name: audit_snapshot(root) for name, root in audits.items()}
        if not all(state['audit_hashes'].values()):raise ValueError('no persistent audit records to verify')
        atomic(path,json.dumps(state,indent=2));print('Pre-reboot state saved; no reboot performed.');return
    state=json.loads(path.read_text())
    if state['before_boot_id']==boot:raise ValueError('boot ID unchanged; process restart is not a host reboot')
    rpc=json.loads(run(['/home/ubuntu/kms-tools/kms-verify','--read','/home/ubuntu/kms-lab/kms-v2-public-proof.json','--require-key-change']))
    for name,digest in state['bench_hashes'].items():
        if pathlib.Path(name).name!=name or sha((bench/name).read_bytes())!=digest:raise ValueError('old benchmark result absent/changed')
    if not state.get('audit_hashes'):raise ValueError('prepare a new state including audit records')
    for name, root in audits.items():verify_audit(root, state['audit_hashes'][name])
    for name in ['kms-v2-proof','kms-v2-post-rotation']:
        s=kube('get','secret',name,'-n','kms-bench-e2e','-o','json')
        if base64.b64decode(s['data']['sample'])!=b'kms-rev2-public-test':raise ValueError('old Secret differs')
    run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','get','--raw=/readyz'])
    for name in ('kms-admin', 'kms-prometheus'):
        run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','-n','kms-system','rollout','status','deployment/'+name,'--timeout=120s'], timeout=130)
    for service in ('containerd','kubelet','tailscaled'):
        run(['systemctl','is-active','--quiet',service])
    report={'status':'PASS','before_boot_id':state['before_boot_id'],'after_boot_id':boot,'prepared_at':state['prepared_at'],'verified_at':stamp(),'public_secret_proofs':2,'old_benchmark_results_preserved':len(state['bench_hashes']),'rpc':rpc,'manual_share_wait_included':True,'rto_upper_bound_seconds':(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(state['prepared_at'])).total_seconds()}
    report['audit_files_preserved'] = {name: len(records) for name, records in state['audit_hashes'].items()}
    report['deployments_ready'] = ['kms-admin','kms-prometheus']
    report['host_services_active'] = ['containerd','kubelet','tailscaled']
    if a.unseal_timing:
        timing = json.loads(pathlib.Path(a.unseal_timing).read_text())
        if timing['boot_id'] != boot or not timing['unsealed']:raise ValueError('unseal timing does not match this boot')
        report['unseal_timing'] = timing
        report['rto_excluding_measured_share_entry_seconds'] = report['rto_upper_bound_seconds'] - timing['elapsed_seconds']
        report['timing_limit'] = 'Upper bound includes operator reconnection and verification delay; only measured share entry is subtracted.'
    if not a.evidence:raise ValueError('--evidence required for check')
    atomic(pathlib.Path(a.evidence),json.dumps(report,indent=2),0o644);print(json.dumps(report,indent=2))
if __name__=='__main__':
    try:main()
    except Exception as e:print('Reboot verification stopped: '+str(e),file=sys.stderr);sys.exit(1)
