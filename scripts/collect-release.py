#!/usr/bin/env python3
"""Collect allowlisted release metadata; never dumps env, credentials, Secrets or logs."""
import argparse
import datetime
import json
import pathlib
import subprocess
import urllib.request
from kms_ops import atomic,kube,load,run,sha

def image(reference):
    d=json.loads(run(['crictl','--runtime-endpoint=unix:///run/containerd/containerd.sock','inspecti',reference]))
    spec=d.get('info',{}).get('imageSpec',{})
    # containerd manifest target is not the config/image ID; obtain it from image ls.
    target=None
    for line in run(['ctr','-n','k8s.io','images','list']).decode().splitlines()[1:]:
        fields=line.split()
        if fields and fields[0]==reference:target=next((f for f in fields if f.startswith('sha256:')),None)
    return {'reference':reference,'manifest_digest':target,'repo_digests':d['status'].get('repoDigests',[]),'config_id':d['status']['id'],'architecture':spec.get('architecture'),'os':spec.get('os'),'user':spec.get('config',{}).get('User')}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',default='docs/release/release-lock.json');a=p.parse_args()
    static=load(pathlib.Path('/etc/kubernetes/manifests/kms-static-pod.yaml').read_bytes())
    deployments=kube('get','deployments','-n','kms-system','-o','json')['items']
    products={'kms-server':image(static['spec']['containers'][0]['image']),'kms-demo-app':None}
    for d in deployments:
        c=d['spec']['template']['spec']['containers'][0];name=d['metadata']['name']
        key={'kms-admin':'kms-admin-api','kms-prometheus':'prometheus','kms-demo-app':'kms-demo-app'}[name];products[key]=image(c['image'])
        if name=='kms-admin':
            env={e['name']:e['value'] for e in c.get('env',[]) if 'value' in e}
            products['kms-bench']=image(env['ADMIN_API_BENCH_IMAGE'])
    head=run(['git','rev-parse','HEAD']).decode().strip()
    record={'schema_version':2,'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'base_sha':head,'release_sha':None,'source_state':'working tree includes host tools/tests/docs and pre-existing bench change; not a new product-image release','versions':{'go':run(['/home/ubuntu/kms-tools/go/bin/go','version']).decode().strip(),'kubernetes':kube('version','-o','json')['serverVersion']['gitVersion'],'etcd':run(['/usr/local/bin/etcdctl','version']).decode().splitlines()[0]},'images':products,'rollback_compatibility':{'storage_schema':1,'preserve_all_kek_versions':True,'compatible_previous_image':'same deployed server image; older schema compatibility unverified','remove_kms_provider_while_encrypted_secrets_exist':False},'demo_app':'deferred with section 10; no deployed image observed'}
    atomic(pathlib.Path(a.output),json.dumps(record,indent=2),0o644)
    out=pathlib.Path('docs/release/evidence/steps12-16')
    node=kube('get','nodes','-o','json')['items'][0]
    health={'recorded_at_utc':record['recorded_at_utc'],'node_ready':next(x['status'] for x in node['status']['conditions'] if x['type']=='Ready'),'deployments':{d['metadata']['name']:{'desired':d['spec'].get('replicas',1),'ready':d.get('status',{}).get('readyReplicas',0)} for d in deployments},'readyz':run(['kubectl','--kubeconfig=/etc/kubernetes/admin.conf','get','--raw=/readyz?verbose']).decode().splitlines(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    targets=json.load(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets',timeout=10))
    health['prometheus_targets']=[{'job':x['labels'].get('job'),'health':x['health']} for x in targets['data']['activeTargets']]
    history=json.load(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/query?query=up%20offset%202h',timeout=10))
    health['prometheus_historical_series_2h']=len(history['data']['result'])
    atomic(out/'cluster-health.json',json.dumps(health,indent=2),0o644)
    sources=[]
    names=run(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
    for name in sorted(set(names)):
        path=pathlib.Path(name)
        if path.is_file() and not name.startswith('docs/') and not name.startswith('deploy/oci-single-node/'):
            sources.append(sha(path.read_bytes())+'  '+name)
    atomic(out/'source-manifest.sha256','\n'.join(sources)+'\n',0o644)
    print('Release metadata and redacted health evidence written.')
if __name__=='__main__':main()
