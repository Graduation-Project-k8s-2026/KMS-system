#!/usr/bin/env python3
"""Deploy a separate Campus Store; never reinitialize or restart KMS.

Requires existing kubeadm/admin.conf, an unsealed KMS, a prepared public HTTPS entrance,
Docker/containerd, openssl and a public Transit CA file. Secret values are passed
through stdin or protected temporary files, never logged or checked into Git.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.parse

ROOT=Path(__file__).resolve().parents[2]
NS='campus-store'
KEY='campus-shipping'
SERVICES=['checkout','shipping','marketing','migration']
PUBLIC_STATE='/var/lib/campus-store-edge/public'
SUDO=[] if os.geteuid()==0 else ['sudo','-n']
KUBE=SUDO+['kubectl','--kubeconfig=/etc/kubernetes/admin.conf']


def run(args, data=None):
    result=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if result.returncode:
        # Avoid dumping a failed kubectl request containing a Secret.
        raise RuntimeError('command failed: '+args[len(SUDO)]+' (output suppressed; inspect command locally)')
    return result.stdout


def kms(method,path,payload=None):
    # curl can use the protected UDS as root without exposing credentials.
    args=SUDO+['curl','--silent','--show-error','--unix-socket','/run/custom-kms/admin/admin.sock','-X',method,'http://localhost'+path,'-H','Content-Type: application/json','-w','\n%{http_code}']
    if payload is not None:args+=['--data-binary','@-']
    data=run(args,json.dumps(payload).encode() if payload is not None else None)
    body,status=data.rsplit(b'\n',1)
    return int(status),json.loads(body)


def resource(kind,name,**kwargs):
    value={'apiVersion':'v1','kind':kind,'metadata':{'name':name,'namespace':NS}}
    value.update(kwargs)
    return value


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--kms-ca',default=str(Path.home()/'kms-lab/transit-ca.crt'))
    parser.add_argument('--runtime',default=str(Path.home()/'kms-lab/campus-store'))
    parser.add_argument('--skip-serve',action='store_true',help='Build and deploy without adding the private /store route')
    parser.add_argument('--access',choices=['public','private'],default='public',help='Public HTTPS by default; private is the legacy Tailscale route')
    parser.add_argument('--plan',action='store_true',help='Offline only: write reviewable placeholder resources; no cluster or KMS access')
    args=parser.parse_args()
    runtime=Path(args.runtime);runtime.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(runtime,0o700)
    if args.access=='private':
        status={'Web':{'private.example:443':{'Handlers':{'/':{'Proxy':'http://127.0.0.1:8201'}}}}} if args.plan else json.loads(run(SUDO+['tailscale','serve','status','--json']))
        entries=[(host,v) for host,v in status.get('Web',{}).items() if host.endswith(':443') and '/' in v.get('Handlers',{})]
        if len(entries)!=1:raise RuntimeError('exactly one existing private HTTPS root route is required')
        host,site=entries[0];origin='https://'+host.removesuffix(':443')
        for path in ['/store','/store/']:
            previous=site.get('Handlers',{}).get(path)
            if previous and previous.get('Proxy')!='http://127.0.0.1:8300':raise RuntimeError('/store is assigned to another service')
        original_root=site['Handlers']['/']
        (runtime/'serve-before.json').write_text(json.dumps(status,indent=2))
    else:
        origin='https://public.example' if args.plan else run(SUDO+['cat',PUBLIC_STATE+'/origin']).decode().strip()
        parsed=urllib.parse.urlsplit(origin)
        if parsed.scheme!='https' or not parsed.hostname or parsed.path or parsed.username:raise RuntimeError('invalid public HTTPS origin')
    nodes=[{'metadata':{'name':'REPLACE_WITH_NODE_NAME'}}] if args.plan else json.loads(run(KUBE+['get','nodes','-o','json']))['items']
    if len(nodes)!=1:raise RuntimeError('this deployment is for the existing single node')
    node=nodes[0]['metadata']['name']
    key_status,key_data=(200,{}) if args.plan else kms('GET','/v1/keys/'+KEY)
    if key_status==404:
        key_status,key_data=kms('POST','/v1/keys',{'name':KEY})
        if key_status not in (200,201):raise RuntimeError('dedicated KMS key creation failed; is KMS unsealed?')
    elif key_status!=200:raise RuntimeError('cannot read dedicated KMS key; existing KMS was not changed')
    print('Offline plan: dedicated KMS key would be reused or created.' if args.plan else 'Dedicated KMS key ready (existing versions preserved).',flush=True)
    source=ROOT/'apps/campus-store'
    digest=hashlib.sha256()
    for p in sorted(source.rglob('*')):
        if p.is_file() and '__pycache__' not in str(p):digest.update(p.relative_to(source).as_posix().encode()+p.read_bytes())
    tag='campus-store:'+digest.hexdigest()[:12]
    if not args.plan:
        print('Building independent app image '+tag,flush=True)
        run(SUDO+['docker','build','-t',tag,str(source)])
        save=subprocess.Popen(SUDO+['docker','save',tag],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        load=subprocess.run(SUDO+['ctr','-n','k8s.io','images','import','-'],stdin=save.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        save.stdout.close()
        if save.wait()!=0 or load.returncode:raise RuntimeError('image import failed')
    # Existing runtime secrets are preserved across redeploys.
    if args.plan:
        secret_data={k:base64.b64encode(b'GENERATED_AT_DEPLOYMENT').decode() for k in ['token','ca.crt','tls.crt','tls.key']}
    else:
        secret_check=run(KUBE+['get','secret','store-internal','-n',NS,'--ignore-not-found=true','-o','json'])
        if secret_check.strip():
            internal=json.loads(secret_check)
            secret_data=internal['data']
        else:
            secret_data=None
    resources=[{'apiVersion':'v1','kind':'Namespace','metadata':{'name':NS}}]
    if args.access=='public':
        password=b'GENERATED_AT_DEPLOYMENT' if args.plan else (runtime/'access-password').read_bytes().strip()
        if not args.plan and len(password)<24:raise RuntimeError('presentation password must have at least 24 bytes')
        resources.append(resource('Secret','store-access',type='Opaque',data={'password':base64.b64encode(password).decode()}))
    if secret_data is None:
        with tempfile.TemporaryDirectory(prefix='campus-pki-') as tmp:
            p=Path(tmp)
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','90','-keyout',str(p/'ca.key'),'-out',str(p/'ca.crt'),'-subj','/CN=Campus Store internal demo CA'])
            run(['openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(p/'tls.key'),'-out',str(p/'tls.csr'),'-subj','/CN=campus-store-workers'])
            sans=','.join('DNS:'+s+'.'+NS+'.svc.cluster.local' for s in SERVICES)
            (p/'extensions').write_text('subjectAltName='+sans+'\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
            run(['openssl','x509','-req','-in',str(p/'tls.csr'),'-CA',str(p/'ca.crt'),'-CAkey',str(p/'ca.key'),'-CAcreateserial','-out',str(p/'tls.crt'),'-days','90','-extfile',str(p/'extensions')])
            secret_data={name:base64.b64encode((p/name).read_bytes()).decode() for name in ['ca.crt','tls.crt','tls.key']}
            secret_data['token']=base64.b64encode(secrets.token_urlsafe(48).encode()).decode()
    resources.append(resource('Secret','store-internal',type='Opaque',data=secret_data))
    resources.append(resource('ConfigMap','kms-ca',data={'ca.crt':'REPLACE_WITH_PUBLIC_KMS_CA' if args.plan else Path(args.kms_ca).read_text()}))
    if not args.plan:run(SUDO+['install','-d','-o','10001','-g','10001','-m','0700','/var/lib/campus-store'])
    resources += [
        {'apiVersion':'v1','kind':'PersistentVolume','metadata':{'name':'campus-store-data'},'spec':{'capacity':{'storage':'1Gi'},'volumeMode':'Filesystem','accessModes':['ReadWriteOnce'],'persistentVolumeReclaimPolicy':'Retain','storageClassName':'','local':{'path':'/var/lib/campus-store'},'nodeAffinity':{'required':{'nodeSelectorTerms':[{'matchExpressions':[{'key':'kubernetes.io/hostname','operator':'In','values':[node]}]}]}}}},
        resource('PersistentVolumeClaim','store-data',spec={'accessModes':['ReadWriteOnce'],'storageClassName':'','volumeName':'campus-store-data','resources':{'requests':{'storage':'1Gi'}}}),
    ]
    for role in ['portal']+SERVICES:
        resources.append(resource('ServiceAccount',role,automountServiceAccountToken=False))
    for service,verb in [('checkout','encrypt'),('shipping','decrypt'),('migration','rewrap')]:
        resources += [
            # C+B 키 소유 모델: campus-shipping은 점 없는 "클러스터 전역 키"라서 네임스페이스 Role은 효력이 없다.
            # ClusterRole + ClusterRoleBinding으로만 허용된다(이름 규칙 kms-cb-<키>-<verbs>, verb별 ClusterRole.
            {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':'kms-cb-'+KEY+'-'+verb},'rules':[{'apiGroups':['kms.local'],'resources':['keys'],'resourceNames':[KEY],'verbs':[verb]}]},
            {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding','metadata':{'name':'kms-cb-'+KEY+'-'+verb},'subjects':[{'kind':'ServiceAccount','name':service,'namespace':NS}],'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'kms-cb-'+KEY+'-'+verb}},
        ]
    for mode in ['portal']+SERVICES:
        portal=mode=='portal'
        env={'STORE_MODE':mode,'STORE_KEY':KEY,'STORE_INTERNAL_TOKEN_FILE':'/internal/token'}
        volumes=[{'name':'internal','secret':{'secretName':'store-internal','defaultMode':0o440,'items':[{'key':'token','path':'token'},{'key':'ca.crt','path':'ca.crt'}]+([] if portal else [{'key':'tls.crt','path':'tls.crt'},{'key':'tls.key','path':'tls.key'}])}},{'name':'tmp','emptyDir':{'sizeLimit':'16Mi'}}]
        mounts=[{'name':'internal','mountPath':'/internal','readOnly':True},{'name':'tmp','mountPath':'/tmp'}]
        if portal:
            env.update(STORE_BIND='127.0.0.1',STORE_PORT='8300',STORE_ORIGIN=origin,STORE_PREFIX='/store',STORE_DEMO_ACCOUNTS='1',STORE_REQUIRE_TAILSCALE='1' if args.access=='private' else '0',STORE_DB='/data/orders.db',STORE_WORKER_CA='/internal/ca.crt')
            if args.access=='public':
                env.update(STORE_ORIGIN_FILE='/public-origin/origin',STORE_ACCESS_PASSWORD_FILE='/access/password')
                volumes += [{'name':'public-origin','hostPath':{'path':PUBLIC_STATE,'type':'Directory'}},{'name':'access','secret':{'secretName':'store-access','defaultMode':0o440}}]
                mounts += [{'name':'public-origin','mountPath':'/public-origin','readOnly':True},{'name':'access','mountPath':'/access','readOnly':True}]
            for service in SERVICES:env['STORE_'+service.upper()+'_URL']='https://'+service+'.'+NS+'.svc.cluster.local:8443'
            volumes.append({'name':'data','persistentVolumeClaim':{'claimName':'store-data'}})
            mounts.append({'name':'data','mountPath':'/data'})
            probe={'exec':{'command':['python3','-c',"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8300/healthz', timeout=2).read()"]}}
        else:
            env.update(STORE_TLS_CERT='/internal/tls.crt',STORE_TLS_KEY='/internal/tls.key',KMS_TRANSIT_URL='https://kms-transit.kube-system.svc.cluster.local:8200',KMS_CA_FILE='/kms-ca/ca.crt',KMS_TOKEN_FILE='/kms-token/token')
            volumes += [{'name':'kms-ca','configMap':{'name':'kms-ca'}},{'name':'kms-token','projected':{'defaultMode':0o440,'sources':[{'serviceAccountToken':{'path':'token','expirationSeconds':3600,'audience':'kms-system'}}]}}]
            mounts += [{'name':'kms-ca','mountPath':'/kms-ca','readOnly':True},{'name':'kms-token','mountPath':'/kms-token','readOnly':True}]
            probe={'httpGet':{'path':'/healthz','port':8443,'scheme':'HTTPS'}}
            resources.append(resource('Service',mode,spec={'selector':{'app':'campus-'+mode},'ports':[{'name':'https','port':8443,'targetPort':8443}]}))
        probe.update(initialDelaySeconds=3,periodSeconds=10,timeoutSeconds=3)
        container={'name':'app','image':tag,'imagePullPolicy':'Never','env':[{'name':k,'value':v} for k,v in env.items()], 'volumeMounts':mounts,
                   'resources':{'requests':{'cpu':'20m','memory':'32Mi'},'limits':{'cpu':'500m','memory':'160Mi'}},
                   'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'readinessProbe':probe,'livenessProbe':dict(probe,failureThreshold=6)}
        spec={'serviceAccountName':mode,'automountServiceAccountToken':False,'nodeSelector':{'kubernetes.io/hostname':node},'tolerations':[{'key':'node-role.kubernetes.io/control-plane','operator':'Exists','effect':'NoSchedule'}],
              'dnsConfig':{'options':[{'name':'ndots','value':'1'}]},
              'securityContext':{'runAsUser':10001,'runAsGroup':10001,'runAsNonRoot':True,'fsGroup':10001,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[container],'volumes':volumes}
        if portal:spec.update(hostNetwork=True,dnsPolicy='ClusterFirstWithHostNet')
        resources.append({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':mode,'namespace':NS},'spec':{'replicas':1,'strategy':{'type':'Recreate'},'selector':{'matchLabels':{'app':'campus-'+mode}},'template':{'metadata':{'labels':{'app':'campus-'+mode}},'spec':spec}}})
    if args.plan:
        destination=ROOT/'deploy/campus-store/resources.example.json'
        destination.write_text(json.dumps({'apiVersion':'v1','kind':'List','items':resources},ensure_ascii=False,indent=2)+'\n')
        print('Offline review plan written; no KMS or cluster changes.',flush=True)
        return
    print('Applying separate namespace, storage, roles and five app deployments.',flush=True)
    run(KUBE+['apply','-f','-'],json.dumps({'apiVersion':'v1','kind':'List','items':resources}).encode())
    for mode in SERVICES+['portal']:
        run(KUBE+['rollout','status','deployment/'+mode,'-n',NS,'--timeout=180s'])
        print(mode+' ready',flush=True)
    if args.access=='private' and not args.skip_serve:
        run(SUDO+['tailscale','serve','--bg','--yes','--set-path=/store','http://127.0.0.1:8300'])
        after=json.loads(run(SUDO+['tailscale','serve','status','--json']))
        if after['Web'][host]['Handlers']['/']!=original_root:
            raise RuntimeError('existing root route changed unexpectedly')
    result={'namespace':NS,'image':tag,'key':KEY,'path':'/store/','origin':origin,'access':args.access,'origin_file':PUBLIC_STATE+'/origin' if args.access=='public' else None,'deployed_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'existing_admin_route_preserved':True}
    (runtime/'deployment.json').write_text(json.dumps(result,indent=2));os.chmod(runtime/'deployment.json',0o600)
    print('Campus Store ready at the configured '+args.access+' HTTPS origin + /store/.',flush=True)
    print('Private connection details saved under runtime/deployment.json; no credentials printed.',flush=True)


if __name__=='__main__':main()
