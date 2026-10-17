import contextlib,base64,importlib.util,io,json,pathlib,re,subprocess,tempfile,unittest
from unittest.mock import patch, MagicMock
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name):
 s=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=module('create-bench-fixture')
migrate=module('migrate-rbac-cb');renderer=module('render-release');etcd=module('verify-etcd-encryption');rewrite=module('rewrite-secrets')
class Contracts(unittest.TestCase):
 def values(self):
  v={k:'fixture' for k in renderer.REQUIRED}
  v.update(NODE_NAME='test-node',NODE_IP='10.0.0.2',GUI_FQDN='kms.example.test',DEMO_FQDN='demo.example.test',SA_ISSUER='https://kubernetes.default.svc.cluster.local',SOURCE_SHA='b'*40,SERVER_VERSION='v1.35.9',TPM_GROUP_GID='995')
  for k in v:
   if k.endswith('_IMAGE'):v[k]='example/image@sha256:'+'a'*64
  return v
 def test_render_all_and_privilege_boundaries(self):
  docs=[]
  for f in (ROOT/'deploy/oci-single-node/templates').glob('*.yaml'):
   text=renderer.render(f.read_text(),self.values());docs+=list(renderer.yaml.load_all(text,Loader=renderer.UniqueLoader))
  static=next(x for x in docs if x.get('kind')=='Pod')
  self.assertTrue(all('hostPath' in v for v in static['spec']['volumes']))
  self.assertFalse(static['spec']['automountServiceAccountToken'])
  env={x['name']:x['value'] for x in static['spec']['containers'][0]['env']}
  self.assertEqual(env['KMS_SA_ISSUER'],self.values()['SA_ISSUER'])
  self.assertEqual(env['KMS_AUTHN'],'on');self.assertEqual(env['KMS_AUTHZ'],'on')
  self.assertEqual(env['KMS_AUTO_UNSEAL'],'false');self.assertEqual(env['KMS_AUTHZ_FAIL_OPEN'],'false')
  self.assertTrue(env['KMS_TRANSIT_TLS_CERT']);self.assertTrue(env['KMS_TRANSIT_TLS_KEY'])
  self.assertEqual(env['KMS_SEAL_ALLOWED'],'shamir,tpm');self.assertNotIn('KMS_SEAL_TYPE',env)
  self.assertEqual(env['KMS_TRANSIT_AUDIT_DIR'],'/transit-audit')
  self.assertEqual(env['KMS_TPM_DEVICE'],'/dev/tpmrm0');self.assertNotIn('KMS_TPM_PCRS',env)
  self.assertEqual(static['spec']['securityContext']['supplementalGroups'],[995])
  tpm=next(v for v in static['spec']['volumes'] if v['name']=='tpm')
  self.assertEqual(tpm['hostPath'],{'path':'/dev/tpmrm0'})
  self.assertIn({'name':'tpm','mountPath':'/dev/tpmrm0'},static['spec']['containers'][0]['volumeMounts'])
  services=[x for x in docs if x.get('kind')=='Service' and x['spec'].get('type')=='NodePort']
  self.assertEqual([x['metadata']['name'] for x in services],['kms-demo-app'])
  self.assertEqual(services[0]['spec']['ports'][0]['nodePort'],30443)
  self.assertEqual(len([x for x in docs if x.get('kind')=='PersistentVolumeClaim']),2)
  for doc in docs:
   for rule in doc.get('rules',[]):
    for field in ['verbs','resources','apiGroups']:self.assertNotIn('*',rule.get(field,[]))
 def test_render_cli_rejects_non_numeric_tpm_gid(self):
  with tempfile.TemporaryDirectory() as d:
   for gid,code in (('995',0),('tss',2),('0',2),('995;x',2)):
    vals=self.values();vals['TPM_GROUP_GID']=gid
    f=pathlib.Path(d)/'v.json';f.write_text(json.dumps(vals));out=pathlib.Path(d)/('out-'+str(abs(hash(gid))))
    r=subprocess.run(['python3',str(ROOT/'scripts/render-release.py'),'--values',str(f),'--templates',str(ROOT/'deploy/oci-single-node/templates'),'--output',str(out)],capture_output=True)
    self.assertEqual(r.returncode,code,(gid,r.stderr))
 def test_render_rejects_duplicate_unresolved_and_unpinned(self):
  for raw in ['kind: Pod\nkind: Job\n','image: latest\n','image: ${MISSING}\n','image: IMAGE_TAG\n','spec: {containers: [{name: app}]}','spec: {initContainers: [{name: init}]}','spec: {containers: []}','kind: Pod\nspec: {}']:
   with self.assertRaises(ValueError):renderer.render(raw,self.values())
 def test_etcd_all_records_and_no_plaintext(self):
  enc=lambda b:base64.b64encode(b).decode()
  doc={'kvs':[{'key':enc(b'/registry/secrets/test/example'),'value':enc(etcd.PREFIX+b'fixture')}]}
  self.assertEqual(etcd.verify(doc,1),1)
  for bad in [{**doc,'count':2},{'kvs':doc['kvs']*2},{'kvs':[]},{**doc,'more':True},{'kvs':[{'key':enc(b'/registry/secrets/test/example'),'value':enc(b'identity-data')}]}]:
   with self.assertRaises(ValueError):etcd.verify(bad)
  with self.assertRaises(ValueError):etcd.verify(doc,2)
 def test_rewrite_pagination_conflict_resume(self):
  pages=[{'items':[1],'metadata':{'continue':'next'}},{'items':[2],'metadata':{}}]
  with patch.object(rewrite,'kubectl',side_effect=pages) as k:
   self.assertEqual(list(rewrite.items('/api/v1/secrets')),[1,2]);self.assertIn('continue=next',k.call_args_list[1].args[0][-1])
  secret={'metadata':{'name':'example','namespace':'test','resourceVersion':'1'},'data':{'x':'Zml4dHVyZQ=='}}
  new={'metadata':{'name':'example','namespace':'test','resourceVersion':'2'},'data':secret['data']}
  with patch.object(rewrite,'kubectl',side_effect=[rewrite.Failure('conflict'),new,{'metadata':{'resourceVersion':'3'}}]) as k:
   rewrite.replace(secret,'backup-fixture');self.assertEqual(k.call_args.args[1]['metadata']['resourceVersion'],'2')
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)/'resume.json';rewrite.checkpoint(p,{'test/example'});self.assertEqual(json.loads(p.read_text()),['test/example']);self.assertNotIn('data',p.read_text())
 def test_fixture_waits_for_authenticated_submission(self):
  rid='a'*32
  running={'run_id':rid,'state':'running'}
  done={**running,'state':'succeeded','upload':'stored','submitter_pod_uid':'fixture-pod','job_uid':'fixture-job','service_account':'bench-transit'}
  result={'run_id':rid,'mode':'transit','errors':0,'success':10,'requests':10}
  def opener(docs):
   o=MagicMock();o.open.side_effect=[io.BytesIO(json.dumps(d).encode()) for d in docs];return o
  o=opener([{'csrf_token':'public-test-csrf'},running,running,done,result])
  self.assertEqual(fixture.fixture(o,'https://fixture.example','transit',sleep=lambda _:None),rid)
  self.assertEqual(o.open.call_args_list[1].args[0].get_method(),'POST')
  self.assertEqual(o.open.call_count,5)
  for invalid in [{**done,'submitter_pod_uid':''},{**done,'service_account':'bench-e2e'},{**done,'upload':'pending'},{**done,'state':'failed'}]:
   with self.assertRaises(ValueError):fixture.fixture(opener([{'csrf_token':'fixture'},running,invalid]),'https://fixture.example','transit')
  with self.assertRaises(TimeoutError):fixture.fixture(opener([{'csrf_token':'fixture'},running,running]),'https://fixture.example','transit',clock=iter([0,1000]).__next__)
  with self.assertRaises(ValueError):fixture.fixture(opener([{'csrf_token':'fixture'},running,done,{**result,'run_id':'b'*32}]),'https://fixture.example','transit')
 def test_versions_and_final_target_contract(self):
  mod=(ROOT/'go.mod').read_text();go=re.search(r'^go ([0-9.]+)$',mod,re.M).group(1)
  locks=json.loads((ROOT/'docs/release/base-image-lock.json').read_text())
  ci=renderer.yaml.safe_load((ROOT/'.github/workflows/ci.yml').read_text())
  setup=next(s for s in ci['jobs']['build-and-test']['steps'] if s.get('uses','').startswith('actions/setup-go@'))
  self.assertEqual(setup['with']['go-version'],go);self.assertTrue(locks['go']['tag'].startswith(go+'-'))
  versions=re.findall(r'^\s*k8s.io/(?:api|apimachinery|client-go|kms) (v[0-9.]+)$',mod,re.M)
  self.assertEqual(len(versions),4);self.assertEqual(len(set(versions)),1)
  docker=(ROOT/'deploy/oci-single-node/Dockerfile').read_text()
  for name in ['go','runtime']:
   self.assertIn(locks[name]['image'],docker)
  for name in ['server','admin-api','bench','demo-app']:
   self.assertRegex(docker,'FROM runtime AS '+name+r'\nCOPY --from=verify /verified /verified\nCOPY --from=build /out/'+name+' /usr/local/bin/'+name)
  for command in ['go vet ./...','go test -race ./...','CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./...']:
   self.assertIn(command,docker)
 def test_script_help_and_error_exit_without_backend(self):
  for name in ['verify-release-contract.sh','test-kmsv2.sh']:
   r=subprocess.run(['bash',str(ROOT/'scripts'/name),'--help'],capture_output=True,text=True)
   self.assertEqual(r.returncode,0);self.assertIn('Exit:',r.stdout)
   self.assertEqual(subprocess.run(['bash',str(ROOT/'scripts'/name),'--unknown'],capture_output=True).returncode,2)
  for name in ['render-release.py','rewrite-secrets.py','verify-etcd-encryption.py','create-bench-fixture.py']:
   self.assertEqual(subprocess.run(['python3',str(ROOT/'scripts'/name),'--help'],capture_output=True).returncode,0)
 def test_rewrite_dry_run_and_resume_after_failure(self):
  with tempfile.TemporaryDirectory() as tmp:
   checkpoint=pathlib.Path(tmp)/'resume.json'
   namespace=lambda n:{'metadata':{'name':n}}
   secret=lambda ns:{'metadata':{'name':'sample','namespace':ns,'resourceVersion':'1'},'data':{'private':'sensitive-fixture'}}
   pages=[[namespace('ns-a'),namespace('ns-b')],[secret('ns-a')],[secret('ns-b')]]
   args=['rewrite-secrets.py','--resume',str(checkpoint)]
   output=io.StringIO()
   with patch.object(rewrite.sys,'argv',args),patch.object(rewrite,'items',side_effect=pages) as listing,patch.object(rewrite,'replace') as replace,contextlib.redirect_stdout(output):
    rewrite.main();replace.assert_not_called()
    self.assertEqual([c.args[0] for c in listing.call_args_list],['/api/v1/namespaces','/api/v1/namespaces/ns-a/secrets','/api/v1/namespaces/ns-b/secrets'])
   self.assertFalse(checkpoint.exists());self.assertNotIn('sensitive-fixture',output.getvalue())
   args+=['--execute','--backup-id','fixture-backup']
   with patch.object(rewrite.sys,'argv',args),patch.object(rewrite,'items',side_effect=pages),patch.object(rewrite,'replace',side_effect=[{},rewrite.Failure('backend')]):
    with self.assertRaises(rewrite.Failure):rewrite.main()
   self.assertEqual(json.loads(checkpoint.read_text()),['ns-a/sample'])
   with patch.object(rewrite.sys,'argv',args),patch.object(rewrite,'items',side_effect=pages),patch.object(rewrite,'replace') as replace,contextlib.redirect_stdout(output):
    rewrite.main();replace.assert_called_once();self.assertEqual(replace.call_args.args[0]['metadata']['namespace'],'ns-b')
   self.assertEqual(json.loads(checkpoint.read_text()),['ns-a/sample','ns-b/sample'])
   self.assertNotIn('sensitive-fixture',checkpoint.read_text()+output.getvalue())

def _rb(kind,ns,name,role_kind,role,subjects):
 md={'name':name};
 if ns:md['namespace']=ns
 return {'kind':kind,'metadata':md,'roleRef':{'kind':role_kind,'name':role},'subjects':subjects}
def _role(kind,ns,name,rules):
 md={'name':name}
 if ns:md['namespace']=ns
 return {'kind':kind,'metadata':md,'rules':rules}
def _rule(names,verbs):
 r={'apiGroups':['kms.local'],'resources':['keys'],'verbs':verbs}
 if names:r['resourceNames']=names
 return r
SA=lambda ns,n:{'kind':'ServiceAccount','name':n,'namespace':ns}
class MigrateRbac(unittest.TestCase):
 def items(self):
  return [
   _role('Role','shop','pay',[_rule(['Payment_Key'],['encrypt','decrypt'])]),
   _rb('RoleBinding','shop','pay','Role','pay',[SA('shop','api'),SA('batch','worker')]),
   _role('Role','shop','pay2',[_rule(['Payment_Key'],['rewrap'])]),
   _rb('RoleBinding','shop','pay2','Role','pay2',[SA('shop','api')]),
   _role('Role','team-a','own',[_rule(['team-a.ledger'],['encrypt'])]),
   _rb('RoleBinding','team-a','own','Role','own',[SA('team-a','app')]),
   _role('Role','wide','all',[_rule([],['encrypt'])]),
   _rb('RoleBinding','wide','all','Role','all',[SA('wide','app')]),
   _role('ClusterRole',None,'done',[_rule(['already'],['encrypt'])]),
   _rb('ClusterRoleBinding',None,'done','ClusterRole','done',[SA('shop','c')]),
   _role('Role','shop','c',[_rule(['already'],['encrypt'])]),
   _rb('RoleBinding','shop','c','Role','c',[SA('shop','c')]),
   _role('Role','shop','other',[{'apiGroups':[''],'resources':['secrets'],'verbs':['get']}]),
   _rb('RoleBinding','shop','other','Role','other',[SA('shop','x')]),
  ]
 def test_check_reports_lost_kept_warnings(self):
  grants,warnings,cg=migrate.analyze(self.items())
  table=migrate.render_table(grants,warnings,cg)
  self.assertIn('사라짐',table);self.assertIn('유지',table);self.assertIn('이전됨',table)
  self.assertTrue(any('resourceNames 없음' in w for w in warnings))
  status={g['key']:migrate.classify(g)[0] for g in grants}
  self.assertEqual(status['team-a.ledger'],'kept');self.assertEqual(status['Payment_Key'],'lost')
  self.assertNotIn('secrets',table)
 def test_generate_makes_equivalent_clusterroles_and_skips_covered(self):
  grants,_,cg=migrate.analyze(self.items())
  docs,skipped=migrate.build_manifests(grants,cg)
  roles={d['metadata']['name']:d for d in docs if d['kind']=='ClusterRole'}
  binds={d['metadata']['name']:d for d in docs if d['kind']=='ClusterRoleBinding'}
  self.assertEqual(set(roles),set(binds));self.assertEqual(len(roles),2)  # decrypt+encrypt / rewrap 두 묶음
  for name,role in roles.items():
   self.assertEqual(role['rules'][0]['resourceNames'],['Payment_Key']);self.assertEqual(role['rules'][0]['apiGroups'],['kms.local'])
   self.assertRegex(name,r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$');self.assertTrue(name.startswith('kms-cb-payment-key-'))
   self.assertEqual(binds[name]['roleRef'],{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':name})
  by_verbs={tuple(r['rules'][0]['verbs']):n for n,r in roles.items()}
  self.assertEqual({(s['namespace'],s['name']) for s in binds[by_verbs[('decrypt','encrypt')]]['subjects']},{('shop','api'),('batch','worker')})
  self.assertEqual([s['name'] for s in binds[by_verbs[('rewrap',)]]['subjects']],['api'])
  self.assertEqual(len(skipped),1)  # 'already' 는 이미 ClusterRoleBinding 으로 있음
  self.assertNotIn('team-a.ledger',json.dumps(docs))
 def test_cli_generate_writes_file_without_overwrite_and_leaves_roles(self):
  with tempfile.TemporaryDirectory() as d:
   inp=pathlib.Path(d)/'in.json';inp.write_text(json.dumps({'kind':'List','items':self.items()}))
   out=pathlib.Path(d)/'cb.yaml'
   with contextlib.redirect_stdout(io.StringIO()):
    self.assertEqual(migrate.main(['generate','--input',str(inp),'--output',str(out)]),0)
    docs=list(renderer.yaml.safe_load_all(out.read_text()))
    self.assertTrue(all(x['kind'] in ('ClusterRole','ClusterRoleBinding') for x in docs if x))
    self.assertEqual(migrate.main(['generate','--input',str(inp),'--output',str(out)]),2)  # 덮어쓰기 거부
    self.assertEqual(migrate.main(['check','--input',str(inp)]),0)
 def test_repo_templates_use_cluster_scope_for_global_keys(self):
  docs=[]
  for f in (ROOT/'deploy/oci-single-node/templates').glob('serviceaccounts-rbac.yaml'):
   docs+=list(renderer.yaml.load_all(renderer.render(f.read_text(),Contracts.values(Contracts())),Loader=renderer.UniqueLoader))
  kms=[x for x in docs if x and x.get('kind') in ('Role','ClusterRole') and any('kms.local' in r.get('apiGroups',[]) for r in x.get('rules',[]))]
  self.assertTrue(kms);self.assertTrue(all(x['kind']=='ClusterRole' for x in kms))
  bind=next(x for x in docs if x and x.get('kind')=='ClusterRoleBinding' and x['metadata']['name']==kms[0]['metadata']['name'])
  self.assertEqual({(s['namespace'],s['name']) for s in bind['subjects']},{('kms-demo','app-a'),('kms-bench','bench-transit')})

if __name__=='__main__':unittest.main()
