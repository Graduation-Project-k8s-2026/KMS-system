import contextlib,base64,importlib.util,io,json,pathlib,re,subprocess,tempfile,unittest
from unittest.mock import patch, MagicMock
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name):
 s=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=module('create-bench-fixture')
renderer=module('render-release');etcd=module('verify-etcd-encryption');rewrite=module('rewrite-secrets')
class Contracts(unittest.TestCase):
 def values(self):
  v={k:'fixture' for k in renderer.REQUIRED}
  v.update(NODE_NAME='test-node',NODE_IP='10.0.0.2',GUI_FQDN='kms.example.test',DEMO_FQDN='demo.example.test',SA_ISSUER='https://kubernetes.default.svc.cluster.local',SOURCE_SHA='b'*40,SERVER_VERSION='v1.35.9')
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
  services=[x for x in docs if x.get('kind')=='Service' and x['spec'].get('type')=='NodePort']
  self.assertEqual([x['metadata']['name'] for x in services],['kms-demo-app'])
  self.assertEqual(services[0]['spec']['ports'][0]['nodePort'],30443)
  self.assertEqual(len([x for x in docs if x.get('kind')=='PersistentVolumeClaim']),2)
  for doc in docs:
   for rule in doc.get('rules',[]):
    for field in ['verbs','resources','apiGroups']:self.assertNotIn('*',rule.get(field,[]))
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
if __name__=='__main__':unittest.main()
