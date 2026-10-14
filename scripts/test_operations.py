import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import kms_ops

def module(name):
    spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

patcher=module('patch-apiserver-kms');backup=module('backup-kms')

class Operations(unittest.TestCase):
    def test_reboot_audit_allows_append_but_rejects_loss_and_mutation(self):
        reboot=module('verify-reboot')
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);file=root/'audit.jsonl';file.write_bytes(b'old entry\n')
            snapshot=reboot.audit_snapshot(root)
            file.write_bytes(b'old entry\nnew entry\n');reboot.verify_audit(root,snapshot)
            for changed in (b'old',b'bad entry\nnew entry\n'):
                file.write_bytes(changed)
                with self.assertRaises(ValueError):reboot.verify_audit(root,snapshot)
            file.unlink()
            with self.assertRaises(FileNotFoundError):reboot.verify_audit(root,snapshot)
    def test_reboot_audit_rejects_escaping_path(self):
        reboot=module('verify-reboot')
        for name in ('../outside','/outside'):
            with self.assertRaises(ValueError):
                reboot.verify_audit(pathlib.Path('/unused'),{name:{'bytes':0,'sha256':kms_ops.sha(b'')}})
    def pod(self):
        return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'kube-apiserver'},'spec':{'containers':[{'name':'kube-apiserver','image':'fixture','command':['kube-apiserver','--etcd-servers=https://fixture:2379'],'volumeMounts':[{'name':'pki','mountPath':'/etc/kubernetes/pki','readOnly':True}]}],'volumes':[{'name':'pki','hostPath':{'path':'/etc/kubernetes/pki'}}]}}
    def test_preserves_source_and_idempotent(self):
        source=self.pod();before=copy.deepcopy(source);result=patcher.patch(source)
        self.assertEqual(source,before);self.assertEqual(patcher.patch(result),result)
        self.assertEqual(result['spec']['containers'][0]['command'][1],before['spec']['containers'][0]['command'][1])
        self.assertEqual(result['spec']['volumes'][0],before['spec']['volumes'][0])
    def test_rejects_conflicts_and_duplicate_keys(self):
        with self.assertRaises(ValueError):kms_ops.load('a: 1\na: 2')
        for flag in ['--encryption-provider-config=/other','--encryption-provider-config']:
            p=self.pod();p['spec']['containers'][0]['command'].append(flag)
            with self.assertRaises(ValueError):patcher.patch(p)
        p=self.pod();p['spec']['containers']*=2
        with self.assertRaises(ValueError):patcher.patch(p)
        p=self.pod();p['spec']['volumes'].append({'name':'kms-v2-socket','hostPath':{'path':'/wrong'}})
        with self.assertRaises(ValueError):patcher.patch(p)
        p=self.pod();p['spec']['containers'][0]['volumeMounts'].append({'name':'other','mountPath':patcher.CONFIG})
        with self.assertRaises(ValueError):patcher.patch(p)
    def test_provider_rejects_unreviewed_migration(self):
        config={'apiVersion':'apiserver.config.k8s.io/v1','kind':'EncryptionConfiguration','resources':[{'resources':['secrets'],'providers':[{'kms':{'apiVersion':'v2','name':'custom-kms','endpoint':'unix://'+patcher.SOCKET_DIR+'/kms-v2.sock','timeout':'3s'}},{'identity':{}}]}]}
        patcher.validate_config(config)
        config['resources'][0]['providers'].reverse()
        with self.assertRaises(ValueError):patcher.validate_config(config)
    def test_atomic_failure_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/'config';p.write_bytes(b'old')
            with patch.object(kms_ops.os,'replace',side_effect=OSError('fault')):
                with self.assertRaises(OSError):kms_ops.atomic(p,b'new')
            self.assertEqual(p.read_bytes(),b'old');self.assertEqual(len(list(pathlib.Path(td).iterdir())),1)
    def test_wait_requires_observed_termination(self):
        with patch.object(kms_ops,'containers',return_value=[{'id':'still-running'}]),patch.object(kms_ops.time,'monotonic',side_effect=[0,200]):
            with self.assertRaises(RuntimeError):kms_ops.wait_stopped(['kms'],150)
    def test_resume_preserves_conflicting_live_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);live=root/'live';live.mkdir();d=root/'backup';(d/'held').mkdir(parents=True)
            (d/'held/kube-apiserver.yaml').write_text('original');(live/'kube-apiserver.yaml').write_text('changed')
            with patch.object(backup,'ROOT',live):
                with self.assertRaises(RuntimeError):backup.restore_manifest(d,'kube-apiserver.yaml')
            self.assertEqual((live/'kube-apiserver.yaml').read_text(),'changed')
            self.assertTrue((d/'held/kube-apiserver.yaml').exists())
    def test_failed_unseal_cannot_restore_apiserver(self):
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td);(d/'state.json').write_text(json.dumps({'complete':True,'replicas':{}}))
            with patch.object(backup,'restore_manifest') as restore,patch.object(backup,'admin',return_value={'sealed':True}),patch.object(backup.time,'monotonic',side_effect=[0,999]):
                with self.assertRaises(RuntimeError):backup.resume(d)
                restore.assert_called_once_with(d,'kms-static-pod.yaml')

class RecoveryAndMigration(unittest.TestCase):
    def test_restore_rejects_archive_escape_and_symlink(self):
        import tarfile,io
        restore=module('restore-kms')
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            for name,kind in [('../escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE)]:
                archive=root/'bad.tar'
                with tarfile.open(archive,'w') as t:
                    member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc';t.addfile(member,io.BytesIO(b''))
                with self.assertRaises(ValueError):restore.extract(archive,root/'out')
            self.assertFalse((root.parent/'escape').exists())
    def test_incomplete_or_corrupted_backup_refused(self):
        restore=module('restore-kms')
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td);(d/'state.json').write_text('{"complete": false}')
            with self.assertRaises(ValueError):restore.verify_backup(d)
            (d/'state.json').write_text('{"complete": true}');(d/'checksums.json').write_text('{"data":"bad"}');(d/'data').write_text('contents')
            with self.assertRaises(ValueError):restore.verify_backup(d)
    def test_migration_requires_complete_matching_sets(self):
        import base64
        migration=module('migrate-secrets')
        secret={'metadata':{'namespace':'fixture','name':'one'}}
        raw={'header':{'revision':10},'count':1,'kvs':[{'key':base64.b64encode(b'/registry/secrets/fixture/other').decode(),'value':base64.b64encode(migration.verifier.PREFIX+b'x').decode()}]}
        with patch.object(migration,'kube',return_value={'items':[secret]}),patch.object(migration,'run',return_value=json.dumps(raw).encode()),patch.object(migration.time,'sleep'):
            with self.assertRaises(RuntimeError):migration.inspect_current()
    def test_failed_job_preserved_as_failure(self):
        benchmark=module('benchmark-release');client=MagicMock();client.request.side_effect=[{'run_id':'fixture'},{'run_id':'fixture','state':'failed','job_uid':'job'}]
        result=benchmark.execute(client,'e2e',{'count':100})
        self.assertEqual(result['state'],'failed');self.assertIsNone(result['result'])

class SecretRewrite(unittest.TestCase):
    def test_raw_list_item_gets_required_type_metadata(self):
        rewrite=module('rewrite-secrets')
        secret={'metadata':{'name':'proof','namespace':'fixture','resourceVersion':'12'},'data':{'sample':'cHVibGlj'}}
        with patch.object(rewrite,'kubectl',return_value={}) as call:
            rewrite.replace(secret,'backup')
            body=call.call_args.args[1]
            self.assertEqual(body['apiVersion'],'v1');self.assertEqual(body['kind'],'Secret')
            self.assertEqual(body['metadata']['resourceVersion'],'12')

if __name__=='__main__':unittest.main()
