import hashlib, importlib.util, io, pathlib, tempfile, unittest, contextlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_kms_manifest", ROOT / "scripts" / "patch-kms-manifest.py")
pm = importlib.util.module_from_spec(spec); spec.loader.exec_module(pm)

DIGEST_OLD = "docker.io/library/kms-server@sha256:" + "a" * 64
DIGEST_NEW = "docker.io/library/kms-server@sha256:" + "b" * 64

# 운영 파일 모양: flow 스타일 env, 템플릿에 없는 tmp emptyDir와 resources
FLOW = """apiVersion: v1
kind: Pod
metadata: {name: kms-core, namespace: kube-system}
spec:
  hostNetwork: true
  containers:
  - name: kms
    image: %s
    env:
    - {name: KMS_STORAGE, value: file}
    - {name: KMS_SEAL_TYPE, value: shamir}
    - {name: KMS_SHAMIR_PARTS, value: '5'}
    - {name: KMS_SA_AUDIENCE, value: kms-system}
    resources:
      requests: {cpu: 250m, memory: 256Mi}
      limits: {memory: 1Gi}
    volumeMounts:
    - {name: keys, mountPath: /data}
    - {name: tmp, mountPath: /tmp}
  volumes:
  - {name: keys, hostPath: {path: /var/lib/custom-kms/keys, type: Directory}}
  - {name: tmp, emptyDir: {sizeLimit: 16Mi}}
  automountServiceAccountToken: false
""" % DIGEST_OLD

BLOCK = """apiVersion: v1
kind: Pod
metadata:
  name: kms-core
spec:
  containers:
  - name: kms
    image: %s
    env:
    - name: KMS_STORAGE
      value: file
    - name: KMS_SEAL_TYPE
      value: shamir
    volumeMounts:
    - name: keys
      mountPath: /data
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: keys
    hostPath:
      path: /var/lib/custom-kms/keys
      type: Directory
  - name: tmp
    emptyDir: {}
""" % DIGEST_OLD


def env(doc):
    return {e["name"]: e["value"] for e in doc["spec"]["containers"][0]["env"]}


class PatchManifest(unittest.TestCase):
    def check_result(self, text, external=True):
        doc = yaml.safe_load(text)
        e = env(doc)
        self.assertNotIn("KMS_SEAL_TYPE", e)
        self.assertEqual(e["KMS_SEAL_ALLOWED"], "shamir")
        self.assertEqual(e["KMS_TRANSIT_AUDIT_DIR"], "/transit-audit")
        if external:
            self.assertEqual(e["KMS_EXTERNAL_ADDR"], "0.0.0.0:9443")
            self.assertEqual(e["KMS_EXTERNAL_RPS"], "20")  # 숫자도 문자열 (env 값은 문자열이어야 한다)
            self.assertEqual(e["KMS_EXTERNAL_KEY_NAMESPACES"], "kms-external")
        else:
            self.assertNotIn("KMS_EXTERNAL_ADDR", e)
        c = doc["spec"]["containers"][0]
        self.assertIn("transit-audit", [m["name"] for m in c["volumeMounts"]])
        self.assertIn({"name": "tmp", "mountPath": "/tmp"}, c["volumeMounts"])
        vols = {v["name"]: v for v in doc["spec"]["volumes"]}
        self.assertEqual(vols["transit-audit"]["hostPath"], {"path": "/var/lib/custom-kms/transit-audit", "type": "Directory"})
        self.assertIn("tmp", vols)
        return doc

    def test_flow_style_patch_preserves_everything_else(self):
        new, notes = pm.patch(FLOW, DIGEST_NEW)
        doc = self.check_result(new)
        self.assertEqual(doc["spec"]["containers"][0]["image"], DIGEST_NEW)
        old = yaml.safe_load(FLOW)
        self.assertEqual(doc["spec"]["containers"][0]["resources"], old["spec"]["containers"][0]["resources"])
        self.assertEqual(env(doc)["KMS_SHAMIR_PARTS"], "5")
        self.assertIn("    - {name: KMS_SEAL_ALLOWED, value: shamir}", new.splitlines())  # 서식(flow) 유지
        # 바뀐 줄만: 원본 줄 중 사라진 것은 image와 KMS_SEAL_TYPE뿐
        removed = [l for l in FLOW.splitlines() if l not in new.splitlines()]
        self.assertEqual(sorted(l.strip() for l in removed), sorted(["image: " + DIGEST_OLD, "- {name: KMS_SEAL_TYPE, value: shamir}"]))

    def test_block_style(self):
        new, _ = pm.patch(BLOCK, None)
        doc = self.check_result(new)
        self.assertEqual(doc["spec"]["containers"][0]["image"], DIGEST_OLD)  # --image 없으면 그대로

    def test_idempotent(self):
        once, _ = pm.patch(FLOW, DIGEST_NEW)
        twice, notes = pm.patch(once, DIGEST_NEW)
        self.assertEqual(once, twice)
        self.assertTrue(any("이미지" in n for n in notes))
        b1, _ = pm.patch(BLOCK)
        b2, _ = pm.patch(b1)
        self.assertEqual(b1, b2)

    def test_no_external_and_existing_value_kept(self):
        new, _ = pm.patch(FLOW, None, external=False)
        self.check_result(new, external=False)
        pre = FLOW.replace("    - {name: KMS_STORAGE, value: file}", "    - {name: KMS_STORAGE, value: file}\n    - {name: KMS_EXTERNAL_RPS, value: '5'}")
        out, notes = pm.patch(pre)
        self.assertEqual(env(yaml.safe_load(out))["KMS_EXTERNAL_RPS"], "5")  # 이미 있으면 덮어쓰지 않는다
        self.assertTrue(any("KMS_EXTERNAL_RPS" in n for n in notes))

    def test_already_has_seal_allowed_removes_seal_type_only(self):
        pre = FLOW.replace("{name: KMS_SEAL_TYPE, value: shamir}", "{name: KMS_SEAL_ALLOWED, value: shamir}")
        out, _ = pm.patch(pre)
        self.assertEqual(out.count("KMS_SEAL_ALLOWED"), 1)

    def test_rejects_bad_image_and_bad_shape(self):
        with self.assertRaises(pm.PatchError):
            pm.patch(FLOW, "kms-server:latest")
        with self.assertRaises(pm.PatchError):
            pm.patch("kind: Pod\nspec: {}\n")

    def test_cli_leaves_input_untouched_and_prints_diff(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = pathlib.Path(d) / "in.yaml", pathlib.Path(d) / "out.yaml"
            src.write_text(FLOW); src.chmod(0o600)
            before = hashlib.sha256(src.read_bytes()).hexdigest()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(pm.main(["--input", str(src), "--output", str(dst), "--image", DIGEST_NEW]), 0)
            self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(), before)
            self.assertIn("+    - {name: KMS_TRANSIT_AUDIT_DIR, value: /transit-audit}", buf.getvalue())
            self.assertIn("-    - {name: KMS_SEAL_TYPE, value: shamir}", buf.getvalue())
            self.assertEqual(oct(dst.stat().st_mode & 0o777), "0o600")
            self.check_result(dst.read_text())
            # 같은 파일을 출력으로 지정하면 거부
            with self.assertRaises(pm.PatchError):
                pm.main(["--input", str(src), "--output", str(src)])
            # 두 번째 실행은 변경 없음
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                pm.main(["--input", str(dst), "--output", str(pathlib.Path(d) / "out2.yaml"), "--image", DIGEST_NEW])
            self.assertIn("변경 없음", buf2.getvalue())

    def test_repo_template_style_input_also_works(self):
        tpl = (ROOT / "deploy/oci-single-node/templates/kms-static-pod.yaml").read_text()
        tpl = tpl.replace("${SERVER_IMAGE}", DIGEST_OLD).replace("${NODE_IP}", "10.0.0.2").replace("${SA_ISSUER}", "https://issuer.test")
        out, _ = pm.patch(tpl, DIGEST_NEW)
        doc = yaml.safe_load(out)
        self.assertEqual(env(doc)["KMS_EXTERNAL_ADDR"], "0.0.0.0:9443")


if __name__ == "__main__":
    unittest.main()
