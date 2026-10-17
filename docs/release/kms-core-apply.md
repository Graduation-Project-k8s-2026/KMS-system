# KMS 본체 묶음 적용 절차서 — 1단계 + 2단계 (재시작 1회)

> **경고 — 먼저 읽으세요.** 이 절차는 KMS를 **재시작 1회** 합니다.
> KMS가 재시작되면 **봉인(sealed) 상태**로 뜨고, **Shamir 조각 3개를 입력**하기 전까지 **클러스터 Secret 읽기가 중단**됩니다.
> 조각 보유자 3명이 **같은 자리에 있을 때** 시작하세요. 4단계의 재시작 직후 바로 조각이 필요합니다.
>
> **TPM 봉인은 이번 적용에 포함하지 않습니다**(배포 보류, ADR-010). `seal-migrate`를 실행하지 않으므로 init 기록은 **v1로 남고**,
> 이전 서버 이미지로 되돌릴 수 있습니다(아래 "되돌리기").

대상: 단일 노드(OCI) 운영 클러스터. 이 문서의 명령은 서버에서 사람이 그대로 실행하도록 썼고, 작성 시점에는 운영 서버에서 실행하지 않았습니다.
각 단계의 **확인**을 통과한 뒤 다음으로 가세요. 막히면 해당 단계의 **되돌리기**를 따르고 그 뒤 단계로 가지 않습니다.

포함: 1단계(C+B 키 소유, Transit 감사, 오류 형식, 키 삭제) + 2단계(data key API, TLS 인증서 무중단 교체, 외부 사용자 경로 ③).
관련 문서: 설계 근거는 `docs/decisions.md` ADR-009·011·012·013·014·015. TPM(보류)은 [tpm-seal.md](tpm-seal.md).

## 이 적용이 바꾸는 것

| 변경 | 운영에 미치는 영향 |
|---|---|
| C+B 키 소유 모델 (ADR-009) | **점 없는 키(`demo`, `campus-shipping` …)는 네임스페이스 Role이 효력을 잃고 ClusterRole/ClusterRoleBinding만 효력.** 재시작 전에 ClusterRole을 먼저 적용해야 권한 공백이 없다 |
| Transit 비동기 감사 | 새 호스트 디렉터리 필요. 켜면 키 이름·주체·결과가 파일에 남는다 (본문 미기록) |
| 오류 응답 `{error,message,hint}` | 상태 코드는 같다. 오류 **본문**을 문자열로 파싱하는 외부 코드가 있으면 확인 |
| 키 삭제(disable → schedule-deletion → 삭제) | 새 관리 API. 기존 키는 모두 active로 읽힌다. KMS v2 키는 자동 보호 |
| data key API (ADR-013) | `POST /v1/datakey/{name}` 신규 verb `datakey` (C+B 규칙 그대로). 기존 권한에는 영향 없음 |
| TLS 무중단 교체 (ADR-015) | 이후 인증서 파일을 바꾸면 재시작 없이 30초 이내 반영. 이번 재시작이 마지막 인증서 때문의 재시작이다 |
| 외부 경로 ③ (ADR-014) | `0.0.0.0:9443` 리스너가 **켜진다**. 인터넷에 닿으려면 OCI 방화벽을 사람이 열어야 하므로(6단계, 점검 통과 후) 재시작만으로는 외부에 노출되지 않는다 |
| 관리 소켓 `seal-profile` | 관리 화면용. `seal-migrate`는 코드에 있지만 **실행하지 않는다** (서버가 `KMS_SEAL_ALLOWED=shamir`라 target=tpm은 403) |

**저장 형식 변경과 되돌리기:**
- 키 저장 형식: `State`/`DeletionDate` 필드가 *추가*되었을 뿐이고, 필드가 없는 기존 키는 active로 읽힌다. 새 코드는 기존 운영 데이터를 그대로 읽는다.
- init 기록: 이번 적용은 `seal-migrate`를 실행하지 않으므로 **v1로 남는다.** 새 코드가 v1을 그대로 읽고, 기록을 v2로 바꾸는 것은 `seal-migrate`뿐이다
  (조각 재발급 `target=shamir`도 v2로 올리므로 **이 적용 동안 실행하지 않는다**). 따라서 **이전 서버 이미지로 되돌릴 수 있다.**

## 0. 준비 (서비스 영향 없음)

1. 새 이미지 빌드·digest 확정 (`SERVER_IMAGE`, `ADMIN_IMAGE`, 변경된 경우 `DEMO_IMAGE`/`BENCH_IMAGE`). 릴리스 값 JSON의 키 목록은 `release-values.example.json`과 같다(TPM 관련 입력 없음).
2. 호스트 디렉터리 (Transit 감사용, KMS 컨테이너는 uid/gid 10001):

```bash
sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/custom-kms/transit-audit
ls -ld /var/lib/custom-kms/transit-audit       # 확인: drwx------ 10001 10001
```

3. (외부 경로를 쓸 경우) **Transit 인증서 SAN에 외부 접속 주소 추가.** 외부 사용자는 `<공인 주소>`(또는 DNS 이름)로 접속하므로 SAN에 있어야 TLS 검증이 통과한다.
   재시작 **전에 해도 된다**(옛 서버도 시작 시 읽은 인증서를 계속 쓰고, 새 서버는 파일 교체를 30초 이내에 다시 읽는다 — 그래서 순서와 무관).
   공인 주소는 이 명령의 인자로만 쓰고 파일·문서에 적지 않는다.

```bash
sudo scripts/reissue-transit-cert.sh --ca-cert <내부 CA 인증서 경로> --ca-key <내부 CA 키 경로> \
  --add-ip <공인 주소> --add-dns <공개 DNS 이름(있다면)> --plan        # 먼저 --plan으로 새 SAN 확인
sudo scripts/reissue-transit-cert.sh --ca-cert <내부 CA 인증서 경로> --ca-key <내부 CA 키 경로> --add-ip <공인 주소>   # [y/N]에 y
# 확인: 마지막에 출력되는 SAN에 기존 항목(kms-transit 등, 127.0.0.1, 노드 IP)과 새 주소가 모두 있고 notAfter가 충분히 먼 미래
```

   **CA 개인 키 확인**: 재발급에는 내부 CA 키(`private-pki/ca.key`, 운영 서버 사용자 폴더 아래)가 필요하다. 재발급을 끝낸 뒤 반드시 확인한다:
   (1) 권한이 `0600`이고 소유자가 root인지(`sudo ls -l <private-pki 경로>/ca.key`; 아니면 `sudo chown root:root` + `sudo chmod 600`),
   (2) **오프라인 보관**(운영 서버 밖의 안전한 매체)이 있는지, (3) 작업 중 만든 임시 복사본이나 셸 기록에 경로·내용이 남지 않았는지. CA 키는 사용자에게 보내지 않는다 — 사용자에게는 공개 인증서(`ca.crt`)만 준다.
   되돌리기: `$TLS_DIR/backup-<시각>/`의 `tls.crt`, `tls.key`를 같은 디렉터리로 복사(임시 이름 → `mv`).
   **주의: 사설망 클라이언트(Pod 등)가 쓰는 CA는 그대로**이므로 클라이언트 신뢰 설정은 바꿀 필요가 없다.
4. (외부 사용자에게 배포할 경우) **CLI 빌드** — 개발 PC에서(운영 서버가 아니어도 됨):

```bash
scripts/build-cli.sh                       # dist/ 에 kms-linux-amd64, kms-linux-arm64, kms-darwin-arm64, kms-windows-amd64.exe + SHA256SUMS
cat dist/SHA256SUMS                        # 확인: 4개 파일 해시
```

   dist/는 git에 올리지 않는다. 배포 위치(`<배포 URL>`)에 올릴 때 바이너리와 `SHA256SUMS`를 함께 올리고, 사용자는 `KMS_CLI_URL=<배포 URL> ./install.sh`로 설치한다(체크섬 불일치면 설치 안 됨). 6단계 이후에 해도 된다.
5. 새 매니페스트 렌더 (static pod 외 구성용; 적용하지 않는다, 결과는 커밋하지 않는다):

```bash
OUT=/root/release-core-$(date -u +%Y%m%dT%H%MZ)
python3 scripts/render-release.py --values <비밀 없는 릴리스 값.json> --output $OUT
```

   **KMS static pod는 렌더 결과로 교체하지 않는다.** 운영 파일에는 템플릿에 없는 `tmp` emptyDir와 `resources`가 있고 flow 스타일 YAML이라 렌더하면 차이가 커진다.
   4단계에서 `scripts/patch-kms-manifest.py`로 **현재 파일을 부분 수정**한다.

## 1. 정지 백업 (기준점)

```bash
ID=pre-core-$(date -u +%Y%m%dT%H%MZ); echo $ID
sudo python3 scripts/backup-kms.py prepare --directory /var/backups/custom-kms/$ID
sudo python3 scripts/host-unseal.py                  # 조각 3개 (TTY, 화면에 보이지 않음)
sudo python3 scripts/backup-kms.py resume --directory /var/backups/custom-kms/$ID
sudo python3 scripts/backup-kms.py status --directory /var/backups/custom-kms/$ID | grep -E '"stage"|"complete"'
# 확인: stage resumed, complete true
```

되돌리기: 이 단계 자체는 운영을 바꾸지 않는다. 실패하면 출력 안내대로 `resume`으로 운영을 먼저 회복한다.
**이후 모든 되돌리기의 기준점이 이 백업이다** (`<ID>/manifests/`에 현재 static pod 매니페스트 사본이 있다).

## 2. RBAC 이전 점검 — `migrate-rbac-cb.py check`

현재 RBAC를 파일로 받아 **효력을 잃는 권한**을 찾는다. (kubectl 읽기 전용 호출만 한다.)

```bash
sudo sh -c 'umask 077; kubectl --kubeconfig=/etc/kubernetes/admin.conf get roles,rolebindings,clusterroles,clusterrolebindings -A -o json > /root/rbac-before.json'
python3 scripts/migrate-rbac-cb.py check --input /root/rbac-before.json
```

읽는 법:
- **사라짐**: 점 없는 키에 대한 네임스페이스 Role/RoleBinding 권한 — 새 서버에서 403이 된다. 다음 단계에서 ClusterRole로 옮긴다.
- **유지**: `<ns>.<name>` 키를 소유 네임스페이스가 준 권한(현재 운영에는 없을 것).
- **이전됨**: 이미 ClusterRoleBinding으로 같은 권한이 있다.
- **경고**: `resourceNames`가 없는 Role(모든 키 허용)은 자동 생성에서 제외된다 — 필요한 키 이름을 사람이 확인해 명시한 Role/ClusterRole을 직접 만든다.
  `*` 와일드카드 규칙도 사람이 확인한다.

예상(이 저장소의 배포 기준): `kms-demo/app-a`, `kms-bench/bench-transit`의 `demo`(템플릿이 이미 ClusterRole로 바뀌어 있음),
`campus-store`의 `checkout/shipping/migration`의 `campus-shipping`. **표가 예상과 다르면 멈추고 보고하세요.**

되돌리기: 읽기 전용이라 없음.

## 3. ClusterRole 먼저 적용 (재시작 전)

```bash
python3 scripts/migrate-rbac-cb.py generate --input /root/rbac-before.json --output /root/rbac-cb.yaml
sudo cat /root/rbac-cb.yaml                           # 사람이 검토: 키·verb·주체가 check 표의 "사라짐"과 같은지
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /root/rbac-cb.yaml
```

`generate`는 파일만 만들고, 기존 Role/RoleBinding은 지우지 않는다. 새 ClusterRole은 **현재(옛) 서버에서도 무해**하므로 지금 적용해도 서비스에 영향이 없다.
`campus-store`는 `deploy/campus-store/deploy.py`가 같은 이름(`kms-cb-campus-shipping-<verb>`)으로 만들므로 나중에 재배포해도 일치한다.

**이미 적용됐으면 건너뜀**: 운영에는 이미 ClusterRole/ClusterRoleBinding 4쌍(`kms-cb-campus-shipping-decrypt/encrypt/rewrap`, `kms-cb-demo-decrypt-encrypt-rewrap`)이 적용되어 있다.
이 경우 `check`가 해당 권한을 "이전됨"으로 표시하고 `generate`는 "0쌍 생성"을 출력한다 — **0쌍이면 `apply`를 하지 않는다**(빈 파일 apply는 오류). 위 4쌍이 모두 있는지:

```bash
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get clusterrole,clusterrolebinding -o name | grep kms-cb-
# 확인: clusterrole/clusterrolebinding 각각 4개
```

확인은 `kubectl auth can-i`를 쓰지 않는다. `kms.local/keys`는 apiserver에 없는 가상 리소스라 `can-i`가 제대로 질의하지 못한다
(운영에서 전부 "no"가 나왔다). 대신 **SubjectAccessReview를 직접 보낸다** — KMS가 실제로 하는 질의와 같다. namespace를 주지 않으면 클러스터 범위 질의다
(전역 키는 ClusterRoleBinding만 효력):

```bash
sar() {  # sar <사용자> <verb> <키 이름> [namespace]  → true/false
  sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf create -o jsonpath='{.status.allowed}' -f - <<YAML
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: $1
  resourceAttributes: {group: kms.local, resource: keys, verb: $2, name: $3${4:+, namespace: $4}}
YAML
  echo
}
sar system:serviceaccount:kms-demo:app-a encrypt demo                      # 확인: true
sar system:serviceaccount:kms-bench:bench-transit encrypt demo             # 확인: true
sar system:serviceaccount:campus-store:checkout encrypt campus-shipping    # 확인: true
sar system:serviceaccount:kms-demo:app-a encrypt campus-shipping           # 확인: false  (시연용 "권한 없음"이 그대로)
```

(운영에서 위 방식으로 확인한 결과: 클러스터 범위 질의에서 app-a·bench-transit의 demo encrypt, checkout의 campus-shipping encrypt는 true, app-a의 campus-shipping은 false.)

되돌리기: `sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf delete -f /root/rbac-cb.yaml` (기존 Role은 그대로 남아 있어 옛 서버 권한에는 영향 없음).

## 4. 새 이미지·매니페스트 교체 → 재시작 (여기서 봉인됨)

1. 보조 구성 요소부터(KMS 무관): 외부 사용자 네임스페이스, 렌더된 RBAC, 변경된 이미지의 Deployment를 적용한다.
   **관리 API(`kms-admin`)와 시연 앱(`kms-demo-app`) 이미지도 여기서 교체**한다 — 새 관리 화면(키 수명 주기·감사 합쳐 보기·성능 기준 비교)과 포털의 파일 암호화 탭이 이 이미지에 들어 있다.
   `admin-deployment.yaml`은 Transit 감사 디렉터리를 읽기 전용으로 마운트하므로(0단계 2의 호스트 디렉터리가 있어야 Pod가 뜬다) KMS 재시작 전에 적용해도 된다. KMS가 아직 옛 버전이어도 새 화면은
   동작하지만, 키 수명 주기 버튼은 KMS 재시작(새 서버) 뒤에야 성공한다(그 전에는 404).

```bash
K="sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf"
$K apply -f $OUT/kms-external.yaml                                   # Namespace kms-external (사용자별 리소스는 6단계에서 스크립트가)
$K apply -f $OUT/serviceaccounts-rbac.yaml
$K apply -f $OUT/admin-deployment.yaml                               # ADMIN_IMAGE 변경 시
$K apply -f $OUT/demo-app.yaml                                       # DEMO_IMAGE 변경 시
$K -n kms-system rollout status deployment/kms-admin --timeout=150s
```

   (`serviceaccounts-rbac.yaml`의 `kms-cb-demo-…` ClusterRole은 이미 적용된 것과 같은 이름이면 그대로 갱신된다. 기존 Role은 apply가 지우지 않는다.)

2. KMS static pod **부분 수정** — 원본은 건드리지 않고 새 파일을 만든 뒤 diff를 사람이 검토한다:

```bash
python3 scripts/patch-kms-manifest.py --input /etc/kubernetes/manifests/kms-static-pod.yaml \
  --output /root/kms-static-pod.new.yaml --image <SERVER_IMAGE digest>
# 확인: diff에 나온 변경은 이것뿐이어야 한다
#   - 이미지 줄
#   - KMS_SEAL_TYPE → KMS_SEAL_ALLOWED=shamir
#   - 추가: KMS_TRANSIT_AUDIT_DIR, KMS_EXTERNAL_* 6개(ADDR 0.0.0.0:9443, 네임스페이스 2개, RPS 20, BURST 40, AUTHFAIL_MAX 10)
#   - 추가: transit-audit 볼륨 마운트·볼륨
# 이미 적용된 항목은 건너뛴다. 두 번 실행해도 같은 결과. 외부 리스너를 아직 켜지 않으려면 --no-external.
```

3. 교체 — kubelet은 `.`으로 시작하는 파일을 무시하므로 임시 파일 → `mv`(원자적):

```bash
sudo install -m 0600 /root/kms-static-pod.new.yaml /etc/kubernetes/manifests/.kms-static-pod.yaml.new
sudo mv /etc/kubernetes/manifests/.kms-static-pod.yaml.new /etc/kubernetes/manifests/kms-static-pod.yaml
# kubelet이 Pod를 다시 만든다. 이 순간부터 봉인 상태 → 바로 조각 3개
until sudo test -S /run/custom-kms/admin/admin.sock; do sleep 2; done
sudo python3 scripts/host-unseal.py
```

확인:

```bash
SOCK=/run/custom-kms/admin/admin.sock
sudo curl -sS --unix-socket $SOCK http://localhost/v1/sys/seal-status
# 확인: "sealed":false, "seal_type":"shamir", "recovery_available":false
sudo curl -sS --unix-socket $SOCK http://localhost/v1/sys/seal-profile
# 확인: Type "shamir"
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf get --raw '/readyz?verbose' | grep kms
# 확인: kms 항목 ok (이름 예: kms-provider-0)
```

되돌리기: 1단계 백업의 매니페스트로 복원하고 조각 3개로 해제.

```bash
sudo install -m 0600 /var/backups/custom-kms/$ID/manifests/kms-static-pod.yaml /etc/kubernetes/manifests/.kms-static-pod.yaml.new
sudo mv /etc/kubernetes/manifests/.kms-static-pod.yaml.new /etc/kubernetes/manifests/kms-static-pod.yaml
sudo python3 scripts/host-unseal.py
```

## 5. 해제 후 점검 (KMS v2 경로가 최우선)

**5-1. 클러스터 Secret 읽기/쓰기 — KMS v2 경로 (SAR을 거치지 않는 경로)**

```bash
K="sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf"
$K get secrets -A --no-headers | wc -l                     # 확인: 오류 없이 개수 출력 (목록 조회는 모든 Secret을 복호화)
$K -n default create secret generic kms-apply-check --from-literal=probe=1
$K -n default get secret kms-apply-check -o jsonpath='{.data.probe}'; echo   # 확인: MQ==
$K -n default delete secret kms-apply-check
```

**5-2. 시연 앱·쇼핑몰·포털** (브라우저로 각각 접속해서 확인; 주소는 배포 값 사용)

- 사용자 포털(demo-app): `demo` 키 암호화/복호화/rewrap 성공, `campus-shipping`은 **403 (권한 없음 시연 — 정상)**.
- 쇼핑몰(campus-store): 가상 주문 1건 생성 → 배송 조회(복호화) 성공. 이 흐름은 `campus-shipping`의 ClusterRole(3단계)에 의존한다.
- 실패(403)하면: `sudo journalctl`이 아니라 KMS 컨테이너 로그에서 `authz: denied ... namespace="" key=...`를 찾는다. `namespace=""`는 전역 키 판단이다.
  해당 주체의 ClusterRoleBinding이 빠진 것이므로 2~3단계 표를 다시 확인한다.

**5-2b. data key 왕복**

data key 왕복은 6단계에서 외부 사용자 토큰으로 함께 확인한다(내부 SA에 `datakey` verb를 따로 주지 않았기 때문). 확인할 것:
`POST /v1/datakey/<키>` → `{"ciphertext":"kms:v1:...","plaintext":"<base64>","key_version":1}`, 그 `ciphertext`를 `POST /v1/decrypt/<키>`에 보내면 같은 `plaintext`.

**5-2c. 인증서 무중단 교체 확인** (3단계의 재발급을 재시작 *후*에 했다면 반드시, 아니면 선택)

```bash
# 인증서 교체 후 최대 30초 뒤, 접속에 실제로 쓰이는 인증서의 SAN과 만료일 (<Transit 주소>는 배포 값)
echo | openssl s_client -connect <Transit 주소> -servername kms-transit 2>/dev/null | openssl x509 -noout -enddate -ext subjectAltName
# 확인: 새 SAN이 보인다. KMS를 재시작하지 않았다.
# KMS 로그에 "tlsreload: certificate reloaded" 한 줄 (깨진 파일이면 "keeping the previous one" 경고 — 이전 인증서는 계속 사용 중)
```

**5-3. Transit 감사 파일 생성**

```bash
# 위 5-2의 요청이 끝난 뒤 (fsync 주기 1초)
sudo ls -l /var/lib/custom-kms/transit-audit/
sudo tail -n 5 /var/lib/custom-kms/transit-audit/$(date -u +%F).jsonl
# 확인: {"utc":...,"request_id":...,"subject":"system:serviceaccount:...","action":"encrypt","key":"demo","sar_namespace":"","status":200,"latency_ms":...}
#       본문/평문/암호문/토큰이 없고 key와 sar_namespace가 있다 (전역 키는 sar_namespace가 빈 문자열)
# 메트릭은 별도 포트(127.0.0.1:9100)
curl -sS http://127.0.0.1:9100/metrics | grep kms_audit_dropped_total
# 확인: kms_audit_dropped_total 0
```

**5-4. 오류 응답 형식** (인증 없이 호출 → 401 JSON; `<Transit 주소>`는 배포 값)

```bash
curl -sk -X POST https://<Transit 주소>/v1/encrypt/demo -d '{}' -H 'content-type: application/json'
# 확인: {"error":"unauthorized","message":"authentication required","hint":"..."}  — 상태 401
```

**5-4b. 새 관리 화면·포털 확인** (브라우저)

- 관리 화면(`/v2/`) 키 상세에 상태 배지와 **키 수명 주기** 패널(관리자 계정에만)이 보이는지, `k8s-secrets`는 사용 중지·삭제 예약 버튼이 비활성(이유 표시)인지.
- 봉인 화면에 'TPM 배포 보류' 안내만 있고 봉인 방식 전환/조각 재발급 버튼이 없는지. 감사 화면에서 Transit 기록(키 이름·경로 필터)이 보이는지(5-3 이후).
- 포털의 '파일 암호화' 탭: 작은 파일을 암호화(.kmsf 내려받기) → 복호화로 원본과 같은지. 개발자 도구 네트워크 탭에서 **파일 본문이 서버로 전송되지 않는지**(`/datakey`는 키 이름만 보낸다).
- 포털에서 권한 없는 키(campus-shipping)를 쓰면 안내 문구가 '(현재 app-a 권한)'을 포함한 403인지(상단에 상시 문구는 없음).

**5-5. 키 삭제 API 스모크 (시험용 키, 곧바로 정리하지 않아도 됨)**

```bash
J='content-type: application/json'
sudo curl -sS --unix-socket $SOCK -XPOST -H "$J" -d '{"name":"apply-check"}' http://localhost/v1/keys
sudo curl -sS --unix-socket $SOCK -XPOST http://localhost/v1/keys/apply-check/disable | grep -o '"state":"[a-z_]*"'      # disabled
sudo curl -sS --unix-socket $SOCK -XPOST http://localhost/v1/keys/apply-check/enable | grep -o '"state":"[a-z_]*"'       # active
sudo curl -sS --unix-socket $SOCK -XPOST http://localhost/v1/keys/k8s-secrets/disable                                    # 확인: 409 key_protected
sudo curl -sS --unix-socket $SOCK -XPOST -H "$J" -d '{"pending_days":7}' http://localhost/v1/keys/apply-check/schedule-deletion | grep -o '"deletion_date":"[^"]*"'
sudo curl -sS --unix-socket $SOCK -XPOST http://localhost/v1/keys/apply-check/cancel-deletion | grep -o '"state":"[a-z_]*"'  # disabled
```

`apply-check` 키는 남겨 두어도 무해하다(다시 `schedule-deletion`을 걸면 7일 뒤 삭제 작업이 도는지 확인할 수 있다).
관리 감사 확인: `sudo tail -n 6 /var/lib/custom-kms/core-audit/$(date -u +%F).jsonl` → `POST /v1/keys/disable` 등에 `"key":"apply-check"`.

되돌리기: 5단계 중 실패가 있으면 4단계의 되돌리기를 따른다.

## 6. 외부 사용자 경로 ③ 열기 — **5단계 점검을 모두 통과한 뒤에만**

재시작만으로는 인터넷에 열리지 않는다. 리스너(`0.0.0.0:9443`)는 떠 있지만 OCI 방화벽이 닫혀 있기 때문이다. 아래 순서로 **사람이** 연다.

1. 외부 사용자 1명과 키 만들기 (서버에서):

```bash
sudo scripts/kms-external-user.sh add alice orders --plan     # 먼저 계획 확인
sudo scripts/kms-external-user.sh add alice orders            # 키 kms-external.orders 가 없으면 만들지 [y/N] → y
# 확인: SA kms-external/alice, Role/RoleBinding kms-ext-alice-orders (verbs encrypt, decrypt, rewrap, datakey)
```

2. **OCI 방화벽에서 TCP 9443 인그레스 열기** (OCI 콘솔: 서브넷 보안 목록 또는 NSG). 가능하면 허용 출처를 특정 CIDR로 좁힌다.
   호스트 자체 방화벽(iptables)도 확인한다 (OCI Ubuntu 이미지는 INPUT 규칙이 닫혀 있을 수 있다):

```bash
sudo iptables -L INPUT -n --line-numbers | head -20          # 9443 허용 규칙이 있는지
# 없으면(영구 저장 방식은 환경에 맞게): sudo iptables -I INPUT -p tcp --dport 9443 -j ACCEPT
```

3. **CA 인증서(공개값) 배포.** 외부 사용자는 내부 CA 인증서로 서버를 검증한다. 인증서는 공개 정보라 안전한 채널(메신저, 이메일 등)로 보내도 된다.
   **CA 키는 절대 보내지 않는다.** 사용자는 받은 파일을 `ca.crt`로 두고 `curl --cacert ca.crt`처럼 쓴다.

```bash
sudo cat <내부 CA 인증서 경로>        # 사용자에게 전달 (PEM 텍스트, 공개값)
```

4. 토큰 발급 (표준 출력으로만 나온다. 파일로 저장하지 말고 변수에 담아 쓴다. 기본 1시간, 최대 24시간):

```bash
TOKEN=$(sudo scripts/kms-external-user.sh token alice 1)      # audience는 운영 매니페스트의 KMS_SA_AUDIENCE에서 읽음
```

5. 외부(운영자 PC 등 서버 밖)에서 확인 — `<공인 주소>`는 실제 값으로:

```bash
B=https://<공인 주소>:9443
curl --cacert ca.crt $B/healthz                                                          # 확인: {"status":"ok"}
PT=$(printf 'hello' | base64)
CT=$(curl -s --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
      -d "{\"plaintext\":\"$PT\"}" $B/v1/encrypt/kms-external.orders | python3 -c 'import sys,json;print(json.load(sys.stdin)["ciphertext"])')
curl -s --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"ciphertext\":\"$CT\"}" $B/v1/decrypt/kms-external.orders                      # 확인: {"plaintext":"aGVsbG8="}
# data key 왕복
DK=$(curl -s --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}' $B/v1/datakey/kms-external.orders)
echo "$DK" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["ciphertext"][:12], d["key_version"], len(d["plaintext"]))'   # kms:v1:... 1 44
# 위 ciphertext를 /v1/decrypt 에 보내면 같은 plaintext(base64)가 돌아온다
```

6. **방어선 확인** (같은 외부 주소에서):

```bash
# (a) 내부 SA 토큰은 외부에서 403 — 서버에서 내부 SA 토큰을 받아 외부 주소로 보낸다
INT=$(sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kms-demo create token app-a --audience <KMS_SA_AUDIENCE> --duration=10m)
curl -s -o /dev/null -w '%{http_code}\n' --cacert ca.crt -H "Authorization: Bearer $INT" -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$PT\"}" $B/v1/encrypt/kms-external.orders                        # 확인: 403
# (b) 외부 토큰으로 내부(전역) 키 접근은 403 — 키가 존재하든 말든 같은 응답
curl -s -w ' %{http_code}\n' --cacert ca.crt -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$PT\"}" $B/v1/encrypt/demo                                        # 확인: forbidden 403
# (c) 관리·진단 경로는 없다
curl -s -o /dev/null -w '%{http_code}\n' --cacert ca.crt -H "Authorization: Bearer $TOKEN" $B/v1/sys/seal-profile   # 확인: 404
# (d) 요청 폭주 → 429 rate_limited (기본 초당 20, burst 40). 이 PC의 IP가 잠깐 제한되는 것은 정상이다
for i in $(seq 1 120); do curl -s -o /dev/null -w '%{http_code}\n' --cacert ca.crt $B/healthz; done | sort | uniq -c   # 확인: 200 ~40+, 429 다수
```

   **주의(인증 실패 차단 시험)**: 잘못된 토큰으로 1분에 10회를 넘게 보내면 **그 PC의 IP가 5분간 429로 막힌다**(정상 동작). 시험하면 5분 기다리거나 다른 PC에서 확인한다.
   서버에서 지표와 감사 확인:

```bash
curl -sS http://127.0.0.1:9100/metrics | grep -E 'kms_external_(requests|rejected)_total|kms_external_blocked_ips'
# 확인: kms_external_rejected_total{reason="rate"} 가 (d) 이후 0보다 큼. IP 값은 지표에 없다
sudo grep '"listener":"external"' /var/lib/custom-kms/transit-audit/$(date -u +%F).jsonl | tail -n 5
# 확인: client_ip, sar_namespace "kms-external", status 200/403 …  본문·토큰·평문 없음
```

   되돌리기: **OCI 방화벽의 9443 규칙을 닫는다**(이것이 가장 빠른 차단). 사용자 제거: `sudo scripts/kms-external-user.sh remove alice`(키는 남는다).
   리스너 자체를 끄려면 static pod에서 `KMS_EXTERNAL_ADDR`를 비운다(백업 매니페스트 복원이면 재시작 필요).

## 7. 정리 확인 (선택, 하루 정도 지켜본 뒤)

- 기존 네임스페이스 Role/RoleBinding(전역 키용)은 새 규칙에서 효력이 없다. **지우지 않고 둔다**(되돌리기 대비). 정리는 별도 판단.
- 2단계 표를 다시 뽑아 "사라짐"이 모두 "이전됨"으로 바뀌었는지 확인: `kubectl get ... -o json > /root/rbac-after.json && python3 scripts/migrate-rbac-cb.py check --input /root/rbac-after.json`.
- 외부 리스너가 떠 있는지: KMS 기동 로그에 `external listener enabled on ...`이 있고 `external listener NOT started`가 없어야 한다(인증·인가 설정이 어긋나면 안전하게 뜨지 않는다, ADR-020).
- 외부 토큰은 수명이 짧을수록 좋다(유출 시 개별 회수 불가). 필요한 때만 발급한다.

## 되돌리기 (이전 서버 이미지로)

이번 적용은 init 기록을 v1로 남기므로 이전 이미지로 되돌릴 수 있다. 4단계의 되돌리기 명령(백업의 매니페스트로 static pod 복원 → 조각 3개 해제)을 쓴다.

| 시점 | 방법 |
|---|---|
| 0~3단계 | 각 단계의 되돌리기 (서비스 영향 없음) |
| 4~5단계 | 백업 `<ID>/manifests/kms-static-pod.yaml`로 static pod 복원 + 조각 3개 해제. 새 ClusterRole은 남겨도 무해 |
| 6단계 (외부 경로) | OCI 방화벽 9443 닫기 → `kms-external-user.sh remove` → (필요 시) 매니페스트 복원 |
| 3단계 인증서 재발급 | `backup-<시각>/`의 인증서·키를 임시 이름 → `mv`로 복원(30초 내 반영) |
| 이전 이미지가 읽는 데이터 | 키 저장소·init 기록(v1) 모두 읽힌다 |
| 키 삭제 기능으로 상태를 바꾼 뒤 이전 이미지로 복귀 | 이전 이미지는 `State`를 모르므로 disabled/pending 키를 active로 취급하고 자동 삭제도 하지 않는다. 복귀 전에 모든 키를 `enable` 해 두는 것이 안전하다 |
| Transit 감사 | 이전 이미지는 `KMS_TRANSIT_AUDIT_DIR`을 모르므로 무시한다(파일은 남는다) |
| 최후 수단 | 정지 백업 복원 — `scripts/restore-kms.py` 절차(recovery.md) |

> 만약 실수로 `seal-migrate`(조각 재발급 포함)를 실행했다면 init 기록이 v2가 되어 이전 이미지는 기동을 거부한다. 그때는 정지 백업 복원이 필요하다.
