# KMS 본체 묶음 적용 절차서 (C+B 키 소유 + 감사 + 오류 형식 + 키 삭제)

> **경고 — 먼저 읽으세요.** 이 절차는 KMS를 **재시작 1회** 합니다.
> KMS가 재시작되면 **봉인(sealed) 상태**로 뜨고, **Shamir 조각 3개를 입력**하기 전까지 **클러스터 Secret 읽기가 중단**됩니다.
> 조각 보유자 3명이 **같은 자리에 있을 때** 시작하세요. 4단계의 재시작 직후 바로 조각이 필요합니다.
>
> **TPM 봉인은 이번 적용에 포함하지 않습니다**(배포 보류, ADR-010). `seal-migrate`를 실행하지 않으므로 init 기록은 **v1로 남고**,
> 이전 서버 이미지로 되돌릴 수 있습니다(아래 "되돌리기").

대상: 단일 노드(OCI) 운영 클러스터. 이 문서의 명령은 서버에서 사람이 그대로 실행하도록 썼고, 작성 시점에는 운영 서버에서 실행하지 않았습니다.
각 단계의 **확인**을 통과한 뒤 다음으로 가세요. 막히면 해당 단계의 **되돌리기**를 따르고 그 뒤 단계로 가지 않습니다.

관련 문서: 설계 근거는 `docs/decisions.md` ADR-009·011·012. TPM(보류)은 [tpm-seal.md](tpm-seal.md).

## 이 적용이 바꾸는 것

| 변경 | 운영에 미치는 영향 |
|---|---|
| C+B 키 소유 모델 (ADR-009) | **점 없는 키(`demo`, `campus-shipping` …)는 네임스페이스 Role이 효력을 잃고 ClusterRole/ClusterRoleBinding만 효력.** 재시작 전에 ClusterRole을 먼저 적용해야 권한 공백이 없다 |
| Transit 비동기 감사 | 새 호스트 디렉터리 필요. 켜면 키 이름·주체·결과가 파일에 남는다 (본문 미기록) |
| 오류 응답 `{error,message,hint}` | 상태 코드는 같다. 오류 **본문**을 문자열로 파싱하는 외부 코드가 있으면 확인 |
| 키 삭제(disable → schedule-deletion → 삭제) | 새 관리 API. 기존 키는 모두 active로 읽힌다. KMS v2 키는 자동 보호 |
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

3. 새 매니페스트 렌더 (적용하지 않는다, 결과는 커밋하지 않는다):

```bash
OUT=/root/release-core-$(date -u +%Y%m%dT%H%MZ)
python3 scripts/render-release.py --values <비밀 없는 릴리스 값.json> --output $OUT
sudo diff /etc/kubernetes/manifests/kms-static-pod.yaml $OUT/kms-static-pod.yaml
# 확인: 차이는 이미지, KMS_SEAL_TYPE→KMS_SEAL_ALLOWED(`shamir`), KMS_TRANSIT_AUDIT_DIR, transit-audit 볼륨뿐
```

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

확인 (ClusterRoleBinding이 적용됐는지; 옛 서버와 무관하게 apiserver 레벨 확인):

```bash
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf auth can-i encrypt keys.kms.local/demo --as=system:serviceaccount:kms-demo:app-a
# 확인: yes     (클러스터 범위 질의 — namespace를 주지 않으므로 ClusterRoleBinding만 해당)
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf auth can-i encrypt keys.kms.local/campus-shipping --as=system:serviceaccount:campus-store:checkout
# 확인: yes
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf auth can-i encrypt keys.kms.local/campus-shipping --as=system:serviceaccount:kms-demo:app-a
# 확인: no      (시연용 "권한 없음"이 그대로)
```

(`kms.local/keys`는 apiserver에 없는 가상 리소스라 kubectl이 "resource type" 경고를 낼 수 있다. 기준은 마지막 줄의 yes/no 답이다. 작성 시점에 실제 클러스터에서 이 명령을 실행해 보지 못했다.)

되돌리기: `sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf delete -f /root/rbac-cb.yaml` (기존 Role은 그대로 남아 있어 옛 서버 권한에는 영향 없음).

## 4. 새 이미지·매니페스트 교체 → 재시작 (여기서 봉인됨)

1. 보조 구성 요소부터(KMS 무관): 렌더된 `serviceaccounts-rbac.yaml`, 변경된 이미지의 `admin-deployment.yaml`/`demo-app.yaml`을 적용한다.

```bash
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f $OUT/serviceaccounts-rbac.yaml
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f $OUT/admin-deployment.yaml     # ADMIN_IMAGE 변경 시
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f $OUT/demo-app.yaml             # DEMO_IMAGE 변경 시
sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kms-system rollout status deployment/kms-admin --timeout=150s
```

   (`serviceaccounts-rbac.yaml`의 `kms-cb-demo-…` ClusterRole은 3단계와 같은 이름이면 그대로 갱신된다. 기존 Role은 apply가 지우지 않는다.)

2. KMS static pod 교체 — kubelet은 `.`으로 시작하는 파일을 무시하므로 임시 파일 → `mv`(원자적):

```bash
sudo install -m 0600 $OUT/kms-static-pod.yaml /etc/kubernetes/manifests/.kms-static-pod.yaml.new
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

## 6. 정리 확인 (선택, 하루 정도 지켜본 뒤)

- 기존 네임스페이스 Role/RoleBinding(전역 키용)은 새 규칙에서 효력이 없다. **지우지 않고 둔다**(되돌리기 대비). 정리는 별도 판단.
- 2단계 표를 다시 뽑아 "사라짐"이 모두 "이전됨"으로 바뀌었는지 확인: `kubectl get ... -o json > /root/rbac-after.json && python3 scripts/migrate-rbac-cb.py check --input /root/rbac-after.json`.

## 되돌리기 (이전 서버 이미지로)

이번 적용은 init 기록을 v1로 남기므로 이전 이미지로 되돌릴 수 있다. 4단계의 되돌리기 명령(백업의 매니페스트로 static pod 복원 → 조각 3개 해제)을 쓴다.

| 시점 | 방법 |
|---|---|
| 0~3단계 | 각 단계의 되돌리기 (서비스 영향 없음) |
| 4~6단계 | 백업 `<ID>/manifests/kms-static-pod.yaml`로 static pod 복원 + 조각 3개 해제. 새 ClusterRole은 남겨도 무해 |
| 이전 이미지가 읽는 데이터 | 키 저장소·init 기록(v1) 모두 읽힌다 |
| 키 삭제 기능으로 상태를 바꾼 뒤 이전 이미지로 복귀 | 이전 이미지는 `State`를 모르므로 disabled/pending 키를 active로 취급하고 자동 삭제도 하지 않는다. 복귀 전에 모든 키를 `enable` 해 두는 것이 안전하다 |
| Transit 감사 | 이전 이미지는 `KMS_TRANSIT_AUDIT_DIR`을 모르므로 무시한다(파일은 남는다) |
| 최후 수단 | 정지 백업 복원 — `scripts/restore-kms.py` 절차(recovery.md) |

> 만약 실수로 `seal-migrate`(조각 재발급 포함)를 실행했다면 init 기록이 v2가 되어 이전 이미지는 기동을 거부한다. 그때는 정지 백업 복원이 필요하다.
