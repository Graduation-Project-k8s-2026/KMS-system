# 기능 검증 체크리스트

## 사용법

앞 단계가 뒷 단계의 전제가 되도록 배치했다. 순서대로 진행할 것.
각 단계는 **목적 → 실행 → 확인 포인트** 구조이며, 확인 포인트가 전부 통과해야 다음으로 넘어간다.

> 요청 본문 필드명은 단계별로 README를 함께 확인할 것.
> 아래 예시는 대화에서 실제로 확인된 것 위주이며, 일부는 실제 구현과 다를 수 있다.

공통 준비:
```bash
cd ~/workspace/active/KMS-system
```

터미널 3개를 쓴다. **T1**=KMS 서버, **T2**=관리 API, **T3**=명령 실행.

---

## M0. 빌드와 테스트

**목적**: 코드가 정상 상태인지 먼저 확인

```bash
go build ./... && go vet ./... && go test ./...
```

- [ ] 세 명령 모두 에러 없이 통과
- [ ] 테스트 실패가 있다면 여기서 멈추고 원인부터 해결

---

## M1. 코어 암호화 — 봉투 암호화 관찰

**목적**: KMS의 심장인 KEK/DEK 계층이 실제로 동작하는지, 암호문 포맷이 설계대로인지

**T1 — 서버**
```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock go run ./cmd/server
```

**T3 — 실행**
```bash
SOCK=$HOME/kms-admin.sock

curl --unix-socket $SOCK http://localhost/v1/sys/seal-status
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/unseal

curl --unix-socket $SOCK -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"demo"}'

curl --unix-socket $SOCK http://localhost/v1/keys/demo
```

암호화 / 복호화:
```bash
CT=$(curl -s -XPOST localhost:8200/v1/encrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello world' | base64)\"}" \
  | grep -o 'kms:v1:[^"]*')
echo $CT

curl -s -XPOST localhost:8200/v1/decrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"ciphertext\":\"$CT\"}"
```

**확인 포인트**
- [ ] 키 조회 응답에 `LatestVersion`, `MinDecryptionVersion`, `Versions` 배열이 있음
- [ ] 키 자료(실제 암호화 키 비트)는 **어디에도 노출되지 않음** — 메타데이터만 나옴
- [ ] 암호문이 `kms:v1:` 로 시작 — 버전이 암호문에 내장되어 있음
- [ ] 같은 평문을 두 번 암호화하면 **서로 다른 암호문**이 나옴 (요청마다 DEK가 새로 생성되므로)
- [ ] 복호화 결과를 base64 디코드하면 원문 복원

```bash
# 같은 평문 두 번 → 다른 암호문 확인
for i in 1 2; do
  curl -s -XPOST localhost:8200/v1/encrypt/demo \
    -H 'content-type: application/json' \
    -d "{\"plaintext\":\"$(echo -n 'same' | base64)\"}"
  echo
done
```

---

## M2. 키 생명주기 — 회전 · 하위호환 · rewrap · 버전 차단

**목적**: 회전해도 옛 암호문이 살아있는지, rewrap이 평문 없이 동작하는지,
`min_decryption_version`으로 옛 버전을 차단할 수 있는지

M1 상태를 이어서 진행.

```bash
# 회전 전 암호화 → v1 암호문 확보
OLD=$(curl -s -XPOST localhost:8200/v1/encrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'before rotation' | base64)\"}" \
  | grep -o 'kms:v1:[^"]*')
echo "OLD=$OLD"

# 회전
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/rotate
curl --unix-socket $SOCK http://localhost/v1/keys/demo

# 회전 후 암호화 → v2 암호문
NEW=$(curl -s -XPOST localhost:8200/v1/encrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'after rotation' | base64)\"}" \
  | grep -o 'kms:v[0-9]*:[^"]*')
echo "NEW=$NEW"

# 옛 암호문이 여전히 풀리는지 (핵심)
curl -s -XPOST localhost:8200/v1/decrypt/demo \
  -H 'content-type: application/json' -d "{\"ciphertext\":\"$OLD\"}"
```

**확인 포인트**
- [ ] 회전 후 `LatestVersion`이 2로 증가, `Versions`에 항목이 2개
- [ ] 새 암호문이 `kms:v2:` 로 시작
- [ ] **v1 암호문이 회전 후에도 정상 복호화됨** — 하위호환의 핵심
- [ ] 키 이름은 그대로 `demo` (정체성 유지, 내용물만 새 버전 추가)

**rewrap**
```bash
REWRAPPED=$(curl -s -XPOST localhost:8200/v1/rewrap/demo \
  -H 'content-type: application/json' -d "{\"ciphertext\":\"$OLD\"}" \
  | grep -o 'kms:v[0-9]*:[^"]*')
echo "REWRAPPED=$REWRAPPED"
```
- [ ] 결과가 `kms:v2:` 로 시작 (최신 버전으로 재암호화됨)
- [ ] **원본 `$OLD`는 그대로 살아있음** (rewrap은 삭제가 아니라 사본 생성)
- [ ] rewrap 응답에 평문이 포함되지 않음

**min_decryption_version** — 필드명은 README 확인 필요
```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/config \
  -H 'content-type: application/json' -d '{"min_decryption_version":2}'

# v1 암호문 복호화 시도 → 거부되어야 함
curl -i -s -XPOST localhost:8200/v1/decrypt/demo \
  -H 'content-type: application/json' -d "{\"ciphertext\":\"$OLD\"}"
```
- [ ] v1 암호문 복호화가 **거부됨**
- [ ] rewrap된 `$REWRAPPED`(v2)는 여전히 복호화됨

**자동 회전** — 짧은 주기로 설정해 관찰
```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/config \
  -H 'content-type: application/json' -d '{"auto_rotate_period_sec":10}'
sleep 15
curl --unix-socket $SOCK http://localhost/v1/keys/demo
```
- [ ] 일정 시간 후 `LatestVersion`이 자동으로 증가
- [ ] `LastRotatedAt`이 갱신됨

---

## M3. 영속성 — 재시작 후에도 복호화되는가

**목적**: memory와 file 저장소의 차이를 몸으로 확인.
KEK가 디스크에 살아남아야 기존 암호문을 풀 수 있다.

**memory 저장소 (서버 끄면 소실)**
```bash
# M1~M2에서 쓰던 서버를 Ctrl+C로 종료 후 같은 설정으로 재시작
# 그다음 기존 암호문 복호화 시도
```
- [ ] 키 목록이 비어 있음
- [ ] 기존 암호문 복호화 실패

**file 저장소**
```bash
# T1
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me \
KMS_STORAGE=file KMS_DATA_DIR=$HOME/kms-data \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock go run ./cmd/server
```
키 생성 → 암호화 → 암호문 저장 → 서버 재시작 → 복호화

- [ ] 재시작 후에도 키 목록에 키가 남아있음
- [ ] 재시작 전에 만든 암호문이 정상 복호화됨
- [ ] `$HOME/kms-data` 안의 파일을 직접 열어봤을 때 **키 자료가 평문으로 보이지 않음**

```bash
ls -la $HOME/kms-data
# 파일 하나를 골라 내용 확인 — 알아볼 수 있는 키 자료가 없어야 함
```

---

## M4. Seal 방식 — 루트 키 보호

**목적**: 4종 seal의 차이를 직접 겪기. 특히 shamir의 정족수 동작.

**4-1. dev seal**
- [ ] init 없이 바로 unseal되는 것 확인 (M1에서 이미 확인)
- [ ] `KMS_MASTER_KEY`를 **다른 값**으로 바꿔 재시작하면 기존 데이터를 못 읽음
  (file 저장소 상태에서 확인 — 루트 키가 달라지므로)

**4-2. shamir seal (배포 예정 방식)**
```bash
rm -rf $HOME/kms-data-shamir
KMS_SEAL_TYPE=shamir KMS_STORAGE=file KMS_DATA_DIR=$HOME/kms-data-shamir \
KMS_SHAMIR_PARTS=5 KMS_SHAMIR_THRESHOLD=3 \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock go run ./cmd/server
```
```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/init
# 조각 N개가 출력됨 — 이 순간 한 번만 보이므로 반드시 복사

curl --unix-socket $SOCK http://localhost/v1/sys/seal-status
# 조각을 하나씩 제출 (요청 본문 형식은 README 확인)
```
- [ ] init 시 조각 5개가 출력됨
- [ ] init 직후 `sealed: true` — 초기화와 unseal은 별개
- [ ] 조각 1개, 2개만 넣었을 때는 **열리지 않음** (진행률만 올라감)
- [ ] 3번째 조각에서 `sealed: false`로 전환
- [ ] sealed 상태에서 암호화 요청 시 거부됨
- [ ] 서버 재시작하면 다시 sealed — 매번 조각을 넣어야 함
- [ ] **재시작 후 unseal하면 기존 암호문이 다시 복호화됨** (데이터는 디스크에 살아있었음)

**4-3. tpm seal (시뮬레이터)**
```bash
KMS_SEAL_TYPE=tpm KMS_TPM_SIMULATOR=true KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock go run ./cmd/server
```
- [ ] 시뮬레이터 모드로 기동 성공
- [ ] init/unseal 동작 확인
- [ ] 실제 하드웨어 TPM이 없음을 인지 (`ls /dev/tpm*` → 없음)

**4-4. seal 비교 엔드포인트**
```bash
curl localhost:8200/v1/sys/seal-profile
curl localhost:8200/v1/sys/seal-benchmark
```
- [ ] 응답이 나옴 (Transit 평면에 있으므로 8200)
- [ ] 이 엔드포인트가 **키를 만들거나 seal 상태를 바꾸지 않음** 확인

---

## M5. 평면 분리 — 격리가 실제로 되는가

**목적**: 관리 기능이 네트워크에 노출되지 않는지 확인

```bash
# Transit(8200)으로 관리 기능 시도 → 전부 404여야 함
for p in "/v1/keys" "/v1/sys/init" "/v1/sys/unseal" "/v1/keys/demo/rotate"; do
  echo "--- $p"
  curl -s -o /dev/null -w "%{http_code}\n" -XPOST localhost:8200$p
done

# 소켓으로는 정상 동작
curl --unix-socket $SOCK http://localhost/v1/keys
```

- [ ] 8200으로 키 생성/회전/init/unseal 전부 **404**
- [ ] 소켓으로는 모두 정상
- [ ] 소켓 파일 권한이 `0600`인지 확인
```bash
ls -la $HOME/kms-admin.sock
```
- [ ] 서버 종료 시 소켓 파일이 삭제됨
- [ ] 소켓 파일이 남아있는 상태로 재기동해도 정상 동작 (stale socket 처리)

---

## M6. 관리 API + console UI

**목적**: 소켓을 HTTP로 중계하는 경로와 웹 UI 복구 확인

**T2 — 관리 API**
```bash
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock go run ./cmd/admin-api
```

```bash
curl localhost:8201/healthz
curl -i localhost:8201/readyz

curl -XPOST localhost:8201/v1/keys \
  -H 'content-type: application/json' -d '{"name":"via-http"}'
curl localhost:8201/v1/keys
```

- [ ] `/healthz`, `/readyz` 모두 200
- [ ] HTTP(8201)로 키 생성 성공 → 소켓 중계가 동작
- [ ] 8201로 만든 키를 8200에서 암호화에 사용 가능 (같은 코어 공유 증명)
- [ ] **KMS 서버를 끈 상태**에서 `/readyz` → 503
- [ ] KMS 서버 없이 관리 API를 기동하면 실패하고 명확한 에러 출력

**브라우저**
- [ ] `localhost:8201/console` 접속 → 화면 표시
- [ ] `localhost:8201/` → `/console`로 리다이렉트
- [ ] console에서 init/unseal, 키 생성·조회·회전·정책 설정 동작
- [ ] "Seal 특성" 카드에 "Transit API 필요" 안내가 표시됨
- [ ] `/dashboard`, `/portal` → 404 (의도된 미등록)

---

## M7. 인증

**목적**: 토큰 없는 Transit 요청이 막히는지, Admin은 영향받지 않는지

**테스트용 키쌍**
```bash
openssl genrsa -out /tmp/sa.key 2048
openssl rsa -in /tmp/sa.key -pubout -out /tmp/sa.pub
```

**T1**
```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=/tmp/sa.pub \
go run ./cmd/server
```

- [ ] 기동 시 인증 활성화 로그 확인
- [ ] 소켓으로 unseal + 키 생성 → 정상 (Admin은 인증 미적용)
- [ ] 토큰 없이 8200 암호화 → **401**
- [ ] 401 응답 본문에 **상세 실패 사유가 노출되지 않음** (`unauthorized` 정도만)
- [ ] 서버 로그에는 상세 사유가 남되 **토큰 원문은 없음**
- [ ] `seal-profile` / `seal-benchmark`도 인증 필요 → 토큰 없이 401
- [ ] `KMS_AUTHN` 제거 후 재시작 → 토큰 없이 정상 동작 (회귀 없음)
- [ ] `KMS_AUTHN=off`일 때 경고 로그 출력

**잘못된 설정**
```bash
KMS_AUTHN=off KMS_AUTHZ=on ... go run ./cmd/server
```
- [ ] 기동 실패 + 원인과 해결책이 담긴 에러 메시지

---

## M8. 인가 — 실제 클러스터 필요

**목적**: SubjectAccessReview가 진짜 apiserver 상대로 동작하는지, 권한이 갈리는지

```bash
kind create cluster --name kms-verify
kind get kubeconfig --name kms-verify > /tmp/kms-kubeconfig
docker cp kms-verify-control-plane:/etc/kubernetes/pki/sa.pub /tmp/sa-real.pub

kubectl create namespace team-a
kubectl -n team-a create serviceaccount app-a
kubectl create namespace team-b
kubectl -n team-b create serviceaccount app-b
```

**권한 부여 — team-a에만 encrypt 허용**
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kms-demo-encrypt
  namespace: team-a
rules:
- apiGroups: ["kms.local"]
  resources: ["keys"]
  resourceNames: ["demo"]
  verbs: ["encrypt"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kms-demo-encrypt
  namespace: team-a
subjects:
- kind: ServiceAccount
  name: app-a
  namespace: team-a
roleRef:
  kind: Role
  name: kms-demo-encrypt
  apiGroup: rbac.authorization.k8s.io
EOF
```

**T1**
```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=/tmp/sa-real.pub \
KMS_AUTHZ=on KMS_KUBECONFIG=/tmp/kms-kubeconfig \
go run ./cmd/server
```

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/unseal
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"demo"}'

TA=$(kubectl -n team-a create token app-a)
TB=$(kubectl -n team-b create token app-b)
```

- [ ] team-a 토큰으로 **encrypt → 200**
- [ ] team-a 토큰으로 **decrypt → 403** (권한 없음. 같은 토큰·같은 키인데 동작에 따라 갈림)
- [ ] team-b 토큰으로 **encrypt → 403** (네임스페이스 격리)
- [ ] 거부 로그에 주체·네임스페이스·키·verb가 남되 토큰 원문은 없음

**캐시**
- [ ] 같은 요청을 연속으로 보내면 두 번째부터 빨라짐
- [ ] TTL(기본 10초) 경과 후 다시 apiserver 질의
- [ ] Role을 삭제한 뒤 TTL 안에서는 아직 허용될 수 있음 → TTL 후 거부로 전환

```bash
kubectl -n team-a delete rolebinding kms-demo-encrypt
# 즉시 요청 → 캐시 때문에 허용될 수 있음
# 10초 이상 기다린 뒤 요청 → 403
```

**apiserver 장애 시**
```bash
kind delete cluster --name kms-verify
# 서버는 켜둔 채로 요청
```
- [ ] fail-closed 기본이므로 **403**
- [ ] `KMS_AUTHZ_FAIL_OPEN=true`로 재기동하면 통과 + 경고 로그

---

## M9. 메트릭 (feat/metrics 완료 후)

```bash
curl localhost:9100/metrics
```
- [ ] Prometheus 텍스트 포맷으로 응답
- [ ] 암호화 요청 후 카운터 증가
- [ ] SAR 캐시 hit/miss 기록
- [ ] sealed 상태 게이지가 실제 상태와 일치
- [ ] **키 이름·토큰·주체·네임스페이스가 라벨에 없음** (민감 정보 차단)
- [ ] `KMS_METRICS_ADDR=""` 로 기동하면 9100이 열리지 않음

---

## M10. 통합 — 시연 리허설

**목적**: 모든 기능을 한 흐름으로 이어서 실행. 발표 시나리오 확정.

shamir + file + 인증 + 인가를 전부 켠 상태로 진행한다.

1. [ ] 서버 기동 → sealed 확인
2. [ ] init → 조각 5개 확보
3. [ ] 조각 3개로 unseal
4. [ ] console에서 키 생성
5. [ ] team-a 앱이 encrypt 성공
6. [ ] team-a 앱이 decrypt 시도 → 403
7. [ ] team-b 앱이 encrypt 시도 → 403
8. [ ] 키 회전 → 옛 암호문 여전히 복호화
9. [ ] rewrap으로 최신 버전 전환
10. [ ] min_decryption_version으로 v1 차단
11. [ ] 서버 재시작 → sealed, 데이터는 보존
12. [ ] 다시 unseal → 모든 암호문 복호화 가능
13. [ ] 메트릭으로 위 과정의 요청 수·지연 확인

---

## 발견 사항 기록

검증 중 발견한 버그·의문점을 여기 적어둘 것.

| 단계 | 내용 | 처리 |
|---|---|---|
| | | |