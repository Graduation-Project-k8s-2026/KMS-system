# 사용법

README가 빠른 시작을 다룬다면, 이 문서는 **기능별 상세 사용법**을 다룬다.

---

## 실행 구성

서버는 두 프로세스로 나뉜다.

| 프로세스 | 역할 | 리스너 |
|---|---|---|
| `cmd/server` | KMS 본체 | Transit `:8200`, admin.sock, metrics `:9100` |
| `cmd/admin-api` | 관리 중계 + 웹 UI | HTTP `:8201` |

### 로컬 최소 실행

**터미널 1 — KMS 서버**
```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory \
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
go run ./cmd/server
```

**터미널 2 — 관리 API**
```bash
KMS_ADMIN_SOCKET=$HOME/kms-admin.sock \
go run ./cmd/admin-api
```

브라우저에서 `http://localhost:8201/console` 접속.

---

## 환경변수

### KMS 서버

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_SEAL_TYPE` | `dev` | 루트 키 보호 방식: `dev`\|`shamir`\|`tpm`\|`k8s` |
| `KMS_MASTER_KEY` | — | dev seal의 패스프레이즈 |
| `KMS_SHAMIR_PARTS` | 5 | shamir 조각 수 |
| `KMS_SHAMIR_THRESHOLD` | 3 | 복원에 필요한 조각 수 |
| `KMS_TPM_SIMULATOR` | false | TPM 시뮬레이터 사용 |
| `KMS_TPM_DEVICE` | `/dev/tpmrm0` | 실제 TPM 장치 경로 |
| `KMS_STORAGE` | `file` | 저장 백엔드: `memory`\|`file` |
| `KMS_DATA_DIR` | `./data` | file 저장소 경로 |
| `KMS_TRANSIT_ADDR` | `:8200` | Transit 리스너 주소 (`PORT`도 하위호환 인식) |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | Admin 유닉스 소켓 경로 |
| `KMS_METRICS_ADDR` | `:9100` | 메트릭 리스너. 빈 값이면 비활성 |

**인증**

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHN` | `off` | `on`이면 Transit 요청에 토큰 요구 |
| `KMS_SA_PUBLIC_KEY` | `/etc/kubernetes/pki/sa.pub` | 서명 공개키 (쉼표로 여러 개) |
| `KMS_SA_ISSUER` | — | 설정 시 `iss` 검증 |
| `KMS_SA_AUDIENCE` | — | 설정 시 `aud` 검증 |

**인가**

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHZ` | `off` | `on`이면 SAR로 권한 판단 |
| `KMS_KUBECONFIG` | — | apiserver 접근용. 비면 in-cluster 설정 시도 |
| `KMS_AUTHZ_CACHE_TTL` | `10`(초) | 판단 결과 캐시 수명. **초 단위 정수**만 받는다(`10s`처럼 단위를 붙이면 기동에 실패한다). `0`은 기본값(10초) 사용, **음수를 주면 캐시를 완전히 비활성화**한다(매 요청마다 apiserver에 SAR을 묻는다) |
| `KMS_AUTHZ_TIMEOUT` | `3`(초) | SAR 호출 타임아웃. 역시 초 단위 정수만 받는다 |
| `KMS_AUTHZ_FAIL_OPEN` | `false` | apiserver 장애 시 허용 여부 |
| `KMS_AUTHZ_QPS` | `50` | 인가 클라이언트가 apiserver에 SAR을 보내는 초당 요청 수 상한. `0`은 기본값, **음수면(QPS/BURST 둘 중 하나라도) 클라이언트 측 속도 제한을 완전히 비활성화**한다. 근거는 ADR-008 참고 |
| `KMS_AUTHZ_BURST` | `100` | 위 QPS의 버스트 용량(토큰이 한꺼번에 쌓일 수 있는 최대치). 해석 규칙은 `KMS_AUTHZ_QPS`와 같다 |

> `KMS_AUTHZ=on`인데 `KMS_AUTHN=off`이면 기동에 실패한다.
> 신원 없이는 권한을 판단할 수 없다.
>
> `KMS_AUTHZ_CACHE_TTL`을 음수로 주고 기동하면 로그에
> `authorization cache is disabled (KMS_AUTHZ_CACHE_TTL < 0) — every request queries the apiserver`가
> 남는다 — 성능에 큰 영향을 주는 설정이라 눈에 띄게 남긴다.
>
> `KMS_AUTHZ_QPS`/`KMS_AUTHZ_BURST`를 명시적으로 설정하지 않으면
> client-go 기본값(QPS 5, Burst 10 — 컨트롤러용)이 아니라 이 값들(50/100)이
> 적용된다. client-go 기본값이 그대로 쓰이면 캐시 미스가 몰릴 때 요청마다
> 최대 수백 ms씩 대기하다 `KMS_AUTHZ_TIMEOUT`을 넘겨 정상 요청이 403을
> 받을 수 있다(ADR-008) — 둘 중 하나라도 음수로 끄면 그 보호가 전부
> apiserver의 API Priority and Fairness에만 맡겨지므로, 끌 때는 기동
> 로그의 경고를 확인해야 한다.

### 관리 API

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ADMIN_API_ADDR` | `:8201` | 수신 주소 |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | 연결할 소켓 |

---

## 기능별 사용법

아래 예시에서 `SOCK`는 admin.sock 경로다.
관리 API(`:8201`)를 쓰면 `curl --unix-socket $SOCK http://localhost` 대신
`curl localhost:8201`로 바꿔 쓸 수 있다.

```bash
SOCK=$HOME/kms-admin.sock
```

### 초기화와 봉인 해제

```bash
curl --unix-socket $SOCK http://localhost/v1/sys/seal-status
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/init
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/unseal
```

seal 방식별 동작:

| seal | init | unseal |
|---|---|---|
| dev | 별도 단계 없음 (패스프레이즈에서 결정적 유도) | 즉시 |
| shamir | 조각 N개 발급 — **이 순간 한 번만 표시됨** | threshold개 조각 제출 |
| tpm | 바로 완료 | 자동 |
| k8s | 바로 완료 | 자동 |

> `init`은 서버 수명 동안 **한 번만** 실행된다. 재실행하면 오류.
> `unseal`은 **프로세스 재시작마다** 필요하다.

### 키 관리

```bash
# 생성
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"demo"}'

# 목록
curl --unix-socket $SOCK http://localhost/v1/keys

# 상세 — 메타데이터만 반환. 키 자료는 절대 노출되지 않음
curl --unix-socket $SOCK http://localhost/v1/keys/demo
```

응답 예:
```json
{
  "Name": "demo",
  "Type": "aes256-gcm",
  "LatestVersion": 1,
  "MinDecryptionVersion": 1,
  "AutoRotatePeriodSec": 0,
  "Versions": [{"Version": 1, "CreatedAt": "..."}]
}
```

### 암복호화

```bash
# 암호화 (평문은 base64)
curl -XPOST localhost:8200/v1/encrypt/demo \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"
# → {"ciphertext":"kms:v1:AAAAP..."}

# 복호화
curl -XPOST localhost:8200/v1/decrypt/demo \
  -H 'content-type: application/json' \
  -d '{"ciphertext":"kms:v1:AAAAP..."}'
```

> 같은 평문을 두 번 암호화하면 서로 다른 암호문이 나온다.
> 요청마다 DEK가 새로 생성되기 때문이다.

### 키 회전

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/rotate
```

회전 후:
- `LatestVersion`이 증가하고 새 버전이 `Versions`에 추가된다
- 새 암호화는 최신 버전을 사용한다 (`kms:v2:...`)
- **기존 버전은 삭제되지 않는다.** 옛 암호문은 계속 복호화된다

### rewrap — 평문 노출 없는 재암호화

```bash
curl -XPOST localhost:8200/v1/rewrap/demo \
  -H 'content-type: application/json' \
  -d '{"ciphertext":"kms:v1:..."}'
# → {"ciphertext":"kms:v2:..."}
```

옛 버전으로 암호화된 데이터를 최신 버전으로 갈아끼운다.
**원본 암호문은 그대로 남는다** — rewrap은 삭제가 아니라 사본 생성이다.
실제 교체는 애플리케이션이 저장소의 값을 바꿔 넣어야 완료된다.

### 정책 설정

```bash
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/config \
  -H 'content-type: application/json' \
  -d '{"min_decryption_version":2}'
```

- `min_decryption_version`: 이 값보다 낮은 버전으로 암호화된 데이터의 복호화를 거부한다.
  키 유출 대응 수단
- 자동 회전 주기 설정도 이 엔드포인트로 한다

### seal 비교

```bash
curl localhost:8200/v1/sys/seal-profile
curl localhost:8200/v1/sys/seal-benchmark
```

Transit 평면에 있다. 특정 키를 대상으로 하지 않으므로 인가 대상에서 제외된다.

---

## 접근 제어 사용

### 인증 활성화

```bash
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=/etc/kubernetes/pki/sa.pub ... go run ./cmd/server
```

Transit 요청에 토큰을 실어 보낸다.

```bash
TOKEN=$(kubectl -n team-a create token app-a)

curl -XPOST localhost:8200/v1/encrypt/demo \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"
```

토큰이 없거나 유효하지 않으면 `401`.
Admin 평면(소켓)은 인증 대상이 아니므로 영향받지 않는다.

### 인가 활성화

```bash
KMS_AUTHN=on KMS_SA_PUBLIC_KEY=... \
KMS_AUTHZ=on KMS_KUBECONFIG=/path/to/kubeconfig \
... go run ./cmd/server
```

관리자가 `kubectl`로 권한을 정의한다.

```yaml
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
```

권한이 없으면 `403`.

### KMS용 자격 증명의 최소 권한

SAR 생성 권한만 있으면 된다. `admin.conf`(클러스터 전체 관리자)는 과도하다.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kms-sar-reviewer
rules:
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
```

---

## 웹 UI

| 경로 | 상태 |
|---|---|
| `/console` | 사용 가능 — 키 관리, init/unseal |
| `/` | `/console`로 리다이렉트 |
| `/dashboard` | 비활성 — seal 비교 엔드포인트가 Transit 평면에 있어 관리 API로 접근 불가 |
| `/portal` | 비활성 — Transit API를 호출하는 별도 데모 앱으로 분리 예정 |

console의 "Seal 특성" 카드는 Transit API가 필요하다는 안내를 표시한다.

---

## 주의사항

**관리 API에는 인증과 TLS가 없다.** 신뢰할 수 없는 네트워크에 노출하지 말 것.

**메트릭 포트에도 인증이 없다.** 네트워크 정책으로 Prometheus만 접근하도록 제한할 것.

**memory 저장소는 재시작 시 모든 키가 소실된다.** 개발·테스트용으로만 사용할 것.
file 저장소를 쓰더라도 디렉터리가 날아가면 KEK가 전멸해 기존 암호문을 영구히 복호화할 수 없다.