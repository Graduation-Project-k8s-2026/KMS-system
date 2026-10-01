# KMS-system

졸업 프로젝트 — Kubernetes 환경에서 동작하는 자체 구현 KMS(Key Management Service).

## 프로젝트 정체성

**Transit형 KMS**를 코어로 한다. 데이터를 저장하지 않고 암복호화 연산만 제공하며 (AWS/GCP KMS, HashiCorp Vault transit engine과 동일한 모델), 필요 시 이를 사용하는 얇은 데모 앱을 부록으로 둔다.

## MVP 기능 범위 (확정)

- [x] 봉투 암호화 (KEK/DEK 계층)
- [x] 키 생성 / 조회 / 목록
- [x] 암호화 / 복호화 API
- [x] 키 회전 (수동 + 자동 주기)
- [x] min_decryption_version (버전 이하 복호화 차단)

## 구현 현황

### 코어
- [x] 봉투 암호화 (Root Key / KEK / DEK 3단 계층)
- [x] 키 생성 / 조회 / 목록
- [x] 암호화 / 복호화 / rewrap
- [x] 키 회전 (수동 + 자동 주기)
- [x] min_decryption_version (버전 이하 복호화 차단)
- [x] 루트 키 보호 4종 (dev / shamir / tpm / k8s)

### API 구조
- [x] Transit / Admin 평면 분리 (TCP / 유닉스 소켓)
- [x] 관리 API (admin.sock → HTTP 중계, 별도 프로세스)

### 접근 제어
- [x] 인증 — ServiceAccount 토큰 로컬 JWT 서명 검증
- [x] 인가 — SubjectAccessReview 기반 (쿠버네티스 RBAC 연동)

### 관측성
- [x] Prometheus 메트릭 (전용 포트, 인증 없음 — 네트워크 정책으로 접근 제한)
- [x] 성능 측정 도구 (`cmd/bench` — 로컬 실행 CLI, 처리량/지연/페이로드/동시성/접근 제어 오버헤드 측정)

### 진행 예정
- [ ] gRPC KMS Provider (kube-apiserver가 etcd Secret 암호화에 사용)
- [ ] 쿠버네티스 배포 (static pod 매니페스트)
- [ ] `cmd/bench`를 쿠버네티스 Job으로 포장 + 관리 대시보드 연동
- [ ] 감사 로그
- [ ] 데모 앱 분리, 관리 대시보드 재설계

## 아키텍처 개요

3단 키 계층으로 봉투 암호화·회전·버전 정책을 하나의 축으로 관통시킨다.
Root Key (seal이 보호, 메모리에만 존재)
└─ KEK = 각 transit 키의 버전 material   ← 회전 / min_decryption_version 단위
└─ DEK = 요청마다 생성되는 1회용 키  ← 실제 데이터 암호화

- 저장 백엔드(`StorageBackend`)와 루트 키 보호 방식(`Seal`)은 인터페이스로 분리되어 있어, 나중에 구현체만 교체 가능.
- 상세 설계는 코드 내 주석 및 `docs/` 참고.

서버는 하나의 코어 위에 여러 입구를 둔다. 입구마다 노출 범위와 검문 수준이 다르다.
관리자 → :8201 (관리 API) → admin.sock ──┐
├→ [KMS 코어]
앱 → :8200 (Transit) → 인증 → 인가 ────┘

자세한 내용은 [docs/architecture.md](docs/architecture.md) 참고.


## 기술 스택

- **언어**: Go 1.23+
- **HTTP 라우터**: [chi](https://github.com/go-chi/chi) — 나중 K8s 인증/인가 미들웨어 체이닝을 고려해 선정
- **CI**: GitHub Actions (`.github/workflows/ci.yml`) — push/PR마다 build + vet + test 자동 실행

## 개발 환경 세팅

1. Go 1.23+ 설치 (WSL/Linux 권장 — K8s 툴체인과의 호환성 때문)
2. 레포 clone
```bash
   git clone https://github.com/Graduation-Project-k8s-2026/KMS-system.git
```


## 프로젝트 구조 (예정)
cmd/server/            KMS 서버 실행 진입점 (main.go) — Transit(TCP)/Admin(유닉스 소켓)/Metrics(TCP) 세 리스너를 함께 기동
cmd/admin-api/         관리 API 프로세스 실행 진입점 — HTTP로 받아 admin.sock으로 중계
cmd/bench/             성능 측정 CLI — Transit API에 부하를 걸어 처리량/지연 측정 (서버 코드 아님, 외부 HTTP 클라이언트)
internal/crypto/       AES-GCM, 봉투암호화 로직
internal/keys/         키 생성/조회/회전/버전 관리
internal/seal/         루트 키 보호 (Seal 인터페이스 + 구현체)
internal/storage/      저장 백엔드 (StorageBackend 인터페이스 + 구현체)
internal/api/httputil/ 두 평면이 공유하는 JSON 응답 헬퍼, 에러 매핑, sealed 가드 미들웨어
internal/api/transit/  데이터 평면 — 암호화/복호화/rewrap, seal 비교·벤치마크 (TCP로 노출)
internal/api/admin/    관리 평면 — 키 관리, init/unseal/seal-status (유닉스 소켓 전용)
internal/api/console/, portal/, dashboard/, home/  웹 UI (현재 비활성 — 아래 "웹 UI" 절 참고)
internal/adminapi/     관리 API 프로세스의 라우팅/프록시 로직 (admin.sock 투명 중계, /healthz, /readyz)
internal/authn/        Transit 요청자 인증 (ServiceAccount 토큰 로컬 서명 검증)
internal/authz/        Transit 요청자 인가 (SubjectAccessReview 기반)
internal/metrics/      Prometheus 지표 정의 + 계측 미들웨어/collector (전용 /metrics 리스너)
internal/bench/        cmd/bench의 측정 로직 (HTTP 클라이언트, worker pool 실행기, 백분위 집계, 결과 포맷)
docs/                  리서치 노트, 설계 근거 등 코드 외 문서

## 브랜치 & 협업 전략

- 기능 단위 브랜치(`feature/xxx`)에서 작업 → PR 생성 → 리뷰 후 `main` 머지
- PR 생성 시 CI(build/vet/test)가 자동으로 돌아감
- 커밋 메시지는 자유 서술 (별도 컨벤션 강제하지 않음)

## 문서

| 문서 | 내용 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 전체 구조, 키 계층, 평면 분리, 접근 제어 |
| [docs/decisions.md](docs/decisions.md) | 설계 결정 기록(ADR) — 각 결정의 배경과 근거 |
| [docs/usage.md](docs/usage.md) | 기능별 상세 사용법, 환경변수 전체 목록 |
| [docs/verification.md](docs/verification.md) | 기능 검증 체크리스트 |
| [docs/benchmark.md](docs/benchmark.md) | 성능 측정 도구(cmd/bench) 사용법, 접근 제어 오버헤드 비교 실험 절차 |
| [docs/vault-practice/](docs/vault-practice/) | 사전 리서치 — Vault 실습 기록 (Day 1~6) |

- 리서치/조사 자료는 별도 레포 [`Study-Research`](https://github.com/Graduation-Project-k8s-2026/Study-Research)에서 관리

## 사용법 (로컬 실행)

### 1. 서버 실행

서버는 두 개의 리스너를 동시에 띄웁니다: Transit(데이터 평면, TCP)과
Admin(관리 평면, 유닉스 도메인 소켓).

```bash
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory go run ./cmd/server
```

`KMS_SEAL_TYPE`으로 루트 키 보호 방식을 선택합니다:

| 값 | 방식 | 관련 환경변수 |
|---|---|---|
| `dev` (기본) | 패스프레이즈 해싱 (개발용) | `KMS_MASTER_KEY` |
| `shamir` | Shamir Secret Sharing | `KMS_SHAMIR_PARTS`(기본 5), `KMS_SHAMIR_THRESHOLD`(기본 3) |
| `tpm` | TPM 봉인 | `KMS_TPM_SIMULATOR=true`(시뮬레이터) 또는 `KMS_TPM_DEVICE`(실제 장치, 기본 `/dev/tpmrm0`) |
| `k8s` | K8s Secret 위임 | `KMS_K8S_NAMESPACE`(기본 `default`), `KMS_K8S_SECRET_NAME`(기본 `kms-root-key`) |

리스너 관련 환경변수:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_TRANSIT_ADDR` | `:8200` | Transit(데이터 평면) TCP 리스너 주소 |
| `PORT` | `8200` | `KMS_TRANSIT_ADDR`가 비어 있을 때만 쓰이는 하위호환 변수 (포트 번호만) |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | Admin(관리 평면) 유닉스 도메인 소켓 경로. 부모 디렉터리가 없으면 생성하고, 이전 실행이 남긴 소켓 파일(stale socket)이 있으면 지우고 다시 바인딩합니다. 파일 권한은 `0600`. |
| `KMS_METRICS_ADDR` | `:9100` | Prometheus 메트릭(`/metrics`) TCP 리스너 주소. 빈 문자열로 명시적으로 설정하면 비활성화됩니다. 자세한 내용은 "7. 메트릭(Prometheus)" 절 참고 |

기타: `KMS_STORAGE`(`memory`\|`file`, 기본 `file`), `KMS_DATA_DIR`(기본 `./data`)

### 2. 웹 UI — console은 관리 API에서 복구됨, dashboard/portal은 아직 비활성

`console`/`portal`/`dashboard`/`home` 패키지(코드)는 저장소에 그대로 남아
있지만, KMS 서버(`cmd/server`)의 Transit/Admin 리스너에는 어느 것도
등록되지 않습니다 — 브라우저는 admin.sock(유닉스 소켓)에 직접 접속할 수
없기 때문입니다.

대신 아래 "4. 관리 API" 절에서 다루는 별도 프로세스(`cmd/admin-api`)가
HTTP로 `/console`을 서빙하고 그 안의 API 호출을 admin.sock으로 중계합니다
— 운영자 콘솔은 이 경로로 다시 쓸 수 있습니다. `/dashboard`, `/portal`은
여전히 어디에도 등록되어 있지 않습니다 — 이유는 "4. 관리 API" 절 참고.

### 3. API 직접 호출 (curl)

**Admin(관리 평면)** — 유닉스 소켓 `KMS_ADMIN_SOCKET`(기본
`/var/run/kms/admin.sock`)으로만 호출할 수 있습니다. `curl --unix-socket`을
씁니다 (URL의 호스트 부분은 무시되므로 아무 값이나 둬도 됩니다).

```bash
SOCK=/var/run/kms/admin.sock

# 상태 확인
curl --unix-socket $SOCK http://localhost/v1/sys/seal-status

# 초기화 및 봉인 해제 (dev 기준)
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/init
curl --unix-socket $SOCK -XPOST http://localhost/v1/sys/unseal

# 키 생성
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys \
  -H 'content-type: application/json' -d '{"name":"demo"}'

# 키 목록 / 조회 / 회전 / 정책 설정
curl --unix-socket $SOCK http://localhost/v1/keys
curl --unix-socket $SOCK http://localhost/v1/keys/demo
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/rotate
curl --unix-socket $SOCK -XPOST http://localhost/v1/keys/demo/config \
  -H 'content-type: application/json' -d '{"min_decryption_version":2}'
```

**Transit(데이터 평면)** — 네트워크(TCP, 기본 `:8200`)로 호출합니다. 아래
예시는 기본값(`KMS_AUTHN=off`) 기준이며, 인증을 켠 경우는 "5. Transit API
인증" 절을 참고하세요.

```bash
# 암호화
curl -XPOST localhost:8200/v1/encrypt/demo -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"

# 복호화
curl -XPOST localhost:8200/v1/decrypt/demo -H 'content-type: application/json' \
  -d '{"ciphertext":"<위 암호화 응답의 ciphertext>"}'

# seal 방식 비교·벤치마크 (키 사용과 무관한 읽기 전용 진단 엔드포인트)
curl localhost:8200/v1/sys/seal-profile
curl localhost:8200/v1/sys/seal-benchmark
```

### 4. 관리 API — HTTP로 admin.sock 중계

`admin.sock`은 유닉스 소켓이라 같은 노드가 아니면(예: 별도 머신에서
포트포워딩 없이) 접근할 수 없고, 브라우저는 원천적으로 접속할 수
없습니다. `cmd/admin-api`는 KMS 서버와 별개의 프로세스로 떠서, HTTP로
받은 `/v1/*` 요청을 경로/메서드/헤더/바디 그대로 admin.sock에 중계합니다
— 요청을 해석하거나 바꾸지 않는 투명 프록시입니다. 그와 함께 운영자
콘솔(`/console`)도 서빙합니다.

> ⚠️ **인증·TLS 없음.** 이 프로세스는 이번 범위에서 인증도 TLS도 구현하지
> 않았습니다. HTTP로만 열리고 누구나 요청을 보낼 수 있으므로, 신뢰된
> 네트워크(예: 같은 노드/네임스페이스 안) 밖에는 절대 노출하지 마세요.
> 기동 시 이 사실을 경고 로그로도 남깁니다.

두 프로세스를 함께 띄우는 예시 (터미널 두 개):

```bash
# 터미널 1: KMS 서버 (admin.sock을 만든다)
KMS_SEAL_TYPE=dev KMS_MASTER_KEY=change-me KMS_STORAGE=memory go run ./cmd/server

# 터미널 2: 관리 API (KMS 서버가 뜬 뒤 — admin.sock이 있어야 기동된다)
go run ./cmd/admin-api
```

관리 API 환경변수:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ADMIN_API_ADDR` | `:8201` | 관리 API가 HTTP를 수신할 주소 |
| `KMS_ADMIN_SOCKET` | `/var/run/kms/admin.sock` | 중계할 admin.sock 경로. 시작 시 이 경로에 파일이 없으면(= KMS 서버가 아직 안 떴을 가능성) 명확한 에러와 함께 기동을 실패시킨다 |

상태 확인 엔드포인트:

- `GET /healthz` — 관리 API 프로세스 자체의 생존만 확인 (admin.sock을 건드리지 않음)
- `GET /readyz` — admin.sock에 실제로 연결 가능한지 확인해 200/503 반환

관리 API를 거쳐 HTTP로 admin.sock을 호출하는 예시 (직접
`curl --unix-socket`을 쓰는 대신):

```bash
# 상태 확인
curl localhost:8201/v1/sys/seal-status

# 초기화 및 봉인 해제 (dev 기준)
curl -XPOST localhost:8201/v1/sys/init
curl -XPOST localhost:8201/v1/sys/unseal

# 키 생성
curl -XPOST localhost:8201/v1/keys -H 'content-type: application/json' \
  -d '{"name":"demo"}'

# 관리 API 자체 상태
curl localhost:8201/healthz
curl localhost:8201/readyz
```

#### 브라우저 접속 (운영자 콘솔)

두 프로세스를 모두 띄운 뒤, 브라우저에서 `http://localhost:8201/console`로
접속합니다. `/`는 아직 홈 랜딩이 따로 없어 `/console`로 바로 안내(redirect)합니다.

콘솔에서 할 수 있는 것 — 전부 Admin 평면(admin.sock)이라 그대로 동작합니다:

- 서버 초기화(Init) / 봉인 해제(Unseal)
- 키 생성 / 목록 / 조회 / 회전
- 정책 설정(`min_decryption_version`, 자동 회전 주기)

콘솔에는 "Seal 특성(참고용)" 카드가 하나 있는데, 이건 Transit 평면
엔드포인트(`/v1/sys/seal-profile`, `:8200`)를 호출합니다. 관리 API는
admin.sock만 중계하므로 이 카드는 "이 기능은 Transit API(:8200)가
필요합니다" 안내만 보여주고 실제로 값을 불러오지는 않습니다 — 콘솔의
나머지 기능에는 영향이 없습니다.

`/dashboard`, `/portal`은 관리 API에 등록되어 있지 않습니다(404):

- **`/dashboard`**: seal 4종 비교 화면인데, 쓰는 API(`seal-profile`,
  `seal-benchmark`)가 전부 Transit 평면이라 admin.sock 경유로는 접근할 수
  없습니다. 벤치마크 실행기(Job)가 직접 측정하고 관리 API가 그 결과를
  저장·표시하는 구조로 다시 설계한 뒤 연결할 예정입니다.
- **`/portal`**: 고객용 암복호화 화면으로, 목표 구조에서는 Transit
  API(`:8200`)를 직접 호출하는 별도 데모 애플리케이션이 됩니다. 관리
  API(admin.sock 전용)에는 연결하지 않습니다.

두 패키지(`internal/api/dashboard`, `internal/api/portal`) 모두 코드는
삭제하지 않고 그대로 남겨뒀습니다.

### 5. Transit API 인증 (ServiceAccount 토큰, 1단계: 인증만)

Transit API(`:8200`)는 기본적으로 인증이 꺼져 있어(`KMS_AUTHN=off`) 누구나
호출할 수 있습니다. `KMS_AUTHN=on`으로 켜면 모든 Transit 요청에
`Authorization: Bearer <ServiceAccount 토큰>` 헤더를 요구합니다. **Admin
(admin.sock)에는 이 인증이 적용되지 않습니다** — 소켓 파일 권한(`0600`)과
같은 노드 제약으로 이미 보호되고 있고, 관리 API 인증은 별도 과제입니다.

**1단계는 인증(누구인지 확인)만입니다.** 검증에 성공한 요청은 신원과
무관하게 모든 키에 접근할 수 있습니다 — "무엇을 할 수 있는지" 판단하는
인가(authorization, SubjectAccessReview 기반)는 2단계에서 다룹니다.

#### 왜 kube-apiserver의 TokenReview가 아닌가

KMS 서버는 static pod로 배포될 예정입니다. static pod는 kubelet이 매니페스트를
직접 읽어 생성하므로 kube-apiserver의 admission controller를 거치지 않고,
그 결과 **ServiceAccount 토큰이 자동 마운트되지 않습니다**
(`spec.serviceAccountName`을 지정해도 `/var/run/secrets/kubernetes.io/
serviceaccount/`가 생기지 않습니다). TokenReview를 호출하려면 KMS 자신이
별도의 자격 증명을 마련해야 하는데, 암복호화는 요청마다 발생하는 핫패스라
매 요청 apiserver 왕복은 지연 측면에서도 부적합합니다.

대신 KMS가 컨트롤 플레인 노드에 static pod로 배치된다는 점을 활용해,
ServiceAccount 토큰(kube-apiserver가 서명한 JWT)의 서명을 컨트롤 플레인
노드에 있는 서명 공개키(`/etc/kubernetes/pki/sa.pub`)로 **로컬에서 직접**
검증합니다.

> ⚠️ **한계: 토큰 폐기(revocation) 여부는 확인할 수 없습니다.** 서명이
> 유효하고 만료(`exp`)되지 않았다면, apiserver가 그 사이 해당 토큰을
> 무효화했더라도(예: Pod/ServiceAccount 삭제) 로컬 검증은 통과시킵니다.
> TokenReview를 호출하지 않는 이상 이 한계는 구조적으로 남습니다 — 짧은
> `exp`를 쓰는 projected 토큰(TokenRequest API 기본값)을 쓰면 노출 시간을
> 줄일 수 있습니다.

#### 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHN` | `off` | `off`\|`on`. off면 인증 없이 전부 통과(경고 로그 남김). on이면 아래 키 로딩에 실패할 경우 기동 자체를 실패시킨다 |
| `KMS_SA_PUBLIC_KEY` | `/etc/kubernetes/pki/sa.pub` | 서명 검증용 공개키 경로. **쉼표로 여러 개** 지정 가능(`a.pub,b.pub`) — apiserver 서명키 회전 중 새/이전 키가 동시에 유효한 기간을 지원하기 위함 |
| `KMS_SA_ISSUER` | (없음) | 설정하면 토큰의 `iss` 클레임이 이 값과 일치해야 한다. 비어 있으면 검사하지 않는다 |
| `KMS_SA_AUDIENCE` | (없음) | 설정하면 토큰의 `aud` 클레임에 이 값이 포함돼야 한다. 비어 있으면 검사하지 않는다 |

지원 알고리즘은 RS256/ES256뿐입니다(`alg: none`, HMAC 계열은 항상 거부).
레거시 토큰(자동 마운트 시크릿, `exp`/`nbf`/`iat` 없음)과 projected
토큰(TokenRequest API, `kubernetes.io` 클레임 아래 namespace/서비스어카운트
이름) 둘 다 지원합니다.

#### curl 예시

```bash
# 클러스터 안에서: 파드에 마운트된 토큰을 그대로 사용
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -H "Authorization: Bearer $TOKEN" \
  -XPOST localhost:8200/v1/encrypt/demo -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"

# 토큰 없이 호출하면 (KMS_AUTHN=on일 때)
curl -XPOST localhost:8200/v1/encrypt/demo -H 'content-type: application/json' \
  -d "{\"plaintext\":\"$(echo -n 'hello' | base64)\"}"
# -> 401 {"error":"unauthorized"}
```

### 6. Transit API 인가 (SubjectAccessReview, 2단계: 권한 판단)

1단계(인증)는 "누구인지"만 확인했고, 검증만 통과하면 모든 키에 접근할 수
있었습니다. `KMS_AUTHZ=on`으로 켜면 "이 요청자가 이 키에 이 동작을 해도
되는가"까지 판단합니다. **Admin(admin.sock)에는 적용되지 않습니다** —
1단계와 같은 이유(소켓 파일 권한/같은 노드 제약)입니다.

KMS는 자체 정책 저장소를 갖지 않습니다. 대신 kube-apiserver의
**SubjectAccessReview(SAR)**에 "이 주체가 이 작업을 해도 되는가"를 묻고,
관리자는 익숙한 `kubectl`로 `Role`/`RoleBinding`만 다루면 됩니다.

#### RBAC 어휘 매핑

KMS의 개념을 쿠버네티스 RBAC 어휘로 옮깁니다. 아래는 실제로 존재하는
쿠버네티스 리소스가 아닙니다 — SAR은 존재하지 않는(가상의) 리소스에도
질의를 허용하므로 이 방식이 성립합니다. API 그룹/리소스 이름은
`internal/authz`의 상수(`APIGroup`, `Resource`) 한 곳에서만 정의하므로
바뀌어도 그 한 곳만 고치면 됩니다.

| KMS 개념 | RBAC 표현 |
|---|---|
| API 그룹 | `kms.local` |
| 리소스 종류 | `keys` |
| 키 이름 | `resourceNames` |
| 동작 | verb: `encrypt`, `decrypt`, `rewrap` |
| 스코프 | 네임스페이스(요청자의 namespace 기준) |

> **네임스페이스 스코프의 의미.** 키 저장소 자체에는 네임스페이스 개념이
> 없습니다 — 키는 클러스터 전역으로 하나의 목록입니다. 네임스페이스는
> **접근 권한 판단에만** 쓰입니다. 즉 "team-a의 demo 키"가 따로 존재하는
> 게 아니라, "demo 키에 대한 team-a 소속 요청자의 권한"을 SAR에 묻는
> 것입니다. 같은 `demo` 키를 여러 네임스페이스의 ServiceAccount가 서로
> 다른 권한으로(예: team-a는 encrypt+decrypt, team-b는 encrypt만) 쓸 수
> 있습니다.

`seal-profile`/`seal-benchmark`은 인가 대상에서 제외합니다 — 특정 키를
대상으로 하지 않는 진단용 엔드포인트이고, 애초에 이 둘을 Admin이 아닌
Transit에 둔 이유가 벤치마크 실행기(Job) 같은 호출자가 키 관리 권한 없이
호출할 수 있게 하려는 것이었기 때문입니다. 인증(1단계)은 그대로
요구합니다.

#### Role/RoleBinding 예시

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kms-demo-key-user
  namespace: team-a
rules:
- apiGroups: ["kms.local"]
  resources: ["keys"]
  resourceNames: ["demo"]
  verbs: ["encrypt", "decrypt"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kms-demo-key-user-binding
  namespace: team-a
subjects:
- kind: ServiceAccount
  name: app-workload
  namespace: team-a
roleRef:
  kind: Role
  name: kms-demo-key-user
  apiGroup: rbac.authorization.k8s.io
```

이 Role/RoleBinding이 있으면 `team-a` 네임스페이스의 `app-workload`
ServiceAccount는 `demo` 키에 `encrypt`/`decrypt`만 할 수 있고, `rewrap`이나
다른 키에는 여전히 403을 받습니다.

#### 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_AUTHZ` | `off` | `off`\|`on`. off면 인증만 통과하면 모든 키에 접근 가능(경고 로그 남김). **`KMS_AUTHN=off`인데 `KMS_AUTHZ=on`이면 기동을 실패시킨다** — 신원 없이는 권한을 판단할 수 없다 |
| `KMS_KUBECONFIG` | (없음) | kube-apiserver 접속용 kubeconfig 파일 경로. 비어 있으면 in-cluster 설정을 시도한다. 둘 다 실패하면 기동을 실패시킨다 |
| `KMS_AUTHZ_CACHE_TTL` | `10`(초) | SAR 판단 결과(허용/거부 둘 다)를 캐싱하는 시간. 짧을수록 권한 회수가 반영되는 지연이 줄지만 apiserver 호출이 늘어난다 |
| `KMS_AUTHZ_TIMEOUT` | `3`(초) | SAR 호출 하나에 허용하는 최대 시간 |
| `KMS_AUTHZ_FAIL_OPEN` | `false` | apiserver 호출 자체가 실패했을 때(타임아웃 등, 캐시 미스 상태) 거부(기본, fail-closed) 대신 허용할지. `true`면 기동 시 경고 로그를 남긴다 |

> ⚠️ **기본은 fail-closed입니다.** apiserver에 물어볼 수 없으면(장애,
> 타임아웃 등) 기본적으로 거부합니다 — 보안 도구이므로 판단이 안 될 때는
> 거부하는 쪽이 안전하다고 봅니다. 단, apiserver 호출 자체가 실패한
> 경우의 이 폴백 결정은 캐싱하지 않습니다 — 장애가 복구되면 바로 다음
> 요청부터 실제 판단으로 돌아갑니다.

#### KMS용 kubeconfig에 필요한 최소 권한

KMS가 SubjectAccessReview를 **생성**할 수 있어야 합니다. 클러스터
전역(비네임스페이스) 리소스이므로 `ClusterRole`+`ClusterRoleBinding`이
필요합니다:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kms-sar-creator
rules:
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kms-sar-creator-binding
subjects:
- kind: ServiceAccount
  name: <KMS가 KMS_KUBECONFIG로 접속할 때 쓰는 주체>
  namespace: <해당 네임스페이스>
roleRef:
  kind: ClusterRole
  name: kms-sar-creator
  apiGroup: rbac.authorization.k8s.io
```

이 이상의 권한(키 목록 조회, Secret 접근 등)은 필요 없습니다 — KMS는
SAR "질의"만 하고, RBAC 규칙 자체를 읽거나 쓰지 않습니다.

### 7. 메트릭 (Prometheus)

KMS는 세 번째 리스너로 `/metrics`를 서빙합니다 — Transit(`:8200`)이나
Admin(admin.sock)과는 별개의 전용 포트입니다.

> ⚠️ **인증 없음.** 이 리스너에는 인증을 붙이지 않았습니다(의도적 —
> Prometheus가 KMS_AUTHN과 무관하게 항상 수집할 수 있어야 합니다).
> 대신 루프백에만 바인딩하지 않으므로(쿠버네티스에서 Prometheus는 다른
> 파드), **반드시 네트워크 정책(NetworkPolicy)으로 이 포트에 접근할 수
> 있는 파드를 Prometheus로 제한하세요.** 신뢰되지 않은 네트워크에
> 노출하면 안 됩니다.

#### 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `KMS_METRICS_ADDR` | `:9100` | 메트릭 리스너 주소. **빈 문자열로 명시적으로 설정하면**(`KMS_METRICS_ADDR=""`) 리스너 자체를 기동하지 않는다 — 설정하지 않은 경우(기본값 사용)와는 다르다 |

#### 노출되는 메트릭

**암복호화(Transit, `internal/api/transit`에서 계측)**

| 이름 | 종류 | 라벨 | 의미 |
|---|---|---|---|
| `kms_transit_requests_total` | Counter | `operation`(encrypt/decrypt/rewrap), `result`(success/error) | Transit 요청 수 |
| `kms_transit_request_duration_seconds` | Histogram | `operation` | 요청 처리 시간(초). 버킷은 1µs~10s를 20구간으로 로그 등분 — 실제 연산이 마이크로초~저밀리초 단위이기 때문 |
| `kms_transit_payload_bytes` | Histogram | `operation` | 처리한 평문/암호문 크기(바이트). 64B~128KB, 2배씩 12구간 |

**인가(`internal/authz`에서 계측 — 캐싱 효과 확인용)**

| 이름 | 종류 | 라벨 | 의미 |
|---|---|---|---|
| `kms_authz_sar_requests_total` | Counter | `result`(allowed/denied/error) | SubjectAccessReview 호출 수 |
| `kms_authz_sar_duration_seconds` | Histogram | (없음) | SubjectAccessReview 호출 지연(초) |
| `kms_authz_cache_requests_total` | Counter | `result`(hit/miss) | 인가 판단 캐시 조회 수 — hit 비율이 곧 apiserver 왕복을 얼마나 줄였는지를 보여준다 |
| `kms_authz_cache_entries` | Gauge | (없음) | 현재 캐시에 들어있는 항목 수 |

**seal/키 현황(`internal/metrics.SealKeyCollector` — 스크레이프 시점에 조회)**

| 이름 | 종류 | 의미 |
|---|---|---|
| `kms_seal_sealed` | Gauge | 1=sealed, 0=unsealed |
| `kms_seal_last_unsealed_timestamp_seconds` | Gauge | 이 프로세스가 unsealed를 마지막으로 관찰한 시각(Unix epoch). 한 번도 못 봤으면 0. barrier.Unseal() 호출 시각이 아니라 스크레이프 시점에 처음 감지한 시각이라 약간 늦을 수 있다 |
| `kms_keys_total` | Gauge | 현재 등록된 키 개수. sealed 상태에서는 조회할 수 없어 0 |
| `kms_key_versions_total` | Gauge | 모든 키의 버전 총합(회전 횟수 포함). sealed면 0 |

**Go 런타임 / 프로세스 메트릭**: `go_*`, `process_*` — client_golang이 기본으로 제공하는 고루틴 수, GC, 메모리, 파일 디스크립터 등.

절대 노출하지 않는 값: 키 이름, 키 자료, 평문, 암호문, 토큰, 주체(subject) 이름, 네임스페이스 이름. 인가 메트릭도 주체/네임스페이스를 라벨로 쓰지 않습니다 — cardinality 폭발과 정보 노출 양쪽을 막기 위함입니다.

#### 확인 방법 (curl)

```bash
curl localhost:9100/metrics

# 특정 지표만
curl -s localhost:9100/metrics | grep '^kms_transit_requests_total'
```

#### Prometheus scrape 설정 예시

```yaml
scrape_configs:
  - job_name: kms
    static_configs:
      - targets: ["kms-server.kms-system.svc:9100"]
```

### 8. 로컬 K8s(kind)에서 K8sSeal 검증

```bash
kind create cluster --name kms-dev
KMS_SEAL_TYPE=k8s KMS_STORAGE=memory go run ./cmd/server
# 다른 터미널에서 위 admin.sock curl 호출로 init/unseal 후:
kubectl get secret kms-root-key -o yaml
```

### 9. 성능 측정 (`cmd/bench`)

Prometheus 메트릭이 "운영 중 무슨 일이 일어났는가"를 수동적으로 기록한다면,
`cmd/bench`는 인위적으로 부하를 걸어 조건을 통제한 상태에서 측정하는 CLI다.
Transit API만 HTTP로 호출하는 외부 클라이언트이고, 키를 만들거나 서버
설정을 바꾸지 않는다 — 측정 전 키를 직접 만들어 둬야 한다.

```bash
go run ./cmd/bench --key bench-demo --scenario all --format json --output result.json
```

플래그 전체 목록, 접근 제어 오버헤드 비교 실험(서버를 네 가지 설정으로
각각 띄워 측정하는 절차), 결과 해석 방법은
[docs/benchmark.md](docs/benchmark.md)에 정리했다.
