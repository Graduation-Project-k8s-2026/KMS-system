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

### 다음 단계 (미확정 / 논의 예정)
- rewrap (평문 노출 없는 재암호화)
- 감사 로그
- 루트 키 보호 방식 (Shamir / K8s Secret / 외부 클라우드 KMS 위임)
- K8s 통합 및 접근 제어 (RBAC 연동, 정책 방식)

## 아키텍처 개요

3단 키 계층으로 봉투 암호화·회전·버전 정책을 하나의 축으로 관통시킨다.
Root Key (seal이 보호, 메모리에만 존재)
└─ KEK = 각 transit 키의 버전 material   ← 회전 / min_decryption_version 단위
└─ DEK = 요청마다 생성되는 1회용 키  ← 실제 데이터 암호화

- 저장 백엔드(`StorageBackend`)와 루트 키 보호 방식(`Seal`)은 인터페이스로 분리되어 있어, 나중에 구현체만 교체 가능.
- 상세 설계는 코드 내 주석 및 `docs/` 참고.

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
3. (진행 예정) `go mod init github.com/Graduation-Project-k8s-2026/KMS-system`

## 프로젝트 구조 (예정)
cmd/server/            KMS 서버 실행 진입점 (main.go) — Transit(TCP)/Admin(유닉스 소켓) 두 리스너를 함께 기동
cmd/admin-api/         관리 API 프로세스 실행 진입점 — HTTP로 받아 admin.sock으로 중계
internal/crypto/       AES-GCM, 봉투암호화 로직
internal/keys/         키 생성/조회/회전/버전 관리
internal/seal/         루트 키 보호 (Seal 인터페이스 + 구현체)
internal/storage/      저장 백엔드 (StorageBackend 인터페이스 + 구현체)
internal/api/httputil/ 두 평면이 공유하는 JSON 응답 헬퍼, 에러 매핑, sealed 가드 미들웨어
internal/api/transit/  데이터 평면 — 암호화/복호화/rewrap, seal 비교·벤치마크 (TCP로 노출)
internal/api/admin/    관리 평면 — 키 관리, init/unseal/seal-status (유닉스 소켓 전용)
internal/api/console/, portal/, dashboard/, home/  웹 UI (현재 비활성 — 아래 "웹 UI" 절 참고)
internal/adminapi/     관리 API 프로세스의 라우팅/프록시 로직 (admin.sock 투명 중계, /healthz, /readyz)
docs/                  리서치 노트, 설계 근거 등 코드 외 문서

## 브랜치 & 협업 전략

- 기능 단위 브랜치(`feature/xxx`)에서 작업 → PR 생성 → 리뷰 후 `main` 머지
- PR 생성 시 CI(build/vet/test)가 자동으로 돌아감
- 커밋 메시지는 자유 서술 (별도 컨벤션 강제하지 않음)

## 문서

- 리서치/조사 자료는 별도 레포 [`Study-Research`](https://github.com/Graduation-Project-k8s-2026/Study-Research)에서 관리
- Vault 실습 기록: `docs/vault-practice/`

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

**Transit(데이터 평면)** — 네트워크(TCP, 기본 `:8200`)로 호출합니다.

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

### 5. 로컬 K8s(kind)에서 K8sSeal 검증

```bash
kind create cluster --name kms-dev
KMS_SEAL_TYPE=k8s KMS_STORAGE=memory go run ./cmd/server
# 다른 터미널에서 위 admin.sock curl 호출로 init/unseal 후:
kubectl get secret kms-root-key -o yaml
```
