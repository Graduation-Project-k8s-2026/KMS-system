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

### 2. 웹 UI — 현재 비활성

`console`/`portal`/`dashboard`/`home` 패키지(코드)는 저장소에 그대로 남아
있지만, 이번 API 계층 분리 이후로는 Transit/Admin 어느 리스너에도
등록되지 않습니다.

이유: 관리 기능(키 생성, init/unseal 등)이 유닉스 소켓(`admin.sock`)으로
옮겨갔는데, 브라우저는 유닉스 소켓에 직접 접속할 수 없습니다. 아래 "4.
관리 API" 절에서 다루는 별도 프로세스가 HTTP를 받아 admin.sock으로
중계하지만, 이 프로세스는 아직 `/v1/*` 프록시와 `/healthz`/`/readyz`만
제공하고 웹 UI는 서빙하지 않습니다 — 웹 UI를 그쪽으로 옮기는 작업은
다음 단계입니다. 그 전까지는 아래 curl 예시처럼 admin.sock/관리 API를
직접 호출해야 합니다.

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
— 요청을 해석하거나 바꾸지 않는 투명 프록시입니다.

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

### 5. 로컬 K8s(kind)에서 K8sSeal 검증

```bash
kind create cluster --name kms-dev
KMS_SEAL_TYPE=k8s KMS_STORAGE=memory go run ./cmd/server
# 다른 터미널에서 위 admin.sock curl 호출로 init/unseal 후:
kubectl get secret kms-root-key -o yaml
```
