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
cmd/server/        실행 진입점 (main.go)
internal/crypto/    AES-GCM, 봉투암호화 로직
internal/keys/      키 생성/조회/회전/버전 관리
internal/seal/      루트 키 보호 (Seal 인터페이스 + 구현체)
internal/storage/   저장 백엔드 (StorageBackend 인터페이스 + 구현체)
internal/api/       HTTP 핸들러/라우팅
docs/               리서치 노트, 설계 근거 등 코드 외 문서

## 브랜치 & 협업 전략

- 기능 단위 브랜치(`feature/xxx`)에서 작업 → PR 생성 → 리뷰 후 `main` 머지
- PR 생성 시 CI(build/vet/test)가 자동으로 돌아감
- 커밋 메시지는 자유 서술 (별도 컨벤션 강제하지 않음)

## 문서

- 리서치/조사 자료는 별도 레포 [`Study-Research`](https://github.com/Graduation-Project-k8s-2026/Study-Research)에서 관리
- Vault 실습 기록: `docs/vault-practice/`
