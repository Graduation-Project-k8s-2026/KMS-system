# CLAUDE.md

이 파일은 이 저장소에서 작업하는 Claude Code(및 향후 협업자)를 위한 가이드입니다.

## 프로젝트 정체성

Kubernetes 환경에서 동작하는 자체 구현 **Transit형 KMS**(Key Management Service) — 졸업 프로젝트.

Transit형 KMS는 데이터를 저장하지 않고 **암복호화 연산만 제공**한다 (AWS/GCP KMS, HashiCorp
Vault transit engine과 동일한 모델). 필요 시 이를 사용하는 얇은 데모 앱을 부록으로 둘 수 있다.

## MVP 기능 범위 (확정)

1. 봉투 암호화 (KEK/DEK 계층)
2. 키 생성 / 조회 / 목록
3. 암호화 / 복호화 API
4. 키 회전 (수동 + 자동 주기)
5. `min_decryption_version` (특정 버전 이하 복호화 차단)

### 미확정 (다음 단계, 논의 예정)

- rewrap (평문 노출 없는 재암호화)
- 감사 로그
- 루트 키 보호 방식 (Shamir / K8s Secret / 외부 클라우드 KMS 위임)
- K8s 통합 및 접근 제어 (RBAC 연동, 정책 방식)

## 아키텍처: 3단 키 계층

봉투 암호화·회전·버전 정책을 하나의 축으로 관통시키는 3단 키 계층:

```
Root Key   (seal이 보호, 메모리에만 존재 — 디스크에 평문으로 남지 않음)
└─ KEK     각 transit 키의 버전 material   ← 회전 / min_decryption_version 단위
   └─ DEK  요청마다 생성되는 1회용 키       ← 실제 데이터 암호화
```

- **저장 백엔드**(`StorageBackend`)와 **루트 키 보호 방식**(`Seal`)은 인터페이스로 분리 —
  나중에 구현체만 교체 가능하도록 설계 (예: 파일 기반 → K8s Secret → 외부 클라우드 KMS).
- 상세 설계는 코드 내 주석 및 `docs/` 참고.

## 폴더 구조 방침

```
cmd/server/         실행 진입점 (main.go)
internal/crypto/    AES-GCM, 봉투암호화 로직
internal/keys/      키 생성/조회/회전/버전 관리
internal/seal/      루트 키 보호 (Seal 인터페이스 + 구현체)
internal/storage/   저장 백엔드 (StorageBackend 인터페이스 + 구현체)
internal/api/       HTTP 핸들러/라우팅
docs/               리서치 노트, 설계 근거 등 코드 외 문서
```

- Go 관례상 `internal/`은 이 모듈 밖에서 import 불가 — 외부 공개 API가 아님을 명시.
- 인터페이스(`Seal`, `StorageBackend`)와 구현체는 같은 패키지 내에 두되, 향후 구현체가
  늘어나면 하위 패키지로 분리 고려 (예: `internal/seal/shamir`, `internal/seal/k8s`).

## 기술 스택

- **언어**: Go 1.23+
- **모듈 경로**: `github.com/Graduation-Project-k8s-2026/KMS-system`
- **HTTP 라우터**: [chi](https://github.com/go-chi/chi) (`github.com/go-chi/chi/v5`) —
  K8s 인증/인가 미들웨어 체이닝을 고려해 선정
- **CI**: GitHub Actions (`.github/workflows/ci.yml`) — push/PR마다 build + vet + test 자동 실행

## 협업 규칙

- 기능 단위 브랜치(`feature/xxx`)에서 작업 → PR 생성 → 리뷰 후 `main` 머지
- 커밋 메시지는 자유 서술 (별도 컨벤션 강제하지 않음)
- 사용자는 Go 경험이 없으므로, 코드/설정 변경 시 **왜 이렇게 하는지** 간단히 설명 필요
