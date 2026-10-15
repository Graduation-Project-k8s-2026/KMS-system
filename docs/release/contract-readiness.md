# rev2 §5.2.3–§5.2.5 충족 여부 재검토

검토일: 2026-10-11 UTC. 현재 checkout/개인 origin/브랜치/기존 미커밋 변경을 유지했다. 원본 rev2는 수정하지 않았다. **코드·로컬 시험 기준으로 §5.3 이미지 빌드를 시작할 준비가 됐다.** 컨테이너 빌드나 배포 성공을 뜻하지 않는다. 이번에도 이미지 build/pull/import/push, Kubernetes 적용, 운영 init, apiserver 변경은 하지 않았다.

제출용 릴리스 SHA 확정은 남아 있다. 신규 소스·스크립트는 현재 작업 트리에 있고 아직 Git에 커밋하지 않았다. §5.2.5의 “Git에 넣는다”까지 완료했다고 표시하지 않는다. 실제 제출 이미지를 만들기 전에 변경분을 검토하고 커밋하여 SOURCE_SHA를 확정해야 한다. 기존 HEAD를 수정된 소스의 릴리스 SHA로 기록하면 안 된다. 제품 image digest는 빌드 후 기록할 값이며 현재 null이다.

## §5.2.3 — 설정 계약

**충족: 요구된 이름에 실제 읽기·검증·동작 경로가 있다.** 값만 주입하고 미구현 handler를 완료로 표시하지 않았다. 세부 기본값과 경로는 [config-contract](config-contract.md)에 있다.

| 인터페이스 | 실제 구현 및 검증 |
|---|---|
| server `KMS_TRANSIT_TLS_CERT/KEY` | 시작 전 인증서 로드, TLS≥1.2, 필수 파일/CA/SAN/만료 거부 시험 |
| server `KMS_V2_SOCKET/KEY_NAME` | 독립 공식 v2 UDS, 보호 키 이름 검증, RPC·회전·재시작·API 부재 부팅 시험 |
| server `KMS_AUDIT_DIR` | 호스트 감사 fsync와 SO_PEERCRED UID; 미설정 시작 실패, 실제 UDS 위조 헤더 시험 |
| admin `ADMIN_API_AUTH_MODE/ROLES_FILE/PUBLIC_ORIGIN` | tailscale만 허용, 역할 파일 필수, Host/Origin·admin/viewer·CSRF·역할 회수 시험 |
| admin `ADMIN_API_DATA_DIR` | file storage/프로세스 잠금, jobs/bench/audit 분리 |
| admin `ADMIN_API_PROMETHEUS_URL` | 실제 고정 query/query_range 호출, 장애 N/A503. 기존 `ADMIN_API_METRICS_URL` 비어 있지 않으면 시작 거부 |
| admin `ADMIN_API_JOB_NAMESPACE/PLUGIN_NAMESPACE/E2E_NAMESPACE` | 고정 Job 대상 세 namespace 분리, Plugin hostPath/SA와 E2E 전용 namespace 시험 |
| admin `ADMIN_API_BENCH_IMAGE` | digest 필수, 실행 당시 image/source/endpoint를 run에 저장하여 관리자 업그레이드 후에도 기존 Job 계약 유지 |
| admin `ADMIN_API_INGEST_ADDR/TLS_CERT/TLS_KEY/AUDIENCE` | 사설 IP:8202/TLS, audience=kms-bench-results, 관리 route 없는 별도 listener |
| bench `--mode=transit\|plugin\|e2e` | 실제 TLS Transit 왕복, 공식 UDS RPC, Kubernetes Secret CRUD 구현 및 로컬 시험 |
| bench `--ca-file/--submit-ca-file/--submit-token-file` | 별도 TLS/토큰 파일, 매 요청 재읽기, 동일 토큰 경로 거부, 제출 실패 nonzero |
| bench `--run-id/--submit-required/--kms-socket/--namespace` | 32자리 소문자 hex ID, 제출 설정 누락 실패, plugin socket 필요, E2E namespace 고정 |
| `--submit` | origin 뒤 `/api/bench/results`로 POST. 제품 Job은 `--submit-required` 사용 |
| `/healthz`, `/readyz` | 프로세스 생존과 UDS 연결 준비 구분, sealed만으로 GUI를 죽이지 않음 |

신규 필수 env 누락 시험은 실제 server main 자식 프로세스와 admin serve 검증을 실행한다. 단순 소스 문자열 검색을 지원 증거로 삼지 않았다. 도움말은 `bench --mode=transit --help`로 새 인터페이스를 확인한다. 기존 수동 bench CLI는 보존했으며 제품 Job은 반드시 --mode를 사용한다.

HTTP: 인증 실패401, 권한 거부403, 재init/중복 키/결과 충돌409, 형식400, body 제한413, backend503, 최초 init201. 없는 자원은404이다. 이번 감사에서 남아 있던 Job/SAR/키 저장소의 backend 오류 오분류를 고쳤다. 중복 키 생성은 기존400에서409로 통일했다. 일반 키 정책 형식 위반은400이다.

## §5.2.4 — Job·결과·감사

**충족: 실제 구현과 로컬 정상·거부·장애 시험 완료. Kubernetes 제어 동작은 fake client로 검증했으며 실클러스터 판정은 별도다.**

| 요구 | 구현 및 시험 결과 |
|---|---|
| 고정 입력·상한 | basic/roundtrip 세 모드, count≤100000/concurrency≤32/payload≤1MiB/duration≤300s, deadline900s/backoff0/동시1. 임의 command/URL·초과값 거부 |
| Job 상태 | run 저장 후 생성. 생성 직후 queued, Active/StartTime 관측 후 running. succeeded/failed/timed_out 처리. 취소는 추가 중간 상태 cancelling을 영속화하고 Job 삭제·Pod 종료 확인 후 cancelled |
| 취소/재조정 | 실제 client create/get/delete 호출, UID 조건, 응답 유실·재시작 후 중복 없음. 취소 완료 미제출 upload=failed. API/저장소 장애503을 충돌409와 구분 |
| 성공 판단 | Job 완료와 유효 결과 저장 모두 필요. 결과 없음/오류 있음은 실패. count 기반 실행의 오류 없는 불완전 결과도400 거부 |
| 결과 스키마 | schema_version/run_id/mode/source_sha/image_digest/server/client version/TLS/auth/retries/요청·성공·실패/지연 분위수/UTC. unknown field 거부 후 typed 재직렬화 |
| 귀속·멱등 | TokenReview의 audience·SA·namespace·PodUID/name, 실제 Pod의 Job owner/run label 대조. Pod UID를 결과보다 먼저 영속화해 장애 복구 시 귀속 유지. 같은 hash201/다른 hash409 |
| 결과 시각 | 저장 전에 UTC로 정규화. 운영자 고정 provenance를 비교하며 원격 attestation으로 주장하지 않음 |
| 결과 제출 실패 | 별도 토큰/TLS, 실패 nonzero. 저장 실패503·TokenReview 장애503, 잘못된 audience/SA/Pod/run 거부 시험 |
| 감사 | UTC/request ID/검증 주체/고정 작업/허용·성공만 기록. 요청 body/Authorization 제외. 실제 SO_PEERCRED는 위조 헤더로 바꿀 수 없음 |
| 감사 보존 | 날짜별 파일, 30일 보존, 다음 레코드 크기를 포함해 하루8MiB 이하, 파일/부모 디렉터리 fsync. 감사 실패는 성공 응답으로 숨기지 않음 |
| PVC/노출 | 운영 데이터·Prometheus PVC 템플릿, 관리127.0.0.1:8201, ingest8202, 앱만 NodePort30443. 렌더링 시험에서 Static Pod hostPath와 RBAC/노출 경계 확인 |

의도적인 계약 구체화: basic/roundtrip만 지원하며 requests는 개별 API 호출이 아닌 왕복 작업 수다. cancelling은 “삭제 요청 접수”와 “Pod 실제 종료”를 혼동하지 않도록 추가한 중간 상태다. 수동 bench YAML 대신 관리 API가 생성하는 유일한 고정 템플릿을 사용한다. 이유와 영향 코드·시험은 config-contract와 [구현 매트릭스](implementation-matrix.md)에 기록했다.

## §5.2.5 — 스크립트·버전·개발 게이트

| 필수 파일 | 판정·로컬 검증 |
|---|---|
| `verify-release-contract.sh` | 전체 `go test ./... -count=1` + Python8개 시험, help0/잘못된 인자2. 마지막 실행 PASS |
| `test-kmsv2.sh` | 공식 client↔실제 UDS RPC, 오류·고정 벡터·회전·재시작 `-race -count=1` PASS |
| `render-release.py` | 명시 값만 치환, duplicate YAML/미치환/tag/누락 이미지·container 거부. 실제 templates 전부 렌더링 시험 PASS |
| `create-bench-fixture.sh` (+ `.py`) | 관리 session/CSRF→고정 Job 생성→완료·stored·SA/Job/Pod 귀속·결과 확인. 성공·누락·오류·timeout mock 시험 PASS. 실제 tailnet에서는 미실행 |
| `rewrite-secrets.py` | namespace/Secret pagination, conflict retry, checkpoint·재개, 기본 dry-run. mock에서 첫 변경 후 장애/재개 시 이미 완료한 Secret 건너뛰기, 무출력 PASS. 운영 Secret 미접근 |
| `verify-etcd-encryption.py` | 전달된 전체 current Secret의 지정 v2 prefix, more/count mismatch/중복/빈 목록/identity 거부. synthetic 시험 PASS. 실제 etcd 미접근 |

Go 1.26.9가 go.mod/CI/공식 builder lock에 일치하고 Docker는 GOTOOLCHAIN=local을 쓴다. Kubernetes api/apimachinery/client-go/kms는 모두 v0.35.9이며 조사된 cluster는 v1.35.9다. gRPC v1.83.2, 공식 Prometheus3.13.4와 runtime/builder digest 및 ARM64 manifest는 [base-image-lock](base-image-lock.json)에 고정했다. 원래 module/import는 유지했다.

Dockerfile은 하나이며 server/admin-api/bench와 추가 demo-app final target이 각 바이너리 하나를 받는다. 각 final target은 verify 성공 산출물에 의존한다. verify 정의에 vet/race/CGO0 ARM64/계약 스크립트가 있다. 실제 Docker build는 아직 실행하지 않았다. APT snapshot 고정까지의 비트 단위 재현성은 주장하지 않는다.

## 이번 재검토에서 실행한 결과

증거는 `evidence/contracts/`에 보존했다. 이전 §5.2.2 결과와 이번 결과를 혼동하지 않도록 별도 디렉터리를 사용한다.

| 명령 | 결과 |
|---|---|
| `go vet ./...` | PASS, 종료0 |
| `go test -race ./... -count=1` | PASS, 캐시를 사용하지 않은 전체 시험 |
| `bash scripts/verify-release-contract.sh` | PASS, 전체 Go suite + Python8개 |
| `bash scripts/test-kmsv2.sh` | PASS |
| `CGO_ENABLED=1 go test -tags=tpm_lab ./internal/seal -count=1` | PASS, simulator 전용 프로필 |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | PASS,8개 |
| CGO0/linux/arm64 네 cmd 로컬 컴파일 | PASS, 실제 ARM64 ELF 확인. 컨테이너 이미지 아님 |
| `govulncheck@v1.8.0 -show verbose ./...` | PASS, 호출 가능0/import package0/미사용 OpenPGP module 경고1 |
| `git diff --check` | PASS |

현재 최종 검사에 남은 실패는 없다. GO-2026-5932는 여전히 요구 모듈 경고이며 전체 모듈 무취약을 뜻하지 않는다. DB 온라인 조회 완료 시각과 정확한 소스·바이너리 hash는 [release-lock](release-lock.json)에 갱신했다.

## 이미지 빌드·배포 단계에서 남은 검증

- **빌드 단계:** 변경 소스 Git 기록/릴리스 SHA 확정, 실제 Docker verify 및 네 final target 빌드, 이미지 내용·ARM64·실제 product digest 검사. 현재 untracked 파일을 커밋에서 빠뜨리지 않아야 한다.
- **배포 후:** 실제 RBAC/TokenReview/Pod extras/projected token 갱신과 폐기, Job scheduling·취소·Plugin mount·E2E namespace, TLS Service 경로 및 최소권한.
- **배포 후:** Tailscale Serve 신원·Host 처리, viewer/admin·CSRF·MFA/기기 회수, 공개 관리 NodePort/Funnel 부재와 실제 외부 네트워크 경계.
- **배포 후:** PVC/Prometheus target/TSDB 및 결과·감사 재시작 보존, 운영 용량·인증서 교체, NodePort 앱/실제 브라우저 시연.
- **후속 암호화 전환:** 원본 manifest 멱등 병합, 백업 후 apiserver 연결, 실제 Secret 재쓰기/raw etcd prefix/identity 제거, 전체 재시작·운영 백업 복원. 이번에 실행하지 않았고 KMS provider만 제거하는 롤백을 제안하지 않는다.

따라서 §5.3으로 넘어가기 위한 **코드와 로컬 검증 조건은 충족**, **최종 릴리스·운영 합격 조건은 미충족/미실행**이다. 이 판정은 이미지 빌드나 배포를 자동으로 시작하라는 실행 승인을 의미하지 않는다.
