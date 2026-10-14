# G1–G10 구현 및 로컬 검증 결과

기준: rev2 §5.2.2. §5.2.3–5.2.5를 설정·데이터·시험 계약으로 사용했다. **아래 구현 완료는 현재 미커밋 소스와 로컬 시험의 완료이며, 운영 배포 합격이나 최종 릴리스를 뜻하지 않는다.** 각 시험은 [실행 기록](verification.md)의 실제 명령에 포함된다. 원본 guide와 개인 origin/branch는 보존했다.

시작 시 있던 것은 Transit/envelope, Shamir 알고리즘, UDS 관리, JWT/SAR 라이브러리, scheduler, 직접 scrape dashboard 및 수동 Transit CLI였다. 아래 항목을 추가·수정했다. 시작 상태는 [baseline](baseline.md), 실제 인터페이스는 [config-contract](config-contract.md), 남은 운영 제약은 [limitations](limitations.md)에 기록했다.

## G1 — 초기화 metadata와 Root 검증

- **구현 완료 여부:** 로컬 구현 완료. format/store ID/parts/threshold와 Root 검증 AEAD를 하나의 원자적 문서로 확정한 뒤 share를 반환한다. 재init은 409, 잘못된 Root는 sealed 유지. Root/share 원문은 저장하지 않는다.
- **수정 파일:** `internal/barrier/initialization.go`, `barrier.go`; `internal/seal/shamir.go`; `internal/api/admin/admin.go`. 중복 share 좌표·오염·다른 초기화 세트 검증, initialized/migration_required 상태와 기존 데이터 재초기화 차단을 추가했다.
- **실행한 시험 / 결과:** `TestInitializationRestartWrongRootAndRestore`, `TestConcurrentInitializationAndLegacyRefusal`, `TestBackupRestoreIntoSeparateDirectory` 및 관리 lifecycle 시험 **PASS**. 12개 동시 init 중 하나만 성공, 잘못된 세트/중복/변조 거부, 별도 디렉터리에 복원한 이전 암호문 복호화를 확인했다. 테스트 fixture에서만 init했다.
- **배포 후 검증:** 사용자가 직접 share를 입력하는 운영 init/unseal, 호스트 재부팅 후 동일 metadata·share 복구, 실제 오프호스트 백업 복원.
- **남은 작업:** 운영 복구 시연. metadata 없는 구형 저장소는 안전하게 migration-required로 거부하며 자동 변환 도구는 제공하지 않는다. init 응답 유실 시 share 재발급 없이 보존·조사한다([복구 정책](recovery.md)).

## G2 — 원자적 저장과 동시성

- **구현 완료 여부:** 로컬 구현 완료. 같은 디렉터리 임시 파일→fsync→rename→부모 디렉터리 fsync, 0700/0600, 프로세스 flock과 키별 전체 RMW 잠금을 적용했다.
- **수정 파일:** `internal/storage/file.go`, `durability_test.go`; `internal/keys/manager.go`, `concurrency_test.go`. os.Root 경로 제한, symlink/탈출 거부, 살아 있는 잠금 파일 유지, Create/Rotate/Config 경합 보호를 추가했다.
- **실행한 시험 / 결과:** `TestAtomicFaultsPreserveCommittedValue`, `TestLockSymlinkAndTraversal`, `TestKilledWriter`, `TestConcurrentCreateRotateConfig` **PASS**, race **PASS**. 실제 테스트 자식 프로세스 SIGKILL, 두 번째 저장소 열기 거부, 각 저장 단계의 ENOSPC/EROFS 오류 주입, 동시 생성·40회 회전/config 갱신을 검증했다. rename 후 dir-fsync 실패는 새 값이 보일 수 있으나 오류를 숨기지 않는다.
- **배포 후 검증:** 운영 파일시스템의 용량·권한·실제 I/O 장애, 컨테이너 중복 writer 거부, OCI 전원 장애/볼륨 복원.
- **남은 작업:** 실제 disk-full/read-only 운영 장애 훈련. 로컬 오류 주입은 물리 디스크 장애 시험의 대체 증거가 아니다.

## G3 — 수동 unseal 이후 scheduler

- **구현 완료 여부:** 로컬 구현 완료. 수동 unseal→Root 검증→전용 KEK 준비 성공 후 scheduler를 한 번 시작한다. 준비 실패는 reseal/503, seal·종료는 scheduler 중단이다.
- **수정 파일:** `cmd/server/main.go`; `internal/api/admin/admin.go`, `lifecycle_test.go`; `internal/rotation/scheduler.go`; `internal/barrier/barrier.go`; `internal/metrics/collector.go`.
- **실행한 시험 / 결과:** `TestManualUnsealStartsRotationAndSealStops` **PASS**. 실제 HTTP share 제출 후 빠른 scheduler 회전, 반복 unseal 시 단일 실행, 이전 암호문 복호화, seal 후 중단을 확인했다. G1 시험에서 중복 unseal이 last-unseal 시각을 바꾸지 않는 것도 확인했다. 전체 race **PASS**.
- **배포 후 검증:** Static Pod 재시작/호스트 재부팅 후 수동 unseal·운영 주기 회전, Prometheus의 실제 last-unseal 값.
- **남은 작업:** 운영 복구 시연과 실제 주기 관찰. 제품 main의 auto-unseal은 거부한다.

## G4 — Transit TLS + JWT/SAR

- **구현 완료 여부:** 로컬 구현 완료. TLS≥1.2/인증서 필수, JWT issuer/audience/exp/subject 검증과 fail-closed SAR를 기본으로 강제한다. listener보다 인증 설정 검증을 먼저 수행한다.
- **수정 파일:** `cmd/server/main.go`, `offline_test.go`, 관련 server tests; `internal/security/http.go`, `http_test.go`; `internal/authn/{claims,middleware,verifier}.go`; `internal/api/transit/transit.go`; `internal/api/httputil/httputil.go`. body 2MiB 제한·서버 timeout·토큰 재읽기·redirect 거부와 socket 보존을 구현했다. 자원 소모 seal benchmark는 제품 route에서 제거하고 TPM simulator는 `tpm_lab`로 분리했다.
- **실행한 시험 / 결과:** `TestTLSVerificationAndRenewal`, `TestBodyLimitAndRotatedToken` **PASS**: 올바른 CA, 잘못된 SAN, 만료/불신, 교체 인증서, 토큰 교체/누락, 413. 기존 authn/authz/Transit 정상·401·403·SAR 장애 시험 **PASS**. `TestServerBootWithoutKubernetesAPI` **PASS**: 임시 host 파일만으로 실제 main 자식 프로세스 기동, API 불가 상태 UDS 접근·sealed v2 응답·SIGTERM 종료. live socket/일반 파일 보존 시험 **PASS**.
- **배포 후 검증:** 실제 kube-apiserver SA issuer/공개키/SAR 인증서·Role, projected JWT 갱신, 실제 TLS 핸드셰이크와 네트워크 경계.
- **남은 작업:** 인증서·SA 키 교체 및 회수 운영 시연. 파일 교체는 계획된 재시작이 필요하다. hot reload/CRL/OCSP/개별 Transit JWT 즉시 회수는 구현 범위에 포함하지 않았다.

## G5 — 공식 Kubernetes KMS v2

- **구현 완료 여부:** 로컬 구현 완료. 공식 v2 gRPC의 Status/Encrypt/Decrypt, 독립 UDS, 보호 KEK, key ID/AAD, 오류 계약을 구현했다. RPC 내부에 SAR/JWT/Kubernetes 호출이 없다.
- **수정 파일:** `internal/kmsv2/service.go`, `service_test.go`; `cmd/server/main.go`; `internal/keys/manager.go`; `scripts/test-kmsv2.sh`. UID는 요청 식별자로 처리하고 ciphertext AAD에 넣지 않는다. 보호 키의 과거 복호화 버전 삭제를 막는다.
- **실행한 시험 / 결과:** `TestOfficialRPCSealRotationRestart`, `TestDecryptFixedVector` 및 `scripts/test-kmsv2.sh` **PASS**. 공식 client↔실제 UDS, 서로 다른 encrypt/decrypt UID, sealed 오류, 잘못된 key ID/변조/annotation, 회전 경합, 새 서비스·저장소 객체에서 과거 복호화, 독립 AES-GCM 고정 벡터/변조를 확인했다. API 부재 main 부팅 시험 **PASS**.
- **배포 후 검증:** 실제 apiserver v2 연결, 백업 후 Secret 재쓰기·raw etcd prefix, identity 제거, 전체 재시작 복구.
- **남은 작업:** §12의 배포 검증 전체. 원본 manifest의 멱등 병합 도구도 이후 연결 단계에서 구현해야 한다. 이번에는 apiserver를 변경하지 않았다.

## G6 — Tailscale 관리 신원·역할·CSRF

- **구현 완료 여부:** 로컬 구현 완료. 관리 listener는 host `127.0.0.1:8201`, 명시된 Tailscale 신원과 admin/viewer, Host/Origin/CSRF, 명시 method/path allowlist를 적용했다.
- **수정 파일:** `internal/adminapi/{security,router,proxy}.go`, `security_test.go`; `cmd/admin-api/main.go`, `main_test.go`; `internal/api/console/console.html`. 역할 매 요청 reload, 사용자 귀속 HMAC CSRF와 Secure/HttpOnly/SameSite cookie, no-store, UDS backend 장애 503을 추가했다.
- **실행한 시험 / 결과:** `TestIdentityCSRFRoleRevocationAndAllowlist`, `TestServeFailsClosedOnMissingContract` 및 기존 router/proxy tests **PASS**. viewer 쓰기403, 신원없음401, 외부 peer/잘못된 Host/Origin403, 허용 viewer 읽기, 정상 CSRF의 backend 도달, 역할 회수, 정책 손상503, 미등록 route404.
- **배포 후 검증:** 실제 Tailscale Serve 헤더 제거/주입, tailnet 접근/MFA·기기 회수, 외부 IPv4/IPv6 차단, NodePort/Funnel 없는 관리 경계.
- **남은 작업:** 이 호스트에서 Tailscale CLI/서비스를 사용할 수 없어 실제 연결은 미검증. 로그인/MFA는 사용자가 직접 수행한다. host root/hostNetwork 프로세스 신뢰는 별도 경계다.

## G7 — 실제 Job 제어와 세 가지 벤치 모드

- **구현 완료 여부:** 로컬 구현 완료. 고정 템플릿으로 Kubernetes Job create/get/delete 및 재조정 코드를 구현했다. Job API를 fake client로 실행해 검증했고 실제 클러스터 Job은 생성하지 않았다.
- **수정 파일:** `internal/jobs/{model,service}.go`, `service_test.go`; `cmd/bench/release.go`, `release_test.go`, `main.go`; `internal/adminapi/operations.html`; `scripts/create-bench-fixture.{sh,py}`; `deploy/oci-single-node/templates/serviceaccounts-rbac.yaml`.
- **실행한 시험 / 결과:** `TestFixedTemplateReconcileCancelTimeout`, `TestCreateResponseLostAdoptsExistingJob`, `TestRunningJobKeepsRecordedImageAcrossAdminUpgrade` **PASS**. 재시작/응답 유실 후 중복 없음, 취소·deadline, mode별 mount/SA/namespace, 임의 command/URL·상한 위반 거부. `TestReleaseBenchThreeModesAndFailures` **PASS**: 실제 로컬 TLS Transit/UDS plugin 왕복과 실패, fake E2E Secret CRUD/거부/정리. Python fixture의 완료/귀속/실패/시간 초과 시험 **PASS**.
- **배포 후 검증:** 실제 Job scheduling/Pod 수명·취소, Plugin UDS 권한, E2E namespace RBAC, 900초 deadline, 세 모드 실제 부하와 제출.
- **남은 작업:** 클러스터 시험. 지원하는 제품 조합은 `basic/roundtrip`이며 raw 호출이 아닌 왕복 수를 requests로 집계한다. 이 선택의 이유·영향 파일은 config-contract에 기록했다. 수동 YAML 대신 단일 코드 템플릿을 사용한다.

## G8 — 별도 TLS 결과 ingest와 귀속

- **구현 완료 여부:** 로컬 구현 완료. 사설 IP:8202 TLS에는 결과 POST만 등록한다. 별도 audience 토큰의 TokenReview와 run/SA/namespace/Pod UID/Job owner를 대조하며 typed 결과만 저장한다.
- **수정 파일:** `internal/jobs/{model,service}.go`, `service_test.go`; `cmd/admin-api/main.go`; `cmd/bench/{release,main}.go` 및 tests; `internal/security/http.go`; `deploy/oci-single-node/templates/ingest-service.yaml`.
- **실행한 시험 / 결과:** `TestIngestBindingIdempotenceAndRecovery`, `TestJobCompleteWithoutUploadFails`, bench 제출 시험 **PASS**. 잘못된 audience/SA/Pod UID/run 거부, TokenReview 장애503, 저장 실패503, 같은 결과 멱등201/다른 결과409, 메타데이터 복구, 제출 없는 Job 성공은 failed, 제출 실패 CLI nonzero를 확인했다. fixture 스크립트도 저장·귀속·완전한 결과 없이는 성공하지 않는다.
- **배포 후 검증:** 실제 projected audience JWT/Pod extras/만료·삭제 회수, ingest 인증서와 Service 경로, Pod 종료 직전 업로드/재시도.
- **남은 작업:** 실제 TokenReview 및 TLS ingest 연동. 관리 토큰/Transit 토큰과 결과 제출 토큰을 공유하지 않는다.

## G9 — Prometheus, 영속 운영 데이터, 감사

- **구현 완료 여부:** 로컬 구현 완료, PVC/Prometheus는 미적용 템플릿까지 준비. 고정 PromQL query/query_range, 실제 last-unseal·HTTP 상태 지표, 영속 jobs/bench/audit, SO_PEERCRED 및 검증 신원 감사가 구현됐다.
- **수정 파일:** `internal/adminapi/operations.go`, `operations.html`, `router.go`, `security_test.go`; `internal/audit/audit.go`, `audit_test.go`; `internal/metrics/{http,collector}.go`; 두 main; `deploy/oci-single-node/templates/{storage,prometheus,admin-deployment}.yaml`.
- **실행한 시험 / 결과:** `TestPrometheusUnavailableIsNotZero`, `TestPrometheusRangeAllowlistAndMalformedResponse` **PASS**: 실제 로컬 HTTP query/range와 고정식, 미허용식400, 장애/오류 N/A503. `TestPersistentAuditCapacityRetention`, `TestAuditCompletionFailureDoesNotReportSuccess` **PASS**: 파일 재개·30일 보존·용량 제한·감사 완료 실패503. `TestAllHTTPIncludesAuthenticationSealedAndBackendFailures`에서 Prometheus 200/401/403/503/500 집계 및 고정 라벨 **PASS**. 기존 metrics 및 Python PVC/노출 경계 시험 **PASS**.
- **배포 후 검증:** Prometheus target up·실제 시계열, 운영 PVC 바인딩/Pod 재시작 후 보존, 감사/TSDB 저장 용량, 실제 비밀정보 무출력 점검.
- **남은 작업:** 운영 관측·PVC 복구 시험. local PV 선언은 실제 quota가 아니다. 감사 완료 실패 응답은 이미 commit된 작업까지 되돌린다는 의미가 아니다.

## G10 — 독립 demo-app

- **구현 완료 여부:** 로컬 구현 완료. 독립 main과 image target, HTTPS 8443/앱 NodePort30443 템플릿, 고정 키 서버 측 Transit 호출, 브라우저 토큰 비노출을 구현했다.
- **수정 파일:** `cmd/demo-app/main.go`; `internal/demo/demo.go`, `demo_test.go`; `deploy/oci-single-node/Dockerfile`, `templates/demo-app.yaml`.
- **실행한 시험 / 결과:** `TestFixedKeyRoundtripDenialAndNoBrowserToken` **PASS**: 암복호화·권한 거부·backend 장애·Origin 거부·HTML 토큰 비노출. 공통 TLS 신뢰/만료/SAN 시험 **PASS**. 실제 `linux/arm64`, CGO=0 바이너리 빌드 **PASS**. 브라우저 자동화는 실행하지 않았다.
- **배포 후 검증:** 앱 NodePort HTTPS·인증서 SAN, app-a/app-denied 실제 RBAC, 브라우저 새로고침/종료 후 비밀 보존 여부, 외부 노출 경계.
- **남은 작업:** 운영 UI/네트워크 시연. 일반 앱과 관리 UI의 인증·권한 경계는 분리되어 있다.

## 공통 산출물과 제외 범위

`go.mod`, `go.sum`, CI와 Dockerfile을 Go 1.26.9/Kubernetes module v0.35.9로 정렬했다. 취약점 검사로 발견한 gRPC/x/net 도달 가능 취약점을 수정했고 최종 결과는 도달 가능 0건, 미사용 OpenPGP 모듈 경고 1건이다. 공식 Go/runtime/Prometheus 이미지 digest와 ARM64 manifest 존재를 조회해 고정했다. 제품 이미지는 **미빌드**, digest/릴리스 SHA는 **없음**이다.

필수 6개 스크립트, config-contract, 복구 정책, 렌더링 입력 예시와 템플릿을 제공했다. Python 시험은 실제 Secret을 읽지 않고 synthetic/mocked 입력만 사용한다. 이미지 빌드·배포·운영 init·apiserver 변경·Secret 재쓰기·raw 운영 etcd 검사·identity 제거·운영 재부팅은 실행하지 않았다.
