# rev2 실제 설정 계약

이 계약은 현재 작업 트리의 구현을 설명한다. 배포 완료를 뜻하지 않는다. 모든 운영 TLS/JWT/share/kubeconfig는 Git 밖에서 준비한다. 최초 시작 전에 역할 파일, 서버/ingest 인증서, SA 공개키, 전용 SAR 클라이언트 인증서와 RBAC가 필요하다.

## server

| 설정 | 기본/조건 | 구현 |
|---|---|---|
| KMS_STORAGE / KMS_DATA_DIR | file / ./data. 제품은 file만 허용 | root-confined 파일 I/O, 프로세스 flock |
| KMS_SEAL_TYPE | shamir만 허용 | 다른 seal은 라이브러리/격리 시험에 보존 |
| KMS_SHAMIR_PARTS / KMS_SHAMIR_THRESHOLD | 5 / 3, 2≤threshold≤parts≤255 | 영속 metadata 값과 다르면 시작 실패 |
| KMS_AUTO_UNSEAL | false. true 거부 | 사람의 share 입력만 허용 |
| KMS_TRANSIT_ADDR | :8200 (템플릿은 NODE_IP:8200) | HTTPS만 제공 |
| KMS_TRANSIT_TLS_CERT / KMS_TRANSIT_TLS_KEY | 필수 | TLS≥1.2, 시작 시 파일 로드 |
| KMS_ADMIN_SOCKET | /var/run/kms/admin.sock (템플릿은 별도 디렉터리) | UDS 0600, live socket/일반 파일 덮어쓰기 금지 |
| KMS_V2_SOCKET / KMS_V2_KEY_NAME | /run/custom-kms/kmsv2/kms-v2.sock / k8s-secrets | 공식 v2 UDS, 이름 `[a-zA-Z0-9_-]{1,64}` |
| KMS_AUDIT_DIR | 필수 | 실제 SO_PEERCRED UID 감사 |
| KMS_METRICS_ADDR | 127.0.0.1:9100. 명시적 빈 값은 비활성 | 운영 템플릿은 활성 |
| KMS_AUTHN / KMS_AUTHZ | on / on; 제품 main에서 off 거부 | JWT와 fail-closed SAR |
| KMS_SA_PUBLIC_KEY | /etc/kubernetes/pki/sa.pub | 로컬 공개키. 복수 경로는 기존 SplitKeyPaths 규칙 |
| KMS_SA_ISSUER / KMS_SA_AUDIENCE | 필수. 템플릿 audience=kms-system | 서명·issuer·audience·exp·subject 일치 검증 |
| KMS_KUBECONFIG | 필수 | 전용 SAR 자격증명. 파일 파싱만으로 client 구성, 부팅 시 API 접속 불필요 |
| KMS_AUTHZ_FAIL_OPEN | false, true 거부 | API 장애 시 Transit 거부, v2/호스트 unseal 독립 |
| KMS_AUTHZ_QPS / BURST / CACHE_TTL / TIMEOUT | 50 / 100 / 10초 / 3초 | 기존 라이브러리 옵션. 캐시 회수 지연 최대 TTL |

메타데이터는 `initialization.json` 한 원자적 문서에 format_version=1, store_id, parts, threshold, Root 검증 AEAD를 담는다. Root/share는 저장하지 않는다. 기존 keys가 있는데 metadata가 없으면 `migration_required:true`; init과 Shamir unseal을 거부한다. 자동 migration/reinit은 없다.

Init 응답 전 저장을 확정한다. 확정 후 응답 유실 또는 감사 완료 실패로 share를 받지 못한 경우 재발급하지 않는다. 기존 데이터를 유지하고 사건을 기록하며, 보관한 share/백업이 없다면 해당 Root는 복구할 수 없다. 자동 데이터 삭제로 해결하지 않는다. 파일 format과 KEK 포맷은 유지했다.

UDS 관리 allowlist: GET `/v1/sys/seal-status`, `/v1/keys/`, `/v1/keys/{name}`; POST `/v1/sys/init`, `/v1/sys/unseal`, `/v1/sys/seal`, `/v1/keys/`, `/v1/keys/{name}/rotate`, `/v1/keys/{name}/config`. 최초 init 201, 재init 409, 잘못된 share/Root 400, sealed/backend 503. seal-status에 initialized/migration_required 포함. 중복 키 생성은 409이며, 나머지 KeyPolicyError(이름·버전·정책 형식)는 400이다. SAR/키 저장소 backend 장애는 503으로 구분한다.

Transit: POST `/v1/encrypt/{name}`, `/v1/decrypt/{name}`, `/v1/rewrap/{name}`; 기존 GET `/v1/sys/seal-profile`. 자원 사용 GET seal-benchmark는 404. 보호 키는 Transit에서 403, 최소 복호화 버전을 1보다 높이는 변경 거부. 회전은 허용하고 모든 과거 KEK를 보존한다.

KMS v2: 공식 `k8s.io/kms/apis/v2`, Status/Encrypt/Decrypt. UID는 요청 식별자이므로 ciphertext AAD에 넣지 않는다. AAD는 프로토콜/키 ID를 묶는다. key_id=`name:version`, annotations 없음, 미지원 annotation 거부. sealed/키 없음 FailedPrecondition, 잘못된 UID/key ID/ciphertext InvalidArgument. RPC에서 JWT/SAR/Kubernetes API 호출 없음. 보호 KEK는 최초 수동 unseal 뒤 생성하고 실패 시 unseal HTTP 응답을 503으로 처리한다.

## admin-api

| 설정 | 기본/조건 |
|---|---|
| ADMIN_API_ADDR | 127.0.0.1:8201만 허용 |
| ADMIN_API_AUTH_MODE | tailscale만 허용 |
| ADMIN_API_ROLES_FILE | 필수. `{"version":1,"users":{"admin@example.test":"admin","viewer@example.test":"viewer"}}` |
| ADMIN_API_PUBLIC_ORIGIN | 필수 HTTPS origin, path/query/userinfo 없음 |
| ADMIN_API_DATA_DIR | 필수. jobs/, bench/, audit/ 분리, 단일 프로세스 flock |
| ADMIN_API_CORE_AUDIT_DIR | 호스트 server 감사 읽기 경로; 템플릿 /core-audit |
| ADMIN_API_PROMETHEUS_URL | http://127.0.0.1:9090만 허용 |
| ADMIN_API_METRICS_URL | 빈 값만 허용. 직접 scrape를 운영에 사용하지 않음 |
| ADMIN_API_JOB_NAMESPACE / PLUGIN_NAMESPACE / E2E_NAMESPACE | kms-bench / kms-bench-plugin / kms-bench-e2e; 서로 달라야 함. E2E는 고정 namespace |
| ADMIN_API_BENCH_IMAGE | 필수 `repository@sha256:64hex` |
| ADMIN_API_SOURCE_SHA / SERVER_VERSION | 필수 40hex SHA / 제한된 버전 문자열 |
| ADMIN_API_TRANSIT_URL / INGEST_URL | 필수 고정 HTTPS origin. 사용자 Job 요청으로 변경 불가 |
| ADMIN_API_INGEST_ADDR | 필수 사설 IP:8202 |
| ADMIN_API_INGEST_TLS_CERT / KEY | 필수 |
| ADMIN_API_INGEST_AUDIENCE | kms-bench-results만 허용 |
| KMS_ADMIN_SOCKET | /run/custom-kms/admin/admin.sock; 템플릿 마운트 경로로 재정의 |

Ingress 신뢰 경계는 loopback Tailscale Serve이다. 직접 외부 peer, 잘못된 Host를 거부하고 정확한 Tailscale-User-Login 값을 역할 파일에서 조회한다. host root/hostNetwork 프로세스는 신뢰 대상이며 헤더만으로 이들을 격리한다고 주장하지 않는다. 실제 Serve의 헤더 제거/재부여는 배포 후 시험한다.

역할 파일은 매 요청 다시 읽어 회수를 즉시 반영한다. GET `/api/session`은 사용자에 귀속된 30분 HMAC CSRF 토큰과 Secure/HttpOnly/SameSite=Strict cookie를 발급한다. 변경 요청은 admin, 정확한 Origin, cookie/header 일치, 서명·만료가 모두 필요하다. 재시작 시 서명키가 바뀌므로 세션 재발급이 필요하다. viewer의 쓰기 403, 신원 없음 401, 미등록 사용자 403, 정책 읽기 실패 503. 민감 응답 no-store.

관리 allowlist 외에 GET `/`, `/console`, `/dashboard`, `/api/session`, `/api/jobs`, `/api/jobs/{id}`, `/api/bench/results/{id}`, `/api/audit`, `/api/dashboard/metrics`를 제공한다. POST `/api/jobs`, DELETE `/api/jobs/{id}`는 admin+CSRF. 모든 미등록 route는 404/405. `/healthz`는 GET 생존 probe, `/readyz`는 UDS 연결 확인이며 sealed만으로 실패하지 않는다.

별도 8202에는 POST `/api/bench/results`만 존재한다. GUI route는 없다. TokenReview가 인증한 audience·SA·namespace·Pod 이름/UID와 실제 Job owner UID를 대조한다. 검증된 Pod UID를 먼저 영속화한 뒤 결과를 저장한다. 엄격한 typed JSON만 재직렬화하고 시각을 UTC로 정규화한다. 같은 결과 hash는 201, 다른 결과 409, 인증 실패 401/403, storage/API 장애 503, body>2MiB 413. 실행 성공과 결과 저장이 모두 있어야 succeeded.

## Job / bench

고정 Spec: mode=transit|plugin|e2e, scenario=basic, op=roundtrip, count=1..100000, concurrency=1..32, payload_bytes=1..1048576, duration_seconds=0..300. 동시 실행 1, Job deadline 900초, backoffLimit=0. API가 발급한 run ID와 당시 이미지/SHA/고정 endpoint 계약을 먼저 영속화한 뒤 동일 이름의 Job을 생성/재조정한다. Job 생성만으로 running으로 표시하지 않고 실제 Active/StartTime 전까지 queued를 유지한다. 취소는 cancelling을 먼저 저장하고 Job/Pod 종료를 확인하여 cancelled로 가며, 미제출 upload는 failed로 확정한다. Job 성공인데 결과가 없으면 failed. count 기반(duration=0) 실행에서 오류 없이 일부만 수행한 결과는 400으로 거부한다. 업로드 상태 pending/stored/failed는 실행 상태와 별도다. 총 10000 run 상한 도달 시 보관/정리가 필요하다.

제품 Job이 쓰는 새 CLI는 반드시 `--mode`를 지정한다. 지원 flag: `--mode`, `--scenario=basic`, `--op=roundtrip`, `--count`, `--concurrency`, `--payload-bytes`, `--duration-seconds`, `--run-id`, `--submit-required`, `--addr`, `--ca-file`, `--token-file`, `--submit`, `--submit-ca-file`, `--submit-token-file`, `--kms-socket`, `--namespace`. 토큰은 매 HTTP 요청 다시 읽고 TLS redirect를 거부한다. Plugin은 고정 UDS, E2E는 전용 namespace Secret create/get/delete와 UID 조건부 정리만 실행한다.

**의도적 인터페이스 선택:** G7의 서버 제어 Job은 `basic/roundtrip`만 허용한다. 세 계층에서 실제 복호화/읽기와 값 일치까지 검증하고 비교 지표의 의미를 통일하기 위해서다. duration은 count와 함께 상한으로 동작한다. 기존 수동 Transit CLI의 sweep/개별 op 코드는 보존했지만 제품 Job 템플릿에서 사용하지 않는다. 영향: `internal/jobs/model.go`, `cmd/bench/release.go`, `internal/adminapi/operations.html` 및 해당 tests. 예전 raw report API 대신 schema_version=1 typed 결과를 쓴다. 기존 bench CLI도 업로드 실패를 nonzero로 반환하도록 바꿨다.

결과는 run_id, mode, source_sha, image_digest, server/client version, TLS/auth, retries=0, 요청/성공/오류 수, UTC 시작/종료, 오류를 포함한 왕복 지연 p50/p95/p99를 담는다. 자유 형식 error message/평문/JWT/share는 받지 않는다. 서버/이미지 버전은 운영자가 고정한 provenance 선언이며 런타임 원격 attestation은 아니다. source SHA나 server version을 API에서 임의로 선택하지 못한다.

별도 수동 bench YAML을 적용하면 run 귀속이 없어 제출이 거부된다. 유일한 실제 Job 템플릿은 `internal/jobs/service.go`다. `scripts/create-bench-fixture.sh`는 GUI 인증/CSRF를 거쳐 동일 생성 경로를 사용하고 기본 930초 동안 완료를 기다려 stored/Job UID/Pod UID/고정 SA 및 결과를 확인한다. 실패·미제출·시간 초과는 nonzero다. 이것이 rev2의 수동 YAML fixture 대신 선택한 인터페이스이며 테스트가 동일 템플릿/권한을 검사한다.

## 관측, 감사, 독립 앱

Prometheus 질의는 서버가 정한 targets/sealed/requests/last_unseal만 허용한다. `/api/dashboard/metrics?metric=...&range=1`은 최근 15분/15초 간격 query_range다. 장애는 503/N/A이며 0으로 대체하지 않는다. last_unseal은 scrape 시각이 아닌 실제 barrier 이벤트다. 전체 Transit 상태 코드 metric이 sealed/401/403/5xx를 포함한다. 기존 메모리 scraper/업로드 저장기는 production entrypoint에 연결하지 않는다.

감사는 UTC/request ID/주체/고정 작업/허용/성공만 기록한다. 요청/완료를 fsync하고 완료 기록 실패는 503으로 반환한다(작업은 이미 commit됐을 수 있으므로 재조회 필요). 다음 레코드 크기까지 포함하는 하루 8MiB 상한, 30일 보존, 날짜별 파일 회전. 파일과 부모 디렉터리를 fsync한다. GET health/ready probe는 감사 용량에 포함하지 않는다. 최근 당일 1000개씩 GUI/호스트 이벤트를 읽는다. 결과 ingest 감사에는 인증된 SA를 기록하고, 제출 Pod UID는 영속 run 레코드에 기록한다. 정상 로그에도 request body/Authorization을 쓰지 않는다.

독립 `demo-app`은 :8443 HTTPS만 제공하며 NodePort 30443 템플릿이다. 필수 env: DEMO_TRANSIT_URL, DEMO_CA_FILE, DEMO_TOKEN_FILE, DEMO_PUBLIC_ORIGIN, DEMO_TLS_CERT, DEMO_TLS_KEY. 서버가 고정 demo 키로 Transit을 호출하고 토큰은 브라우저에 전달하지 않는다. 동일 Origin/X-Demo-Request를 검사한다. `/encrypt`, `/decrypt`, `/`, GET `/healthz`, `/readyz`. 평문/토큰을 localStorage/sessionStorage에 보존하지 않고 pagehide에 지운다. 사람의 접근 허가는 tailnet/호스트 방화벽으로 제한하며 공인 NodePort 접근 통제는 배포 후 검증 대상이다.

## 갱신·회수·운영 파일

TLS 서버 인증서/SA 검증 공개키/SAR client 인증서는 시작 시 로드하므로 파일 교체 후 계획된 재시작과 수동 unseal이 필요하다. TLS hot reload나 CRL/OCSP를 구현했다고 주장하지 않는다. 인증서 만료 시 연결이 실패하며 CA 교체에는 중복 신뢰 기간이 필요하다. Transit JWT 검증은 오프라인이므로 개별 토큰 회수는 JWT expiry와 SAR 정책/캐시 TTL에 제한된다. ingest는 매 요청 TokenReview를 수행한다. 역할은 매 요청 reload한다.

`templates/`는 미적용 산출물이다. renderer는 명시 키만 치환하며 duplicate YAML/image tag/미치환 입력/기존 출력 덮어쓰기를 거부한다. build definition의 server/admin-api/bench는 서로 다른 final target이고 demo-app은 추가 target이다. 공식 image digest는 base-image-lock.json을 사용한다. verify stage의 APT 패키지 저장소는 snapshot 고정이 아니므로 bit-for-bit 재현을 주장하지 않는다.

필수 스크립트 exit: verify-release-contract/test-kmsv2는 실패 nonzero, renderer는 잘못된 입력 2, fixture/etcd/rewrite 처리 실패 1(잘못된 CLI 사용은 argparse의 2). rewrite-secrets는 기본 dry-run이며 `--execute --backup-id ... --resume ...`를 나중에만 사용한다. 실제 Secret/apiserver 변경은 이번 작업에서 실행하지 않았다. encryption-config 템플릿의 identity는 최초 전환용이며 raw 전체 Secret 검증 뒤 제거하는 단계가 별도로 남는다. 암호문이 남은 상태에서 KMS만 제거하는 롤백은 금지한다.

2026-10-11 §5.2.3–§5.2.5 재검토: [충족 여부와 빌드 준비 판단](contract-readiness.md). Job GET/DELETE의 잘못된 ID 400·없는 run 404·상태 충돌 409·backend 장애 503을 구분한다. Ingest는 없는 run을 403으로 숨기되 저장소 장애는 503이다. CLI `--mode=... --help`는 0, 불필요한 위치 인자와 비16진수 run ID는 실패한다. 검증 shell 스크립트 `--help`는 0, 알 수 없는 인자는 2다.
