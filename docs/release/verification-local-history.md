# 로컬 검증 실행 기록

아래는 최초 G1–G10 구현 시 기록이다. 이후 계약 보완 및 캐시 없는 전체 재검증 결과는 [§5.2.3–§5.2.5 재검토](contract-readiness.md)가 최신이며, 최신 증거는 `evidence/contracts/`에 있다.

실행일: 2026-10-11 UTC. 기준 HEAD `34a37352b64c9028c431d523941c517f165feb67`, branch `infra/oci-single-node`. 현재 변경은 미커밋이며 릴리스 SHA가 아니다. 테스트한 소스 파일 목록/해시는 [source-manifest.sha256](evidence/source-manifest.sha256), 기준 상태는 [baseline](baseline.md)에 있다.

호스트는 실제 linux/arm64다. `PATH=/home/ubuntu/kms-tools/go/bin:$PATH`의 공식 Go 1.26.9를 사용했다. 컨테이너를 실행하거나 클러스터에 적용하지 않았다. 테스트용 임시 디렉터리, loopback TLS/UDS, 가짜 Kubernetes client를 사용했다. 테스트 fixture 초기화는 운영 KMS 초기화와 구분한다.

## 실제 실행 결과

| 실행 명령/검사 | 최종 결과 | 범위와 증거 |
|---|---|---|
| `go vet ./...` | PASS | 종료 0, [vet.log](evidence/vet.log) |
| `go test -race ./...` | PASS | 모든 package 성공 또는 no test files. 변경되지 않은 package의 Go 캐시 결과 포함. [race.log](evidence/race.log) |
| `bash scripts/test-kmsv2.sh` | PASS | 공식 RPC/회전/재시작/고정 벡터, `-race -count=1`. [kmsv2.log](evidence/kmsv2.log) |
| `go test -race ./cmd/server ./internal/jobs ./internal/kmsv2` | PASS | API 부재 실제 main 기동, 잘못된 run/저장 실패와 마지막 v2 시험. [last-tests.log](evidence/last-tests.log) |
| `go test -race ./internal/adminapi -count=1` | PASS | 마지막 proxy 503·Prometheus range/오류 시험. 뒤 전체 race/계약 검사에도 포함 |
| `go test -race ./internal/metrics -count=1` | PASS | 마지막 추가 시험: 실제 Prometheus gather에서 200/401/403/503/500 보존·집계, 고정 라벨 확인. [http-metrics.log](evidence/http-metrics.log) |
| `bash scripts/verify-release-contract.sh` | PASS | 실제 7개 package의 handler/config/CLI 시험 `-count=1` + Python 5개 시험. [contract.log](evidence/contract.log) |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | PASS (5 tests) | template 보안 경계/변수 이름, 미치환·중복·tag 거부, synthetic raw etcd prefix, mocked pagination/conflict/resume, fixture 완료·귀속·실패·timeout |
| `bash -n scripts/create-bench-fixture.sh scripts/test-kmsv2.sh scripts/verify-release-contract.sh` | PASS | shell 구문 확인. 실제 tailnet Job fixture는 실행하지 않음 |
| `CGO_ENABLED=1 go test -tags=tpm_lab ./internal/seal` | PASS | 격리 simulator 프로필. 물리 TPM 보증 아님. [tpm-lab.log](evidence/tpm-lab.log) |
| `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/kms-local-bins/<name> ./cmd/<name>` (server/admin-api/bench/demo-app) | PASS | 4개 실제 ARM64 ELF. 마지막 proxy 변경 후 admin-api 재빌드. [arm64-file.log](evidence/arm64-file.log), [arm64-sha256.log](evidence/arm64-sha256.log) |
| `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -show verbose ./...` | PASS, module 경고 1개 | 종료 0. 호출 가능 0, import package 0, 미사용 OpenPGP module 경고 1. 마지막 코드 수정 후 온라인 Go DB 조회. [govulncheck.log](evidence/govulncheck.log) |
| `git diff --check` | PASS | 공백 오류 없음 |
| control-plane manifest 4개 SHA256 재조회 | PASS (불변) | baseline 값과 동일. apiserver/etcd/control-manager/scheduler 내용을 변경하지 않음 |

PASS는 그 명령이 확인한 범위만 뜻한다. fake Kubernetes client는 admission/RBAC/token 실제 발급·폐기를 수행하지 않는다. `cmd/demo-app` 자체는 no test files이고 앱 동작 시험은 `internal/demo`에 있다. `tpm_lab`은 기본 suite에서 제외되지만 별도로 실제 실행했다.

## 실패를 수정한 내역

- 최초 의존성 검사에서 gRPC/x/net의 호출 가능한 취약점이 발견되어 gRPC v1.83.2/x/net v0.60.0 및 관련 모듈을 갱신했다. 재검사에서 호출 가능 취약점 0건이다. GO-2026-5932 OpenPGP는 import/call하지 않지만 요구 모듈 경고가 남는다.
- 보안 기본값/폐기된 benchmark route/업로드 실패 nonzero 계약과 맞지 않는 기존 시험은 새 요구에 맞춰 수정하고 재실행했다. 인증 off/fail-open 라이브러리 시험은 유지하되 production main은 해당 설정을 거부한다.
- 최종 템플릿 감사에서 issuer 환경변수 이름에 잘못 들어간 치환식을 발견해 `KMS_SA_ISSUER`로 수정했다. 렌더링 시험은 실제 issuer 값과 authn/authz/auto-unseal/fail-open 계약까지 확인한다.
- UDS 프록시 연결 실패의 기본 502를 rev2 backend 장애 계약에 맞춰 503으로 고치고 시험을 갱신했다.
- 새 fixture 시험의 Python Request 메서드 검사 오류를 `get_method()`로 수정했다. 5개 Python 시험은 최종 모두 통과했다.
- 작업 중 컴파일러가 파일을 읽는 시점의 일시적인 import 빌드 오류는 종료 후 재빌드로 해소되었다. 마지막 vet/race/ARM64 빌드는 성공했다.

현재 마지막으로 실행한 검사에 남은 실패는 없다. 이는 아래 미실행 항목이 성공했다는 뜻이 아니다.

## 실행하지 않은 항목

- Dockerfile verify/final target의 **컨테이너 이미지 빌드**, 이미지 pull/import/push, 제품 digest 생성, CI 서비스 실행.
- Kubernetes manifest apply/server-side dry-run, 실제 Job create/cancel/TokenReview, RBAC 최소권한·Plugin mount·E2E namespace 시험.
- 실제 Tailscale Serve/MFA/device 회수/외부 방화벽·OCI NSG/Security List 시험. 이 호스트 조사에서 Tailscale CLI/활성 서비스를 확인할 수 없었고 OCI CLI도 없었다.
- 운영 init/unseal, 실제 인증서·CA 교체/회수, 운영 projected JWT 갱신. 로컬 TLS 교체·만료와 역할/파일 토큰 회수만 시험했다.
- 운영 PVC/Prometheus TSDB 재시작, 물리 disk-full/read-only/전원 차단, 외부 백업 및 etcd snapshot 복원.
- kube-apiserver KMS 연결·원본 manifest 병합, 기존 Secret 재쓰기, **실제** raw etcd prefix 검증, identity 제거, 전체 호스트 재시작.
- 실제 브라우저 자동화/NodePort 데모 시연. 단위 HTTP 시험과 ARM64 앱 바이너리 빌드만 실행했다.

## 버전·릴리스 근거

선택: Go 1.26.9, 실제 cluster v1.35.9와 Kubernetes 모듈 v0.35.9, gRPC v1.83.2, Prometheus 공식 LTS 3.13.4. 공식 image index/digest와 ARM64 manifest를 조회하여 [base-image-lock.json](base-image-lock.json)에 고정했다. 제품 이미지 digest와 release SHA는 [release-lock.json](release-lock.json)에서 `null`이다. runtime의 dated tag 조회 실패 후 bookworm-slim을 한 번 resolve하여 digest로 고정한 사실도 기록했다.

확인한 공식 자료: [Go 릴리스 기록](https://go.dev/doc/devel/release), [Kubernetes patch/support 기록](https://kubernetes.io/releases/patch-releases/), [Prometheus 다운로드](https://prometheus.io/download/), [KMS provider v2](https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/), [잔여 OpenPGP 모듈 경고](https://pkg.go.dev/vuln/GO-2026-5932).

인증서/개인키/JWT/share/kubeconfig/운영 Secret data는 이 증거 디렉터리에 넣지 않았다. evidence에는 package 시험 결과·버전 검사·바이너리 및 소스 해시만 포함한다.
