#!/usr/bin/env bash
# verify-main.sh — main 브랜치 최종 점검 (git 상태 + 빌드·테스트 + 실제 기동 스모크 테스트)
#
# 사용법: 레포 루트에서  bash scripts/verify-main.sh
# 사전 조건: 포트 8200, 8201, 9100이 비어 있을 것 (띄워둔 서버는 먼저 종료)
# kind 클러스터는 필요 없음 (인증·인가 off 상태로 기본 동작만 확인)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SOCK="$HOME/.kms-verify.sock"
PASS=0; FAIL=0; PIDS=()

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
ng()   { printf '  \033[31m✖\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m[%s]\033[0m\n' "$*"; }
check(){ local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else ng "$name"; fi; }

cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$WORK" "$SOCK"
}
trap cleanup EXIT

cd "$REPO"

# -----------------------------------------------------------------------------
step "1. git 상태"
git fetch --prune -q
check "현재 브랜치가 main"            test "$(git branch --show-current)" = main
check "커밋 안 된 변경 없음"          test -z "$(git status --porcelain)"
check "origin/main과 같은 커밋"       test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
check "로컬 브랜치는 main 하나"       test "$(git branch --format='%(refname:short)' | wc -l)" -eq 1
echo "    원격 브랜치: $(git branch -r --format='%(refname:short)' | grep -v HEAD | tr '\n' ' ')"

# -----------------------------------------------------------------------------
step "2. 주요 파일"
for f in cmd/server/main.go cmd/admin-api/main.go cmd/bench/main.go \
         internal/authn/verifier.go internal/authz/client.go internal/metrics/metrics.go \
         internal/dashboard/service.go \
         scripts/bench-access-control.sh scripts/plot-bench.py \
         docs/architecture.md docs/decisions.md docs/usage.md docs/verification.md docs/benchmark.md; do
  check "$f" test -f "$f"
done
check "ADR-008 (속도 제한) 기록"        grep -q "ADR-008" docs/decisions.md
check "README에 대시보드 절"            grep -qi "dashboard\|대시보드" README.md

# -----------------------------------------------------------------------------
step "3. 빌드·검사·테스트 (-race 포함, 1~2분)"
check "go build ./..."   go build ./...
check "go vet ./..."     go vet ./...
if go test -race -count=1 ./... >"$WORK/test.log" 2>&1; then ok "go test -race ./..."
else ng "go test -race ./... (실패 내용: 아래)"; grep -E "^(--- FAIL|FAIL|panic)" "$WORK/test.log" | head -20; fi

# -----------------------------------------------------------------------------
step "4. 실제 기동 스모크 테스트"
for port in 8200 8201 9100; do
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/"; then
    ng "포트 $port 사용 중 — 띄워둔 서버를 종료하고 다시 실행하세요"
    echo; echo "결과: 통과 $PASS / 실패 $FAIL"; exit 1
  fi
done

go build -o "$WORK/kms-server" ./cmd/server && go build -o "$WORK/admin-api" ./cmd/admin-api \
  && go build -o "$WORK/kms-bench" ./cmd/bench || { ng "바이너리 빌드 실패"; exit 1; }

rm -f "$SOCK"
env -i PATH="$PATH" HOME="$HOME" KMS_SEAL_TYPE=dev KMS_MASTER_KEY=verify KMS_STORAGE=memory \
  KMS_ADMIN_SOCKET="$SOCK" "$WORK/kms-server" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do [[ -S "$SOCK" ]] && break; sleep 0.25; done
check "KMS 서버 기동 (admin.sock 생성)"   test -S "$SOCK"

env -i PATH="$PATH" HOME="$HOME" KMS_ADMIN_SOCKET="$SOCK" ADMIN_API_BENCH_DIR="$WORK/bench" \
  "$WORK/admin-api" >"$WORK/admin.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do curl -sf -o /dev/null http://127.0.0.1:8201/healthz && break; sleep 0.25; done
check "관리 API 기동 (/healthz)"          curl -sf -o /dev/null http://127.0.0.1:8201/healthz
check "관리 API → KMS 연결 (/readyz)"     curl -sf -o /dev/null http://127.0.0.1:8201/readyz

# sealed 상태에서는 암호화가 거부되어야 함
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST http://127.0.0.1:8200/v1/encrypt/x \
  -H 'content-type: application/json' -d '{"plaintext":"aGk="}')
check "sealed 상태에서 암호화 거부 ($code)"   test "$code" != 200

curl -s --unix-socket "$SOCK" -XPOST http://localhost/v1/sys/unseal >/dev/null
check "unseal"   bash -c "curl -s --unix-socket '$SOCK' http://localhost/v1/sys/seal-status | grep -q '\"sealed\":false'"
curl -s -XPOST http://127.0.0.1:8201/v1/keys -H 'content-type: application/json' -d '{"name":"verify"}' >/dev/null
check "관리 API로 키 생성"   bash -c "curl -s http://127.0.0.1:8201/v1/keys | grep -q verify"

PT=$(printf 'final check' | base64)
CT=$(curl -s -XPOST http://127.0.0.1:8200/v1/encrypt/verify -H 'content-type: application/json' \
       -d "{\"plaintext\":\"$PT\"}" | grep -o 'kms:v[0-9]*:[^"]*')
check "암호화 → kms:v1: 포맷"   bash -c "[[ '$CT' == kms:v1:* ]]"
check "복호화 → 원문 복원"      bash -c "curl -s -XPOST http://127.0.0.1:8200/v1/decrypt/verify \
  -H 'content-type: application/json' -d '{\"ciphertext\":\"$CT\"}' | grep -q '$PT'"

curl -s --unix-socket "$SOCK" -XPOST http://localhost/v1/keys/verify/rotate >/dev/null
check "회전 후에도 v1 암호문 복호화" bash -c "curl -s -XPOST http://127.0.0.1:8200/v1/decrypt/verify \
  -H 'content-type: application/json' -d '{\"ciphertext\":\"$CT\"}' | grep -q '$PT'"
check "rewrap → kms:v2:"   bash -c "curl -s -XPOST http://127.0.0.1:8200/v1/rewrap/verify \
  -H 'content-type: application/json' -d '{\"ciphertext\":\"$CT\"}' | grep -q 'kms:v2:'"

code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST http://127.0.0.1:8200/v1/keys \
  -H 'content-type: application/json' -d '{"name":"hack"}')
check "Transit(8200)으로 키 생성 불가 ($code)"   test "$code" = 404

check "메트릭(:9100) 응답"            bash -c "curl -s http://127.0.0.1:9100/metrics | grep -q kms_transit_requests_total"
check "메트릭에 키 이름 없음"         bash -c "! curl -s http://127.0.0.1:9100/metrics | grep -q verify"

"$WORK/kms-bench" --key verify --op encrypt --count 200 --warmup 10 \
  --submit http://127.0.0.1:8201 >"$WORK/bench.log" 2>&1
check "bench 실행 + 대시보드로 제출"  bash -c "curl -s http://127.0.0.1:8201/api/bench/results | grep -q '\"id\"'"
check "대시보드 화면 (/dashboard)"    curl -sf -o /dev/null http://127.0.0.1:8201/dashboard
check "대시보드 상태 API"             bash -c "curl -s http://127.0.0.1:8201/api/dashboard/status | grep -q '\"sealed\":false'"
check "console 화면 (/console)"       curl -sf -o /dev/null http://127.0.0.1:8201/console

# -----------------------------------------------------------------------------
echo
if [[ $FAIL -eq 0 ]]; then
  printf '\033[32m결과: 전부 통과 (%d개)\033[0m\n' "$PASS"
else
  printf '\033[31m결과: 통과 %d / 실패 %d\033[0m\n' "$PASS" "$FAIL"
  echo "서버 로그 마지막 10줄:"; tail -10 "$WORK/server.log"
fi
exit $FAIL
