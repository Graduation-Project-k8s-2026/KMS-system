#!/usr/bin/env bash
# =============================================================================
# bench-access-control.sh — 접근 제어 오버헤드 비교 실험 재현 스크립트
#
# 조건마다 KMS 서버를 새로 띄우고 → unseal·키 생성 → 측정 → 종료를 반복한다.
# 모든 조건이 "같은 바이너리, 같은 세션, 같은 파라미터"로 측정되도록 하는 것이 목적.
#
# 측정 조건
#   1. baseline                인증·인가 off
#   2. authn-only              인증만 on (ServiceAccount 토큰 서명 검증)
#   3. authz-cached            인증 + 인가 on, 판단 캐시 기본값(TTL 10초)
#   4. authz-uncached-qps50    인증 + 인가 on, 캐시 off, client-go 속도 제한 기본값(QPS 50 / Burst 100)
#   5. authz-uncached-nolimit  인증 + 인가 on, 캐시 off, 속도 제한 off (apiserver 실제 한계)
#
# 사전 조건
#   - kind 클러스터 kms-bench 가 떠 있고, team-a/app-a ServiceAccount와
#     kms.local/keys "demo" encrypt 권한(Role/RoleBinding)이 있어야 한다
#   - 수동으로 띄운 KMS 서버는 종료해둘 것 (포트 8200/9100 충돌)
#
# 사용법
#   scripts/bench-access-control.sh
#   LEVELS=1,10,50,100 DURATION=20s scripts/bench-access-control.sh
#
# 환경변수로 조정 가능
#   LEVELS    동시성 수준 (기본 1,10,50)
#   DURATION  수준별 측정 시간 (기본 10s)
#   OP        작업 (기본 encrypt)
#   PAYLOAD   평문 크기 (기본 1KB)
#   OUT       결과 디렉터리 (기본 ~/workspace/active/bench-results/<시각>)
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${KIND_CLUSTER:-kms-bench}"
CTX="kind-${CLUSTER}"
PREP="${KMS_BENCH_HOME:-$HOME/.kms-bench}"

LEVELS="${LEVELS:-1,10,50}"
DURATION="${DURATION:-10s}"
OP="${OP:-encrypt}"
PAYLOAD="${PAYLOAD:-1KB}"
KEY="demo"
OUT="${OUT:-$HOME/workspace/active/bench-results/$(date +%Y%m%d-%H%M%S)}"

SOCK="$PREP/bench-admin.sock"
BIN="$PREP/bin"
TOKEN="$PREP/token"
SA_PUB="$PREP/sa.pub"
KUBECONFIG_FILE="$PREP/kubeconfig"

CONDS="baseline,authn-only,authz-cached,authz-uncached-qps50,authz-uncached-nolimit"

SERVER_PID=""
CURRENT=""

# -----------------------------------------------------------------------------
# 공통 함수
# -----------------------------------------------------------------------------
log()  { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
  rm -f "$SOCK"
}
trap stop_server EXIT
trap 'echo; echo "중단됨 — 서버를 정리합니다"; exit 130' INT TERM

wait_ready() {
  for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "--- server-$CURRENT.log (마지막 20줄) ---"
      tail -20 "$OUT/server-$CURRENT.log" || true
      fail "[$CURRENT] 서버가 기동 중 종료되었습니다"
    fi
    if [[ -S "$SOCK" ]] && curl -s -o /dev/null --max-time 1 http://127.0.0.1:9100/metrics; then
      return 0
    fi
    sleep 0.5
  done
  fail "[$CURRENT] 서버 준비 대기 시간 초과 (30초)"
}

# run_condition <이름> <토큰 사용 yes|no> [서버 환경변수...]
run_condition() {
  CURRENT="$1"; shift
  local use_token="$1"; shift

  log "[$CURRENT] 서버 기동"
  rm -f "$SOCK"
  # env -i: 사용자 셸에 남아 있는 KMS_* 변수가 섞이지 않도록 깨끗한 환경에서 띄운다
  env -i PATH="$PATH" HOME="$HOME" \
    KMS_SEAL_TYPE=dev KMS_MASTER_KEY=bench-only KMS_STORAGE=memory \
    KMS_ADMIN_SOCKET="$SOCK" \
    "$@" \
    "$BIN/kms-server" >"$OUT/server-$CURRENT.log" 2>&1 &
  SERVER_PID=$!
  wait_ready
  grep -E "rate limit|cache is disabled|authentication|authorization" "$OUT/server-$CURRENT.log" | sed 's/^/    /' || true

  curl -sf --unix-socket "$SOCK" -XPOST http://localhost/v1/sys/unseal >/dev/null \
    || fail "[$CURRENT] unseal 실패"
  curl -sf --unix-socket "$SOCK" -XPOST http://localhost/v1/keys \
    -H 'content-type: application/json' -d "{\"name\":\"$KEY\"}" >/dev/null \
    || fail "[$CURRENT] 키 생성 실패"

  local tokargs=()
  [[ "$use_token" == yes ]] && tokargs=(--token-file "$TOKEN")

  log "[$CURRENT] 측정 (동시성 $LEVELS, 각 $DURATION)"
  "$BIN/kms-bench" --key "$KEY" --op "$OP" --payload "$PAYLOAD" \
    --scenario concurrency --concurrency-levels "$LEVELS" --duration "$DURATION" \
    "${tokargs[@]}" --label "$CURRENT" \
    --format json --output "$OUT/$CURRENT.json"

  curl -s http://127.0.0.1:9100/metrics >"$OUT/metrics-$CURRENT.txt"
  stop_server
  sleep 3   # 조건 사이 쿨다운
}

# -----------------------------------------------------------------------------
# 1. 사전 점검
# -----------------------------------------------------------------------------
log "사전 점검"
for cmd in go kind kubectl docker curl python3; do
  command -v "$cmd" >/dev/null || fail "필요한 명령이 없습니다: $cmd"
done

for port in 8200 9100; do
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/"; then
    fail "포트 $port 를 이미 사용 중입니다. 수동으로 띄운 KMS 서버를 먼저 종료하세요"
  fi
done

kind get clusters 2>/dev/null | grep -qx "$CLUSTER" \
  || fail "kind 클러스터 '$CLUSTER' 가 없습니다"
kubectl --context "$CTX" -n team-a get rolebinding >/dev/null 2>&1 \
  || fail "클러스터에 접근할 수 없거나 team-a 네임스페이스가 없습니다"

# -----------------------------------------------------------------------------
# 2. 준비물 (/tmp가 아닌 고정 위치에 매번 새로 만든다)
# -----------------------------------------------------------------------------
log "준비물 갱신 ($PREP)"
mkdir -p "$PREP" "$BIN" "$OUT"
kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG_FILE"
docker cp "$CLUSTER-control-plane:/etc/kubernetes/pki/sa.pub" "$SA_PUB" >/dev/null
kubectl --context "$CTX" -n team-a create token app-a --duration=1h >"$TOKEN"
chmod 600 "$TOKEN"
echo "    kubeconfig, sa.pub, token(1h) 준비 완료"

# -----------------------------------------------------------------------------
# 3. 빌드 — 모든 조건이 같은 바이너리를 쓰도록 한 번만 빌드
# -----------------------------------------------------------------------------
log "빌드"
(cd "$REPO" && go build -o "$BIN/kms-server" ./cmd/server && go build -o "$BIN/kms-bench" ./cmd/bench)
echo "    $BIN/kms-server, $BIN/kms-bench"

# -----------------------------------------------------------------------------
# 4. 실험 환경 기록
# -----------------------------------------------------------------------------
{
  echo "date:        $(date -Iseconds)"
  echo "git_branch:  $(git -C "$REPO" branch --show-current)"
  echo "git_commit:  $(git -C "$REPO" rev-parse HEAD)"
  echo "git_dirty:   $([[ -n "$(git -C "$REPO" status --porcelain)" ]] && echo yes || echo no)"
  echo "go:          $(go version)"
  echo "kernel:      $(uname -srm)"
  echo "cpus:        $(nproc)"
  echo "kind_k8s:    $(kubectl --context "$CTX" get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')"
  echo "params:      op=$OP payload=$PAYLOAD levels=$LEVELS duration=$DURATION"
  echo "conditions:  $CONDS"
} >"$OUT/meta.txt"

# -----------------------------------------------------------------------------
# 5. 측정
# -----------------------------------------------------------------------------
AUTHN=(KMS_AUTHN=on KMS_SA_PUBLIC_KEY="$SA_PUB")
AUTHZ=(KMS_AUTHZ=on KMS_KUBECONFIG="$KUBECONFIG_FILE")

run_condition baseline               no  KMS_AUTHN=off KMS_AUTHZ=off
run_condition authn-only             yes "${AUTHN[@]}" KMS_AUTHZ=off
run_condition authz-cached           yes "${AUTHN[@]}" "${AUTHZ[@]}"
run_condition authz-uncached-qps50   yes "${AUTHN[@]}" "${AUTHZ[@]}" KMS_AUTHZ_CACHE_TTL=-1
run_condition authz-uncached-nolimit yes "${AUTHN[@]}" "${AUTHZ[@]}" KMS_AUTHZ_CACHE_TTL=-1 \
                                         KMS_AUTHZ_QPS=-1 KMS_AUTHZ_BURST=-1

# -----------------------------------------------------------------------------
# 6. 요약
# -----------------------------------------------------------------------------
log "요약"
python3 - "$OUT" "$CONDS" <<'PY'
import json, os, re, sys

out, conds = sys.argv[1], sys.argv[2].split(",")

# --- 처리량·지연 표 ---
rows, base = [], {}
for name in conds:
    path = os.path.join(out, f"{name}.json")
    if not os.path.exists(path):
        continue
    for r in json.load(open(path))["runs"]:
        c, ops = r["concurrency"], r["ops_per_sec"]
        if name == "baseline":
            base[c] = ops
        lat = r["latency"]
        rows.append((name, c, ops, lat["p50_seconds"] * 1e3, lat["p99_seconds"] * 1e3, r["error_count"]))

hdr = f"{'condition':<25}{'conc':>5}{'ops/sec':>11}{'vs base':>9}{'p50(ms)':>10}{'p99(ms)':>10}{'errors':>8}"
lines = [hdr, "-" * len(hdr)]
for n, c, ops, p50, p99, e in rows:
    rel = f"{ops / base[c] * 100:.1f}%" if c in base and base[c] else "-"
    lines.append(f"{n:<25}{c:>5}{ops:>11.1f}{rel:>9}{p50:>10.2f}{p99:>10.2f}{e:>8}")

# --- SAR 시간 분해 (대기 vs apiserver 왕복) ---
def metric(text, name):
    m = re.search(rf"^{name} ([0-9.e+-]+)$", text, re.M)
    return float(m.group(1)) if m else None

lines += ["", "SAR 시간 분해 (조건 전체 평균, 워밍업 포함)",
          f"{'condition':<25}{'calls':>9}{'sar(ms)':>10}{'rt(ms)':>9}{'wait(ms)':>10}"]
for name in conds:
    p = os.path.join(out, f"metrics-{name}.txt")
    if not os.path.exists(p):
        continue
    t = open(p).read()
    cnt = metric(t, "kms_authz_sar_duration_seconds_count")
    if not cnt:
        continue
    sar = metric(t, "kms_authz_sar_duration_seconds_sum") / cnt * 1e3
    rt_sum = metric(t, "kms_authz_apiserver_roundtrip_seconds_sum")
    rt_cnt = metric(t, "kms_authz_apiserver_roundtrip_seconds_count")
    rt = rt_sum / rt_cnt * 1e3 if rt_cnt else float("nan")
    lines.append(f"{name:<25}{int(cnt):>9}{sar:>10.2f}{rt:>9.2f}{sar - rt:>10.2f}")

text = "\n".join(lines)
print(text)
open(os.path.join(out, "summary.txt"), "w").write(text + "\n")

with open(os.path.join(out, "summary.csv"), "w") as f:
    f.write("condition,concurrency,ops_per_sec,vs_baseline_pct,p50_ms,p99_ms,errors\n")
    for n, c, ops, p50, p99, e in rows:
        rel = f"{ops / base[c] * 100:.2f}" if c in base and base[c] else ""
        f.write(f"{n},{c},{ops:.2f},{rel},{p50:.3f},{p99:.3f},{e}\n")
PY

log "완료 — 결과: $OUT"
ls -1 "$OUT"