#!/usr/bin/env bash
# 사용자 포털(demo-app)을 운영 서버(단일 노드 kubeadm)에 "처음" 배포한다. 서버에서 직접 실행한다.
#
#   scripts/deploy-user-portal.sh            # 점검 → 인증서 → 렌더링 → 적용 → 검증 → 공개
#   scripts/deploy-user-portal.sh --plan     # 서버 없이 파일만 만들고 검사(클러스터·tailscale·sudo 안 씀)
#   scripts/deploy-user-portal.sh --rollback # 포털만 되돌림(Deployment/Service/Secret, tailscale 8443)
#   옵션: --yes(확인 질문 생략) --skip-serve(8443 공개 생략)
#
# 건드리지 않는 것: KMS 본체, 관리 API, tailscale serve 443(관리 콘솔) 경로.
# 비밀(인증서·키·토큰) 내용은 화면에 출력하지 않는다.
#
# 전체 구조(왜 이렇게 하나):
#   브라우저 ─HTTPS 8443→ tailscale serve ─→ 노드의 NodePort 30443 ─→ Pod(demo-app, TLS 8443)
#   - Pod가 직접 TLS를 하는 이유: 기존 보안 설계(Pod 내부도 HTTPS)를 유지하기 위해서다.
#     이 인증서는 "tailscale serve → Pod" 서버 내부 구간에만 쓰는 자체 서명이다.
#   - 브라우저가 보는 인증서는 tailscale이 관리하는 진짜 인증서다(그래서 경고가 안 뜬다).
set -euo pipefail

# ---------- 설정 (환경변수로 덮어쓸 수 있다) ----------
NS=kms-demo
APP=kms-demo-app
SA=app-a
CA_CM=kms-internal-ca
TLS_SECRET=kms-demo-tls
# 이미지는 서버 containerd에 이미 있다. imagePullPolicy가 Never라서 "이름@sha256:digest" 형식이어야 한다
# (태그@digest 형식은 ErrImageNeverPull이 났었다).
DEMO_IMAGE="${DEMO_IMAGE:-docker.io/library/kms-demo-app@sha256:b88dc68ff0e7107d3593b174e9915957a01ce448f16b023b4d6a98df8071a1b4}"
DEMO_KEYS="${DEMO_KEYS:-demo,campus-shipping}"
DEMO_SA_LABEL="${DEMO_SA_LABEL:-kms-demo/app-a}"
PORTAL_PORT=8443          # 브라우저가 접속하는 tailscale serve HTTPS 포트 (443은 관리 콘솔이 쓰고 있다)
NODEPORT=30443            # 템플릿 Service의 NodePort
WORKDIR="${WORKDIR:-$HOME/kms-lab/user-portal}"
KUBECONFIG_PATH=/etc/kubernetes/admin.conf
ADMIN_SOCK=/run/custom-kms/admin/admin.sock
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$REPO/deploy/oci-single-node/templates/demo-app.yaml"

PLAN=0; ROLLBACK=0; ASSUME_YES=0; SKIP_SERVE=0
for a in "$@"; do
  case "$a" in
    --plan) PLAN=1 ;; --rollback) ROLLBACK=1 ;; --yes) ASSUME_YES=1 ;; --skip-serve) SKIP_SERVE=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $a" >&2; exit 2 ;;
  esac
done

SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
kc() { $SUDO kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"; }
step() { printf '\n== %s\n' "$*"; }
ok()   { printf '  ✔ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
die()  { printf '  ✖ %s\n' "$*" >&2; exit 1; }

# ---------- 되돌리기 ----------
if [ "$ROLLBACK" -eq 1 ]; then
  step "포털 되돌리기 (KMS·관리 콘솔·네임스페이스·서비스 계정은 그대로 둔다)"
  $SUDO tailscale serve --https="$PORTAL_PORT" off 2>/dev/null && ok "tailscale ${PORTAL_PORT} 공개 해제" || warn "tailscale ${PORTAL_PORT} 공개가 없었거나 해제 실패"
  kc -n "$NS" delete deployment/"$APP" service/"$APP" secret/"$TLS_SECRET" --ignore-not-found
  ok "Deployment·Service·TLS Secret 삭제"
  echo "  (인증서 파일은 $WORKDIR 에 남겨 둔다. 다시 배포하면 재사용한다)"
  exit 0
fi

# ---------- 0. 값 정하기 ----------
step "0. 준비"
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"; umask 077   # 인증서·키 파일은 0600
# 포털의 공개 주소(GUI_FQDN)는 tailnet 이름이다. 환경변수로 주지 않으면 tailscale status에서 읽는다.
if [ -z "${GUI_FQDN:-}" ]; then
  [ "$PLAN" -eq 1 ] && die "--plan에서는 GUI_FQDN 환경변수가 필요해요 (예: GUI_FQDN=kms.example.test)"
  GUI_FQDN="$($SUDO tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')" || die "tailscale status에서 이름을 못 읽었어요. GUI_FQDN=<tailnet 이름> 으로 지정하세요"
fi
case "$GUI_FQDN" in *[!a-zA-Z0-9.-]*|"") die "GUI_FQDN 형식이 올바르지 않아요" ;; esac
ORIGIN="https://${GUI_FQDN}:${PORTAL_PORT}"
echo "  포털 주소: $ORIGIN"
echo "  이미지:    ${DEMO_IMAGE##*/}"
echo "  작업 폴더: $WORKDIR"
command -v openssl >/dev/null || die "openssl이 필요해요"
python3 -c 'import yaml' 2>/dev/null || die "python3-yaml이 필요해요 (sudo apt install python3-yaml)"

# ---------- 1. 사전 점검 ----------
# 왜: 하나라도 빠진 채 적용하면 Pod가 뜨지 않거나(이미지/CA), 떠도 암복호화가 안 된다(봉인).
if [ "$PLAN" -eq 0 ]; then
  step "1. 사전 점검"
  # (a) KMS가 봉인 해제 상태여야 포털이 암복호화를 한다. 관리 소켓(root 권한)으로 직접 묻는다.
  seal_json="$($SUDO curl -s --max-time 5 --unix-socket "$ADMIN_SOCK" http://localhost/v1/sys/seal-status)" || die "관리 소켓에 연결할 수 없어요 (KMS가 떠 있나요?)"
  echo "$seal_json" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("sealed") is False else 1)' || die "KMS가 봉인돼 있어요. 관리 콘솔에서 조각 3개로 해제한 뒤 다시 실행하세요"
  ok "KMS 봉인 해제 상태"
  # (b) 네임스페이스·서비스 계정·CA ConfigMap. 포털은 app-a 계정의 토큰으로 KMS에 접속한다.
  kc get ns "$NS" >/dev/null 2>&1 || die "네임스페이스 $NS 가 없어요"
  kc -n "$NS" get sa "$SA" >/dev/null 2>&1 || die "서비스 계정 $SA 가 없어요 (serviceaccounts-rbac 적용 필요)"
  kc -n "$NS" get cm "$CA_CM" >/dev/null 2>&1 || die "ConfigMap $CA_CM (KMS 인증서를 믿기 위한 CA)가 없어요"
  kc -n "$NS" get cm "$CA_CM" -o json | python3 -c 'import json,sys; sys.exit(0 if "ca.crt" in json.load(sys.stdin).get("data",{}) else 1)' || die "$CA_CM 에 ca.crt 항목이 없어요"
  ok "네임스페이스 $NS · 서비스 계정 $SA · CA ConfigMap(ca.crt)"
  # (c) 이미지가 이 노드의 containerd에 있어야 한다(imagePullPolicy Never라서 외부에서 받아 오지 않는다).
  $SUDO ctr -n k8s.io images list -q | grep -qxF "$DEMO_IMAGE" || die "containerd에 이미지가 없어요: ${DEMO_IMAGE##*/}  (ctr -n k8s.io images list 로 확인하세요)"
  ok "이미지가 containerd에 있음"
  command -v tailscale >/dev/null || [ "$SKIP_SERVE" -eq 1 ] || die "tailscale이 필요해요 (--skip-serve로 공개를 건너뛸 수 있어요)"
fi

# ---------- 2. Pod용 TLS 인증서 ----------
# 왜: demo-app은 Pod 안에서 HTTPS로 응답한다. 서비스 이름·127.0.0.1을 SAN에 넣은 자체 서명 인증서를 만든다.
# 이미 있으면 재사용해서(재배포해도 같은 Secret) 불필요한 변경을 줄인다.
step "2. Pod용 TLS 인증서"
CRT="$WORKDIR/tls.crt"; KEY="$WORKDIR/tls.key"
if [ -s "$CRT" ] && [ -s "$KEY" ]; then
  if openssl x509 -checkend 2592000 -noout -in "$CRT" >/dev/null; then ok "기존 인증서 재사용 (30일 이상 남음)"
  else warn "인증서가 30일 안에 만료돼요. $CRT,$KEY 를 지우고 다시 실행하면 새로 만들어요"; fi
else
  SAN="DNS:${APP}.${NS}.svc.cluster.local,DNS:${APP}.${NS}.svc,DNS:${APP},DNS:localhost,IP:127.0.0.1"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj "/CN=${APP}" \
    -addext "subjectAltName=${SAN}" -keyout "$KEY" -out "$CRT" 2>/dev/null
  ok "자체 서명 인증서 생성 (SAN: 서비스 DNS 이름 + 127.0.0.1)"
fi
chmod 600 "$CRT" "$KEY"
if [ "$PLAN" -eq 0 ]; then
  # Secret은 파이프로 바로 적용해서 화면·파일에 YAML이 남지 않게 한다.
  kc -n "$NS" create secret tls "$TLS_SECRET" --cert="$CRT" --key="$KEY" --dry-run=client -o yaml | kc apply -f - >/dev/null
  ok "Secret $TLS_SECRET 등록 (내용은 출력하지 않음)"
fi

# ---------- 3. 매니페스트 렌더링 ----------
# 왜: 템플릿의 ${...} 자리를 이번 배포 값으로 채운다. 검증 규칙은 scripts/render-release.py와 같다
# (미치환 금지, 이미지는 digest 고정). 포털 공개 주소만 이번 배포 방식(tailscale 8443)에 맞게 바꾼다.
step "3. 매니페스트 렌더링"
OUT="$WORKDIR/demo-app.yaml"
DEMO_IMAGE="$DEMO_IMAGE" ORIGIN="$ORIGIN" DEMO_KEYS="$DEMO_KEYS" DEMO_SA_LABEL="$DEMO_SA_LABEL" TEMPLATE="$TEMPLATE" OUT="$OUT" NODEPORT="$NODEPORT" \
python3 - <<'PY'
import os, re, sys, yaml
raw = open(os.environ["TEMPLATE"]).read()
image, origin = os.environ["DEMO_IMAGE"], os.environ["ORIGIN"]
if not re.fullmatch(r"[\w./:-]+@sha256:[a-f0-9]{64}", image):
    sys.exit("이미지는 이름@sha256:digest 형식이어야 해요")
for k in ("DEMO_KEYS", "DEMO_SA_LABEL"):
    if not re.fullmatch(r"[A-Za-z0-9._/,-]+", os.environ[k]):
        sys.exit(k + " 형식이 올바르지 않아요")
raw = raw.replace("${DEMO_IMAGE}", image)
# 템플릿의 공개 주소(DEMO_FQDN:30443)를 tailscale 8443 주소로 바꾼다 — Host/Origin 검사가 이 값과 비교한다.
raw, n = re.subn(r"(name: DEMO_PUBLIC_ORIGIN\n\s+value: )\S+", lambda m: m.group(1) + origin, raw)
if n != 1: sys.exit("DEMO_PUBLIC_ORIGIN 항목을 찾지 못했어요")
raw, n = re.subn(r"(name: DEMO_KEYS\n\s+value: )\S+", lambda m: m.group(1) + os.environ["DEMO_KEYS"], raw)
if n != 1: sys.exit("DEMO_KEYS 항목을 찾지 못했어요")
raw, n = re.subn(r"(name: DEMO_SA_LABEL\n\s+value: )\S+", lambda m: m.group(1) + os.environ["DEMO_SA_LABEL"], raw)
if n != 1: sys.exit("DEMO_SA_LABEL 항목을 찾지 못했어요")
if "${" in raw: sys.exit("치환되지 않은 자리가 남아 있어요")

# ---- 템플릿이 서버 현황과 맞는지 검사 (틀리면 Pod가 떠도 KMS에 못 붙는다) ----
docs = list(yaml.safe_load_all(raw))
dep = next(d for d in docs if d["kind"] == "Deployment")
svc = next(d for d in docs if d["kind"] == "Service")
pod = dep["spec"]["template"]["spec"]
c = pod["containers"][0]
env = {e["name"]: e.get("value") for e in c["env"]}
vols = {v["name"]: v for v in pod["volumes"]}
def need(cond, msg):
    if not cond: sys.exit("템플릿 검사 실패: " + msg)
need(dep["metadata"]["namespace"] == "kms-demo", "네임스페이스는 kms-demo")
need(pod["serviceAccountName"] == "app-a", "서비스 계정은 app-a")
need(c["image"] == image and c["imagePullPolicy"] == "Never", "이미지는 digest 고정 + imagePullPolicy Never")
tok = vols["transit"]["projected"]["sources"][0]["serviceAccountToken"]
need(tok["audience"] == "kms-system" and tok["path"] == "token" and env["DEMO_TOKEN_FILE"] == "/transit/token", "토큰은 audience kms-system, /transit/token")
need(vols["ca"]["configMap"]["name"] == "kms-internal-ca" and env["DEMO_CA_FILE"] == "/ca/ca.crt", "CA는 ConfigMap kms-internal-ca의 ca.crt")
need(env["DEMO_TRANSIT_URL"] == "https://kms-transit.kube-system.svc.cluster.local:8200", "Transit 주소는 kms-transit 서비스 8200")
need(vols["tls"]["secret"]["secretName"] == "kms-demo-tls", "TLS Secret 이름은 kms-demo-tls")
need(env["DEMO_PUBLIC_ORIGIN"] == origin, "공개 주소")
need(svc["spec"]["type"] == "NodePort" and svc["spec"]["ports"][0]["nodePort"] == int(os.environ["NODEPORT"]), "Service는 NodePort 30443")
open(os.environ["OUT"], "w").write(raw)
os.chmod(os.environ["OUT"], 0o600)
print("  ✔ 렌더링·검사 통과: 서비스 계정 app-a, 토큰 audience kms-system, Transit 서비스, CA, TLS Secret, NodePort 30443")
PY
echo "  매니페스트: $OUT"

if [ "$PLAN" -eq 1 ]; then
  step "계획 모드 종료 — 서버에는 아무것도 하지 않았어요"
  echo "  인증서·매니페스트가 $WORKDIR 에 만들어졌어요. 검토 후 --plan 없이 서버에서 실행하세요."
  exit 0
fi

# ---------- 4. 적용 ----------
if [ "$ASSUME_YES" -eq 0 ]; then
  printf '\n%s 에 포털을 배포하고 %s 포트로 공개할까요? [y/N] ' "$NS" "$PORTAL_PORT"
  read -r ans; [ "$ans" = y ] || [ "$ans" = Y ] || die "취소했어요"
fi
step "4. 적용 (Deployment + Service)"
kc apply -f "$OUT" >/dev/null
ok "kubectl apply 완료"
# Pod가 Ready(readinessProbe 통과)가 될 때까지 기다린다. 실패하면 흔한 원인을 알려 준다.
if ! kc -n "$NS" rollout status deployment/"$APP" --timeout=120s; then
  warn "Pod가 준비되지 않았어요. 흔한 원인:"
  warn " - ErrImageNeverPull: 이미지가 노드에 없거나 이름@sha256 형식이 아님"
  warn " - 인증서 Secret/CA ConfigMap 마운트 실패"
  kc -n "$NS" get pods -l app="$APP" || true
  kc -n "$NS" get events --sort-by=.lastTimestamp 2>/dev/null | tail -8 || true
  die "롤아웃 실패 (되돌리려면 --rollback)"
fi
ok "Pod Ready"

# ---------- 5. 동작 검증 (공개 전에 서버 안에서) ----------
# 왜: 인터넷(tailnet)에 열기 전에 포털이 실제로 KMS와 대화하는지, Host 검사가 동작하는지 확인한다.
step "5. 동작 검증"
# NodePort는 보통 127.0.0.1에서도 열린다. 안 열리면 노드의 내부 주소로 시도한다(주소는 출력하지 않는다).
TARGET=""
for h in 127.0.0.1 "$(kc get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"; do
  [ -n "$h" ] || continue
  if curl -sk --max-time 5 -o /dev/null "https://${h}:${NODEPORT}/readyz"; then TARGET="$h"; break; fi
done
[ -n "$TARGET" ] || die "NodePort ${NODEPORT} 에 접속되지 않아요 (kubectl -n $NS get svc,pods 확인)"
BASE="https://${TARGET}:${NODEPORT}"
code() { curl -sk --max-time 15 -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code "$BASE/readyz")" = 200 ] && ok "readyz 200" || die "readyz 실패"
[ "$(code -H "Host: ${GUI_FQDN}:${PORTAL_PORT}" "$BASE/")" = 200 ] && ok "포털 화면 200 (올바른 Host)" || die "포털 화면 실패"
[ "$(code -H "Host: evil.example" "$BASE/")" = 403 ] && ok "잘못된 Host는 403 (Host 검사 동작)" || warn "잘못된 Host가 403이 아니에요"
# 포털이 알려 주는 키 목록(비밀 아님)과 설정 확인
curl -sk --max-time 10 -H "Host: ${GUI_FQDN}:${PORTAL_PORT}" "$BASE/api/config" | python3 -c 'import json,sys; c=json.load(sys.stdin); print("  ✔ 허용 키:", ",".join(c["keys"]), "| 표시 계정:", c["service_account"])' || warn "/api/config 확인 실패"
# 실제 암호화→복호화 왕복. 암호문·평문은 출력하지 않고 결과 코드만 본다(Origin·X-Demo-Request가 있어야 통과).
post() { curl -sk --max-time 20 -w '\n%{http_code}' -H "Host: ${GUI_FQDN}:${PORTAL_PORT}" -H "Origin: ${ORIGIN}" -H 'X-Demo-Request: 1' -H 'Content-Type: application/json' -d "$2" "$BASE/$1"; }
enc="$(post encrypt '{"key":"demo","value":"portal-deploy-check"}')"
if [ "$(echo "$enc" | tail -1)" = 200 ]; then
  ct="$(echo "$enc" | head -n -1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"
  dec="$(post decrypt "$(CT="$ct" python3 -c 'import json,os; print(json.dumps({"key":"demo","value":os.environ["CT"]}))')")"
  [ "$(echo "$dec" | tail -1)" = 200 ] && ok "demo 키 암호화→복호화 왕복 성공 (KMS 연결·app-a 권한 확인)" || die "복호화 실패"
else
  die "demo 키 암호화 실패(HTTP $(echo "$enc" | tail -1)). 토큰 audience·CA·KMS 권한(app-a → demo)을 확인하세요"
fi
# campus-shipping은 app-a에 권한이 없어서 403이 나오는 것이 정상이다(권한 없음 시연용).
s="$(echo "$(post encrypt '{"key":"campus-shipping","value":"x"}')" | tail -1)"
[ "$s" = 403 ] && ok "campus-shipping은 403 (권한 없음 시연 정상)" || warn "campus-shipping 응답 HTTP $s — 권한 정책이 예상과 달라요(시연용 403이 아님)"

# ---------- 6. 공개 (tailscale serve 8443) ----------
# 왜: tailnet의 다른 기기에서 https://<이름>:8443 으로 접속하게 한다. 443(관리 콘솔)은 건드리지 않는다.
if [ "$SKIP_SERVE" -eq 0 ]; then
  step "6. tailscale serve ${PORTAL_PORT} 공개"
  $SUDO tailscale serve status --json > "$WORKDIR/serve-before.json"
  # Pod가 HTTPS(자체 서명)이므로 https+insecure:// 로 연결한다. 이 구간은 서버 내부(loopback/노드)다.
  $SUDO tailscale serve --bg --yes --https="$PORTAL_PORT" "https+insecure://${TARGET}:${NODEPORT}" >/dev/null
  $SUDO tailscale serve status --json > "$WORKDIR/serve-after.json"
  # 443 핸들러가 그대로인지 확인 (관리 콘솔 경로 보존)
  python3 - "$WORKDIR/serve-before.json" "$WORKDIR/serve-after.json" <<'PY' || die "443 경로가 바뀐 것 같아요! --rollback 후 serve-before.json을 확인하세요"
import json, sys
def h443(p):
    web = json.load(open(p)).get("Web", {}) or {}
    return {k: v for k, v in web.items() if k.endswith(":443")}
sys.exit(0 if h443(sys.argv[1]) == h443(sys.argv[2]) else 1)
PY
  ok "443(관리 콘솔) 경로는 그대로, ${PORTAL_PORT} 추가됨"
  code_pub="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' "${ORIGIN}/readyz" || true)"
  [ "$code_pub" = 200 ] && ok "공개 주소 응답 200" || warn "공개 주소 확인은 서버에서 안 될 수 있어요(HTTP ${code_pub}). 다른 기기에서 ${ORIGIN}/ 로 열어 보세요"
fi

step "완료"
echo "  접속: ${ORIGIN}/   (tailnet에 연결된 기기에서)"
echo "  상태: kubectl -n $NS get pods,svc     (sudo kubectl --kubeconfig $KUBECONFIG_PATH ...)"
echo "  되돌리기: $0 --rollback   (포털만 제거, KMS·관리 콘솔은 그대로)"
