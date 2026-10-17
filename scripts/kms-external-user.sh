#!/usr/bin/env bash
# 외부(인터넷) 사용자 관리: add / token / remove.   서버에서 사람이 실행한다.
#
#   kms-external-user.sh add <user> <key>      SA kms-external/<user> + 키 kms-external.<key> 권한(Role/RoleBinding) 생성
#   kms-external-user.sh token <user> [hours]  토큰 발급 (기본 1시간, 최대 24시간) — 표준 출력으로만 낸다
#   kms-external-user.sh remove <user>         RoleBinding·Role·SA 삭제 (키는 지우지 않는다)
#
# 옵션: --plan(실행할 명령만 보여 주고 아무것도 바꾸지 않음), --audience <값>(token용)
# 환경변수: KUBECTL(기본 'kubectl'), KMS_ADMIN_SOCKET(기본 /run/custom-kms/admin/admin.sock),
#           KMS_MANIFEST(audience를 읽을 static pod 매니페스트, 기본 /etc/kubernetes/manifests/kms-static-pod.yaml)
#
# 모델(ADR-009): 키 kms-external.<key>는 kms-external 네임스페이스 소유라 그 네임스페이스의 Role/RoleBinding만 효력이 있다.
# 외부 리스너는 요청자 SA와 키가 모두 kms-external 소속이어야 받는다.
set -euo pipefail

NS=kms-external
KUBECTL=${KUBECTL:-kubectl}
CURL=${CURL:-curl}
SOCK=${KMS_ADMIN_SOCKET:-/run/custom-kms/admin/admin.sock}
MANIFEST=${KMS_MANIFEST:-/etc/kubernetes/manifests/kms-static-pod.yaml}
PLAN=0
AUDIENCE=""

die() { echo "오류: $*" >&2; exit 2; }

args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN=1; shift ;;
    --audience) [ $# -ge 2 ] || die "--audience 값이 필요해요"; AUDIENCE=$2; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]:-}"
cmd=${1:-}; shift || true

valid_user() { [[ "$1" =~ ^[a-z0-9]([-a-z0-9]{0,40}[a-z0-9])?$ ]] || die "사용자 이름은 소문자/숫자/-만 쓸 수 있어요 (DNS-1123): $1"; }
valid_key()  { [[ "$1" =~ ^[a-zA-Z0-9_-]{1,40}$ ]] || die "키 이름은 영문/숫자/_/-만 쓸 수 있어요 (최대 40자): $1"; }
# k8s 객체 이름용: 소문자, _ → -
objname() { echo "kms-ext-$1-$(echo "$2" | tr 'A-Z_' 'a-z-')"; }

run() { if [ "$PLAN" = 1 ]; then echo "[plan] $*"; else "$@"; fi; }

case "$cmd" in
add)
  user=${1:-}; key=${2:-}; [ -n "$user" ] && [ -n "$key" ] || die "사용법: add <user> <key>"
  valid_user "$user"; valid_key "$key"
  fullkey="$NS.$key"; name=$(objname "$user" "$key")
  manifest=$(cat <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $user
  namespace: $NS
  labels: {kms-external/user: "$user", app.kubernetes.io/managed-by: kms-external-user}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: $name
  namespace: $NS
  labels: {kms-external/user: "$user", app.kubernetes.io/managed-by: kms-external-user}
rules:
- apiGroups: [kms.local]
  resources: [keys]
  resourceNames: ["$fullkey"]
  verbs: [encrypt, decrypt, rewrap, datakey]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: $name
  namespace: $NS
  labels: {kms-external/user: "$user", app.kubernetes.io/managed-by: kms-external-user}
subjects:
- {kind: ServiceAccount, name: $user, namespace: $NS}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: $name}
YAML
)
  if [ "$PLAN" = 1 ]; then
    echo "[plan] 키 확인: $CURL --unix-socket $SOCK http://localhost/v1/keys/$fullkey  (없으면 생성할지 [y/N]로 물어봄)"
    echo "[plan] $KUBECTL apply -f -   <<'매니페스트'"; echo "$manifest"
  else
    code=$($CURL -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" "http://localhost/v1/keys/$fullkey" || true)
    if [ "$code" = 404 ]; then
      read -r -p "키 $fullkey 가 없어요. 관리 소켓으로 만들까요? [y/N] " ans || ans=""
      if [ "$ans" = y ] || [ "$ans" = Y ]; then
        $CURL -sf -X POST -H 'content-type: application/json' --unix-socket "$SOCK" -d "{\"name\":\"$fullkey\"}" http://localhost/v1/keys >/dev/null \
          || die "키 생성에 실패했어요"
        echo "키 $fullkey 생성"
      else
        echo "키를 만들지 않았어요. 권한만 설정합니다 (키가 생길 때까지 요청은 404)." >&2
      fi
    elif [ "$code" != 200 ]; then
      die "키 조회가 예상 밖의 응답이에요 (HTTP $code). 관리 소켓과 KMS 상태(봉인 여부)를 확인하세요"
    fi
    echo "$manifest" | $KUBECTL apply -f -
  fi
  echo "완료: SA $NS/$user → 키 $fullkey (encrypt, decrypt, rewrap, datakey). 토큰: $0 token $user" >&2
  ;;
token)
  user=${1:-}; hours=${2:-1}; [ -n "$user" ] || die "사용법: token <user> [hours]"
  valid_user "$user"
  [[ "$hours" =~ ^[0-9]+$ ]] && [ "$hours" -ge 1 ] || die "hours는 1 이상의 정수여야 해요"
  [ "$hours" -le 24 ] || die "토큰 수명은 최대 24시간이에요 (요청: ${hours}시간). 짧을수록 유출 피해가 작아요"
  if [ -z "$AUDIENCE" ]; then
    [ -r "$MANIFEST" ] || die "audience를 알 수 없어요: --audience 를 주거나 $MANIFEST 를 읽을 수 있어야 해요"
    AUDIENCE=$(python3 - "$MANIFEST" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
for c in doc["spec"]["containers"]:
    for e in c.get("env", []):
        if e.get("name") == "KMS_SA_AUDIENCE":
            print(e["value"]); raise SystemExit
raise SystemExit("KMS_SA_AUDIENCE 항목이 매니페스트에 없어요")
PY
) || die "매니페스트에서 audience를 읽지 못했어요"
  fi
  [[ "$AUDIENCE" =~ ^[A-Za-z0-9._:/-]{1,128}$ ]] || die "audience 형식이 올바르지 않아요"
  # 토큰은 표준 출력으로만 낸다 (파일·로그·셸 기록에 남기지 않는다). 아래 명령은 토큰 값을 출력하지 않는다.
  if [ "$PLAN" = 1 ]; then
    echo "[plan] $KUBECTL -n $NS create token $user --audience=$AUDIENCE --duration=${hours}h"
  else
    $KUBECTL -n "$NS" create token "$user" --audience="$AUDIENCE" --duration="${hours}h"
  fi
  ;;
remove)
  user=${1:-}; [ -n "$user" ] || die "사용법: remove <user>"
  valid_user "$user"
  run $KUBECTL -n "$NS" delete rolebinding,role -l "kms-external/user=$user"
  run $KUBECTL -n "$NS" delete serviceaccount "$user"
  echo "삭제 요청 완료 (키는 지우지 않았어요). 이미 발급된 토큰은 만료 전까지 SA 삭제 후 거부되지만, 짧은 수명이 기본 방어선이에요." >&2
  ;;
*)
  sed -n '2,13p' "$0"; exit 2 ;;
esac
