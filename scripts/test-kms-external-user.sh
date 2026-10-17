#!/usr/bin/env bash
# kms-external-user.sh 테스트: 가짜 kubectl/curl로 호출 인자와 매니페스트를 확인한다 (클러스터 불필요).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
S=scripts/kms-external-user.sh
cat >"$W/kubectl" <<'K'
#!/usr/bin/env bash
echo "ARGS: $*" >>"$FAKE_LOG"
if [ "$1" = apply ]; then cat >>"$FAKE_LOG"; fi
case "$*" in *"create token"*) echo "FAKE.TOKEN.VALUE";; esac
K
cat >"$W/curl" <<'C'
#!/usr/bin/env bash
echo "CURL: $*" >>"$FAKE_LOG"
case "$*" in *"-w"*) echo "${FAKE_KEY_CODE:-404}";; esac
C
chmod +x "$W/kubectl" "$W/curl"
export KUBECTL="$W/kubectl" CURL="$W/curl" FAKE_LOG="$W/log" KMS_ADMIN_SOCKET=/nonexistent.sock
: >"$W/log"

# --plan: 아무것도 실행하지 않고 매니페스트와 명령만 보여 준다
out=$($S add alice shop_data --plan 2>/dev/null)
echo "$out" | grep -q 'resourceNames: \["kms-external.shop_data"\]'
echo "$out" | grep -q 'verbs: \[encrypt, decrypt, rewrap, datakey\]'
echo "$out" | grep -q 'name: kms-ext-alice-shop-data'      # 객체 이름은 k8s 규칙(소문자, _ → -)
[ ! -s "$W/log" ] || { echo "--plan이 명령을 실행함"; exit 1; }

# add: 키가 없으면 y/N로 물어보고, n이면 만들지 않는다. 그래도 apply는 한다
echo n | $S add alice shop_data >/dev/null 2>&1
grep -q '^ARGS: apply -f -' "$W/log"
! grep -q 'POST' "$W/log"
: >"$W/log"
echo y | $S add alice shop_data >/dev/null 2>&1
grep -q 'CURL: .*-X POST .*kms-external.shop_data' "$W/log"
grep -q 'kind: RoleBinding' "$W/log"
: >"$W/log"
FAKE_KEY_CODE=200 $S add alice shop_data </dev/null >/dev/null 2>&1   # 키가 있으면 묻지 않는다
! grep -q 'POST' "$W/log"

# 잘못된 이름 거부
for bad in "Alice" "a;b" "-x" ""; do
  if $S add "$bad" k --plan >/dev/null 2>&1; then echo "잘못된 사용자 '$bad' 통과"; exit 1; fi
done
if $S add alice 'k;rm' --plan >/dev/null 2>&1; then echo "잘못된 키 통과"; exit 1; fi

# token: 기본 1시간, 24시간 초과 거부, audience 필수/매니페스트에서 읽기, 토큰은 stdout으로만
: >"$W/log"
tok=$($S token alice --audience kms-system 2>"$W/err")
[ "$tok" = FAKE.TOKEN.VALUE ]
grep -q 'create token alice --audience=kms-system --duration=1h' "$W/log"
! grep -q 'FAKE.TOKEN.VALUE' "$W/log" "$W/err"
$S token alice 24 --audience kms-system >/dev/null
if $S token alice 25 --audience kms-system >/dev/null 2>&1; then echo "25시간 통과"; exit 1; fi
if $S token alice 0 --audience kms-system >/dev/null 2>&1; then echo "0시간 통과"; exit 1; fi
cat >"$W/m.yaml" <<'Y'
spec:
  containers:
  - name: kms
    env:
    - {name: KMS_AUTHN, value: 'on'}
    - {name: KMS_SA_AUDIENCE, value: my-audience}
Y
KMS_MANIFEST="$W/m.yaml" $S token alice 2 >/dev/null
grep -q 'audience=my-audience --duration=2h' "$W/log"
if KMS_MANIFEST=/nonexistent $S token alice >/dev/null 2>&1; then echo "audience 없이 통과"; exit 1; fi
$S token alice --plan --audience kms-system | grep -q 'plan.*create token alice'

# remove: 키는 지우지 않는다
: >"$W/log"
$S remove alice >/dev/null 2>&1
grep -q 'delete rolebinding,role -l kms-external/user=alice' "$W/log"
grep -q 'delete serviceaccount alice' "$W/log"
! grep -qi 'DELETE .*keys' "$W/log"
echo "kms-external-user 테스트 통과"
