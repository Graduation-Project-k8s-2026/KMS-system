#!/usr/bin/env bash
# Transit 인증서 재발급: 기존 SAN을 그대로 유지하면서 --add-ip/--add-dns를 더해 같은 내부 CA로 다시 발급한다.
# 서버에서 사람이 실행한다. 새 파일은 임시 이름으로 쓴 뒤 mv로 바꾼다(원자적) — KMS는 30초 이내에 다시 읽는다(재시작 불필요).
#
#   reissue-transit-cert.sh --ca-cert <ca.crt> --ca-key <ca.key> [--add-ip <IP>]... [--add-dns <이름>]...
#                           [--tls-dir /etc/custom-kms/transit-tls] [--days 90] [--plan] [--yes]
#
# --plan: 아무것도 바꾸지 않고 할 일만 보여 준다.   --yes: [y/N] 확인을 생략한다 (자동화용).
# 공인 IP 같은 값은 실행할 때 인자로만 받고 파일·로그에 기록하지 않는다 (임시 작업 디렉터리는 끝나면 지운다).
# 환경변수 KEY_BITS(기본 3072): 키 길이 (테스트에서만 줄인다).
set -euo pipefail

TLS_DIR=/etc/custom-kms/transit-tls
DAYS=90
PLAN=0
YES=0
CA_CERT=""
CA_KEY=""
ADD_IP=()
ADD_DNS=()
KEY_BITS=${KEY_BITS:-3072}

die() { echo "오류: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ca-cert) CA_CERT=${2:?}; shift 2 ;;
    --ca-key) CA_KEY=${2:?}; shift 2 ;;
    --tls-dir) TLS_DIR=${2:?}; shift 2 ;;
    --days) DAYS=${2:?}; shift 2 ;;
    --add-ip) ADD_IP+=("${2:?}"); shift 2 ;;
    --add-dns) ADD_DNS+=("${2:?}"); shift 2 ;;
    --plan) PLAN=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "알 수 없는 인자: $1" ;;
  esac
done

[ -n "$CA_CERT" ] && [ -n "$CA_KEY" ] || die "--ca-cert 와 --ca-key 가 필요해요"
[ -r "$CA_CERT" ] && [ -r "$CA_KEY" ] || die "CA 파일을 읽을 수 없어요 (root 권한이 필요할 수 있어요)"
[ -r "$TLS_DIR/tls.crt" ] && [ -r "$TLS_DIR/tls.key" ] || die "$TLS_DIR 에 tls.crt/tls.key 가 있어야 해요"
[[ "$DAYS" =~ ^[0-9]+$ ]] && [ "$DAYS" -ge 1 ] && [ "$DAYS" -le 825 ] || die "--days 는 1~825"
for ip in "${ADD_IP[@]:-}"; do
  [ -z "$ip" ] && continue
  python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$ip" 2>/dev/null || die "IP 형식이 올바르지 않아요: $ip"
done
for d in "${ADD_DNS[@]:-}"; do
  [ -z "$d" ] && continue
  [[ "$d" =~ ^[A-Za-z0-9]([-A-Za-z0-9.]{0,251}[A-Za-z0-9])?$ ]] || die "DNS 이름 형식이 올바르지 않아요: $d"
done

# 기존 SAN 읽기: "DNS:a, IP Address:1.2.3.4" → "DNS:a IP:1.2.3.4"
old_san=$(openssl x509 -in "$TLS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' | sed 's/^ *//; s/IP Address:/IP:/' | grep -E '^(DNS|IP):' || true)
[ -n "$old_san" ] || die "기존 인증서에서 SAN을 읽지 못했어요 (그대로 유지할 값이 없으면 중단합니다)"
san=$( { echo "$old_san"; for ip in "${ADD_IP[@]:-}"; do [ -n "$ip" ] && echo "IP:$ip"; done; for d in "${ADD_DNS[@]:-}"; do [ -n "$d" ] && echo "DNS:$d"; done; true; } | awk '!seen[$0]++' | paste -sd, -)

echo "대상 디렉터리 : $TLS_DIR"
echo "새 SAN        : $san"
echo "유효기간      : ${DAYS}일, 같은 CA로 서명"
echo "백업          : $TLS_DIR/backup-<시각>/ (기존 tls.crt, tls.key)"
echo "교체 방식     : 임시 이름으로 쓴 뒤 mv (키 → 인증서 순서)"
if [ "$PLAN" = 1 ]; then echo "[plan] 아무것도 바꾸지 않았어요."; exit 0; fi

if [ "$YES" != 1 ]; then
  read -r -p "진행할까요? [y/N] " ans || ans=""
  [ "$ans" = y ] || [ "$ans" = Y ] || { echo "취소했어요."; exit 1; }
fi

W=$(mktemp -d); chmod 700 "$W"; trap 'rm -rf "$W"' EXIT
TS=$(date -u +%Y%m%dT%H%M%SZ)
BK="$TLS_DIR/backup-$TS"
install -d -m 700 "$BK"
cp -p "$TLS_DIR/tls.crt" "$TLS_DIR/tls.key" "$BK/"

openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEY_BITS" -out "$W/new.key" 2>/dev/null
openssl req -new -key "$W/new.key" -out "$W/new.csr" -subj "/CN=kms-transit"
cat >"$W/new.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EXT
openssl x509 -req -in "$W/new.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$W/ca.srl" \
  -days "$DAYS" -sha256 -extfile "$W/new.ext" -out "$W/new.crt" 2>/dev/null
openssl verify -CAfile "$CA_CERT" "$W/new.crt" >/dev/null || die "새 인증서가 CA 검증에 실패했어요 (교체하지 않음)"

# 새 파일은 같은 디렉터리에 임시 이름으로 두고 소유자/권한을 기존 파일과 맞춘 뒤 mv로 교체
install -m "$(stat -c %a "$TLS_DIR/tls.key")" "$W/new.key" "$TLS_DIR/.tls.key.new"
install -m "$(stat -c %a "$TLS_DIR/tls.crt")" "$W/new.crt" "$TLS_DIR/.tls.crt.new"
chown --reference="$TLS_DIR/tls.key" "$TLS_DIR/.tls.key.new" 2>/dev/null || true
chown --reference="$TLS_DIR/tls.crt" "$TLS_DIR/.tls.crt.new" 2>/dev/null || true
mv "$TLS_DIR/.tls.key.new" "$TLS_DIR/tls.key"
mv "$TLS_DIR/.tls.crt.new" "$TLS_DIR/tls.crt"

echo "교체 완료. KMS는 30초 이내에 새 인증서를 읽습니다 (재시작 불필요). 백업: $BK"
openssl x509 -in "$TLS_DIR/tls.crt" -noout -enddate -ext subjectAltName
