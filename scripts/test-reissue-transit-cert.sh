#!/usr/bin/env bash
# reissue-transit-cert.sh 테스트: 임시 CA/인증서로 SAN 유지·추가, 백업, 원자적 교체, --plan, 확인 거부를 확인한다.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
S=$PWD/scripts/reissue-transit-cert.sh
export KEY_BITS=2048
cd "$W"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
openssl req -x509 -new -sha256 -days 30 -key ca.key -out ca.crt -subj '/CN=Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
mkdir tls
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out tls/tls.key 2>/dev/null
openssl req -new -key tls/tls.key -out t.csr -subj '/CN=kms-transit'
printf 'subjectAltName=DNS:kms-transit,DNS:kms-transit.kube-system.svc,IP:127.0.0.1,IP:10.1.2.3\n' >t.ext
openssl x509 -req -in t.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 5 -out tls/tls.crt -extfile t.ext 2>/dev/null
chmod 640 tls/tls.crt tls/tls.key
before_crt=$(sha256sum tls/tls.crt | cut -d' ' -f1)

# --plan: 아무것도 바뀌지 않는다
$S --ca-cert ca.crt --ca-key ca.key --tls-dir tls --add-ip 192.0.2.77 --plan | grep -q 'IP:192.0.2.77'
[ "$(sha256sum tls/tls.crt | cut -d' ' -f1)" = "$before_crt" ]
! ls tls | grep -q backup

# 확인에서 N(또는 빈 입력)이면 취소
if echo n | $S --ca-cert ca.crt --ca-key ca.key --tls-dir tls --add-ip 192.0.2.77 >/dev/null 2>&1; then echo "N인데 진행됨"; exit 1; fi
[ "$(sha256sum tls/tls.crt | cut -d' ' -f1)" = "$before_crt" ]

# 잘못된 입력 거부
if $S --ca-cert ca.crt --ca-key ca.key --tls-dir tls --add-ip 999.1.1.1 --plan >/dev/null 2>&1; then echo "잘못된 IP 통과"; exit 1; fi
if $S --ca-cert ca.crt --ca-key ca.key --tls-dir tls --add-dns 'a b;c' --plan >/dev/null 2>&1; then echo "잘못된 DNS 통과"; exit 1; fi

# 실제 실행
echo y | $S --ca-cert ca.crt --ca-key ca.key --tls-dir tls --add-ip 192.0.2.77 --add-dns api.example.test --days 30 >out.txt
san=$(openssl x509 -in tls/tls.crt -noout -ext subjectAltName)
for want in 'DNS:kms-transit' 'DNS:kms-transit.kube-system.svc' '127.0.0.1' '10.1.2.3' '192.0.2.77' 'DNS:api.example.test'; do
  echo "$san" | grep -q "$want" || { echo "SAN에 $want 없음"; exit 1; }
done
openssl verify -CAfile ca.crt tls/tls.crt >/dev/null
# 키와 인증서가 짝이 맞는다
[ "$(openssl x509 -in tls/tls.crt -noout -pubkey | sha256sum)" = "$(openssl pkey -in tls/tls.key -pubout | sha256sum)" ]
# 백업: 옛 인증서가 보존되어 있다
bk=$(ls -d tls/backup-*)
[ "$(sha256sum "$bk/tls.crt" | cut -d' ' -f1)" = "$before_crt" ]
[ "$(stat -c %a tls/tls.crt)" = 640 ] && [ "$(stat -c %a tls/tls.key)" = 640 ] && [ "$(stat -c %a "$bk")" = 700 ]
# 임시 파일이 남지 않는다
! ls -a tls | grep -q '\.new'
# 끝에 만료일과 SAN을 보여 준다
grep -q notAfter out.txt && grep -q 'IP Address:192.0.2.77' out.txt
echo "reissue-transit-cert 테스트 통과"
