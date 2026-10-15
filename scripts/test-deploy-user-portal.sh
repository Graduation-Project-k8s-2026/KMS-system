#!/usr/bin/env bash
# deploy-user-portal.sh --plan(서버 없이 파일만 만드는 모드)이 올바른 매니페스트를 만드는지 확인한다.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
GUI_FQDN=kms.example.test WORKDIR="$W/up" scripts/deploy-user-portal.sh --plan >/dev/null
f="$W/up/demo-app.yaml"
grep -q 'value: https://kms.example.test:8443' "$f"
grep -q 'image: docker.io/library/kms-demo-app@sha256:[a-f0-9]\{64\}' "$f"
grep -q 'value: demo,campus-shipping' "$f"
! grep -q '\${' "$f"
[ "$(stat -c %a "$W/up/tls.key")" = 600 ] && [ "$(stat -c %a "$f")" = 600 ]
# 태그@digest 형식 이미지는 거부돼야 한다
if GUI_FQDN=kms.example.test WORKDIR="$W/bad" DEMO_IMAGE='kms-demo-app:latest@sha256:abc' scripts/deploy-user-portal.sh --plan >/dev/null 2>&1; then echo "잘못된 이미지가 통과함"; exit 1; fi
# 위험한 문자가 든 키 목록도 거부
if GUI_FQDN=kms.example.test WORKDIR="$W/bad2" DEMO_KEYS='a;b' scripts/deploy-user-portal.sh --plan >/dev/null 2>&1; then echo "잘못된 DEMO_KEYS가 통과함"; exit 1; fi
echo "deploy-user-portal --plan 테스트 통과"
