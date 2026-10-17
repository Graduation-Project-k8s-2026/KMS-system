#!/usr/bin/env bash
# build-cli.sh + install.sh 테스트: 로컬 file:// 주소로 정상 설치, 체크섬 불일치·SHA256SUMS 누락·N 응답이면 설치 안 됨.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
case "$(uname -s)-$(uname -m)" in Linux-x86_64) T=linux/amd64 ;; Linux-aarch64) T=linux/arm64 ;; Darwin-arm64) T=darwin/arm64 ;; *) echo "skip: 이 플랫폼은 테스트 대상이 아님"; exit 0 ;; esac
OUT="$W/dist" TARGETS="$T windows/amd64" VERSION=vtest scripts/build-cli.sh >/dev/null
[ -f "$W/dist/SHA256SUMS" ] && grep -q 'kms-windows-amd64.exe' "$W/dist/SHA256SUMS"
export HOME="$W/home"; mkdir -p "$HOME"
D="$W/bin"

# 정상 설치
echo y | KMS_INSTALL_DIR="$D" ./install.sh "file://$W/dist" >/dev/null 2>&1
[ -x "$D/kms" ] && "$D/kms" version | grep -q 'vtest'
rm -rf "$D"

# N이면 설치 안 함
if echo n | KMS_INSTALL_DIR="$D" ./install.sh "file://$W/dist" >/dev/null 2>&1; then echo "N인데 설치됨"; exit 1; fi
[ ! -e "$D/kms" ]

# 체크섬 불일치 → 아무것도 설치하지 않는다 (y를 답해도 그 전에 중단)
cp -r "$W/dist" "$W/bad"; echo tampered >> "$W/bad/kms-${T%/*}-${T#*/}"
if echo y | KMS_INSTALL_DIR="$D" ./install.sh "file://$W/bad" >/dev/null 2>&1; then echo "변조된 바이너리가 설치됨"; exit 1; fi
[ ! -e "$D" ] || [ ! -e "$D/kms" ]

# SHA256SUMS 없음 / 항목 없음
rm "$W/bad/SHA256SUMS"
if echo y | KMS_INSTALL_DIR="$D" ./install.sh "file://$W/bad" >/dev/null 2>&1; then echo "SUMS 없이 설치됨"; exit 1; fi
echo "other  kms-nothing" > "$W/bad/SHA256SUMS"
if echo y | KMS_INSTALL_DIR="$D" ./install.sh "file://$W/bad" >/dev/null 2>&1; then echo "항목 없이 설치됨"; exit 1; fi
# 주소 없음
if ./install.sh >/dev/null 2>&1; then echo "주소 없이 통과"; exit 1; fi
[ ! -e "$D/kms" ]
echo "install-cli 테스트 통과"
