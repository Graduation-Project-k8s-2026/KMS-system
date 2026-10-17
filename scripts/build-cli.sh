#!/usr/bin/env bash
# kms CLI를 여러 플랫폼용으로 빌드해 dist/ 에 바이너리와 SHA256SUMS 를 만든다.
#   scripts/build-cli.sh                 linux/amd64, linux/arm64, darwin/arm64, windows/amd64
#   TARGETS="linux/amd64" scripts/build-cli.sh   일부만 (테스트용)
#   VERSION=v1.2.3 scripts/build-cli.sh  버전 문자열 (기본: git describe 또는 dev)
# CGO 없이 정적 빌드(-trimpath)하므로 대상 머신에 별도 라이브러리가 필요 없다. dist/ 는 .gitignore 대상이다.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT=${OUT:-dist}
TARGETS=${TARGETS:-"linux/amd64 linux/arm64 darwin/arm64 windows/amd64"}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
rm -rf "$OUT"; mkdir -p "$OUT"
for t in $TARGETS; do
  os=${t%/*}; arch=${t#*/}
  name="kms-$os-$arch"; [ "$os" = windows ] && name="$name.exe"
  echo "build $name ($VERSION)"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/$name" ./cmd/kms
done
(cd "$OUT" && sha256sum kms-* > SHA256SUMS)
echo "완료: $OUT/ ($(wc -l < "$OUT/SHA256SUMS")개 + SHA256SUMS)"
