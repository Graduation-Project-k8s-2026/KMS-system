#!/usr/bin/env bash
# kms CLI 설치 스크립트.
#   KMS_CLI_URL=<배포 주소> ./install.sh            또는   ./install.sh <배포 주소>
#   (배포 주소 아래에 kms-<os>-<arch> 와 SHA256SUMS 가 있어야 한다. 실제 주소는 관리자에게 받으세요: <배포 URL>)
# 동작: OS·아키텍처 감지 → 바이너리와 SHA256SUMS 다운로드 → sha256 검증 → 설치 경로 확인 [y/N] → 설치.
# 검증에 실패하면 아무것도 설치하지 않는다. 기본 설치 경로는 ~/.local/bin (sudo 불필요, KMS_INSTALL_DIR 로 변경).
set -euo pipefail

BASE=${1:-${KMS_CLI_URL:-}}
[ -n "$BASE" ] || { echo "배포 주소가 필요해요: KMS_CLI_URL=<배포 URL> ./install.sh   (실제 주소는 관리자에게 문의)" >&2; exit 2; }
BASE=${BASE%/}
DEST=${KMS_INSTALL_DIR:-$HOME/.local/bin}

case "$(uname -s)" in
  Linux) os=linux ;; Darwin) os=darwin ;;
  *) echo "이 스크립트는 Linux/macOS용이에요. Windows는 kms-windows-amd64.exe 를 직접 받아 SHA256SUMS 와 비교하세요." >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;;
  *) echo "지원하지 않는 아키텍처: $(uname -m)" >&2; exit 2 ;;
esac
name="kms-$os-$arch"

fetch() {  # fetch <url> <파일>
  if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null; then wget -q "$1" -O "$2"
  else echo "curl 또는 wget 이 필요해요" >&2; return 1; fi
}

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
echo "다운로드: $name"
fetch "$BASE/$name" "$W/$name" || { echo "바이너리를 받지 못했어요 (주소와 플랫폼을 확인하세요)" >&2; exit 1; }
fetch "$BASE/SHA256SUMS" "$W/SHA256SUMS" || { echo "SHA256SUMS 를 받지 못했어요. 검증할 수 없으니 설치하지 않아요" >&2; exit 1; }

want=$(awk -v n="$name" '$2==n || $2=="*"n {print $1}' "$W/SHA256SUMS")
[ -n "$want" ] || { echo "SHA256SUMS 에 $name 항목이 없어요. 설치하지 않아요" >&2; exit 1; }
if command -v sha256sum >/dev/null; then got=$(sha256sum "$W/$name" | cut -d' ' -f1); else got=$(shasum -a 256 "$W/$name" | cut -d' ' -f1); fi
if [ "$got" != "$want" ]; then
  echo "체크섬이 일치하지 않아요 — 변조되었거나 손상된 파일일 수 있어요. 아무것도 설치하지 않았어요." >&2
  exit 1
fi
echo "체크섬 확인 완료 ($want)"

echo "설치 경로: $DEST/kms"
read -r -p "설치할까요? [y/N] " ans || ans=""
[ "$ans" = y ] || [ "$ans" = Y ] || { echo "취소했어요."; exit 1; }
mkdir -p "$DEST"
install -m 0755 "$W/$name" "$DEST/kms.new"
mv "$DEST/kms.new" "$DEST/kms"
echo "설치 완료: $DEST/kms"
case ":$PATH:" in *":$DEST:"*) ;; *) echo "참고: $DEST 가 PATH에 없어요. 셸 설정에 추가하세요: export PATH=\"$DEST:\$PATH\"" ;; esac
"$DEST/kms" version || true
