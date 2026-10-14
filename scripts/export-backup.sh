#!/usr/bin/env bash
# Interactive encryption only. Download ciphertext to a DIFFERENT machine and verify SHA256 there.
set -euo pipefail
umask 077
if [[ "${1:-}" == --final && $# == 1 ]]; then
  set -- /var/backups/custom-kms/final-kms-v2-20261011T1616Z /home/ubuntu/kms-final-v2-backup.tar.gpg
  if [[ -f "$2" && -f "$2.sha256" ]]; then
    (cd "$(dirname "$2")" && sha256sum -c "$(basename "$2").sha256")
    exit 0
  fi
fi
if [[ $# != 2 || "$1" == --help ]]; then
  echo 'Usage: sudo scripts/export-backup.sh /var/backups/custom-kms/ID /home/ubuntu/ID.tar.gpg'
  echo 'Enter a new backup passphrase at the local TTY; keep it separately from the backup.'
  exit 2
fi
[[ -t 0 && -d "$1" && -f "$1/checksums.json" && ! -e "$2" ]] || { echo 'TTY, completed backup and new output required' >&2; exit 1; }
python3 - "$1" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);s=json.loads((p/'state.json').read_text());assert s['complete']
for n,h in json.loads((p/'checksums.json').read_text()).items():
 assert pathlib.Path(n).name==n
 assert hashlib.sha256((p/n).read_bytes()).hexdigest()==h
PY
export GPG_TTY
GPG_TTY=$(tty)
partial="$2.partial"
[[ ! -e "$partial" ]] || { echo 'Partial output exists; inspect before retry' >&2; exit 1; }
tar -C "$(dirname "$1")" -cf - "$(basename "$1")" | gpg --no-symkey-cache --cipher-algo AES256 --symmetric --output "$partial"
mv "$partial" "$2"
(cd "$(dirname "$2")" && sha256sum "$(basename "$2")") > "$2.sha256"
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$2" "$2.sha256"
echo 'Encrypted archive prepared. External backup is NOT verified until transfer and destination checksum succeed.'
