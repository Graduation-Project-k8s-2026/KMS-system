#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: scripts/test-kmsv2.sh [--help] | --socket PATH [--save FILE] [--read FILE] [--require-key-change]"
  echo "Without arguments: local official RPC tests. With --socket: probe running server using KMS_VERIFY_BIN (default /home/ubuntu/kms-tools/kms-verify). Never modifies apiserver."
  echo "Exit: 0 success; 2 invalid arguments; other nonzero means verification failed."
  exit 0
fi
if [[ "${1:-}" == "--socket" ]]; then
  exec "${KMS_VERIFY_BIN:-/home/ubuntu/kms-tools/kms-verify}" "$@"
fi
if (( $# )); then
  echo "Unsupported argument; use --help" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
go test -race ./internal/kmsv2 -count=1
