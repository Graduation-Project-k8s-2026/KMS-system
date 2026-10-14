#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: scripts/test-kmsv2.sh [--help]"
  echo "Run official KMS v2 local RPC, error, rotation and restart tests; never connects apiserver."
  echo "Exit: 0 success; 2 invalid arguments; other nonzero means verification failed."
  exit 0
fi
if (( $# )); then
  echo "Unsupported argument; use --help" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
go test -race ./internal/kmsv2 -count=1
