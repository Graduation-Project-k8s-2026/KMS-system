#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: scripts/verify-release-contract.sh [--help]"
  echo "Run local configuration, handler, CLI and script contracts; never deploys."
  echo "Exit: 0 success; 2 invalid arguments; other nonzero means verification failed."
  exit 0
fi
if (( $# )); then
  echo "Unsupported argument; use --help" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
go test ./... -count=1
python3 -m unittest discover -s scripts -p 'test_*.py'
