#!/usr/bin/env bash
# Run on an approved human tailnet device. Serve supplies identity; no JWT input.
set -euo pipefail
exec python3 "$(dirname "$0")/create-bench-fixture.py" "$@"
