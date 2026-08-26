#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v semgrep >/dev/null 2>&1; then
  SEMGREP=(semgrep)
elif command -v uvx >/dev/null 2>&1; then
  SEMGREP=(uvx semgrep)
else
  echo "semgrep not installed and uvx unavailable; skipping"
  exit 0
fi

# Semgrep 1.168.0's default shared-memory/Eio backend can fail on this
# workstation with `io_uring_queue_init` allocation errors. The legacy parmap
# backend is slower but stable for this small Solidity scope.
"${SEMGREP[@]}" \
  --config p/smart-contracts \
  --config semgrep/safe-guard.yml \
  --x-parmap \
  --exclude-rule solidity.performance.array-length-outside-loop.array-length-outside-loop \
  --exclude-rule solidity.performance.inefficient-state-variable-increment.inefficient-state-variable-increment \
  --exclude-rule solidity.performance.non-payable-constructor.non-payable-constructor \
  --exclude-rule solidity.performance.state-variable-read-in-a-loop.state-variable-read-in-a-loop \
  --exclude-rule solidity.performance.unnecessary-checked-arithmetic-in-loop.unnecessary-checked-arithmetic-in-loop \
  --exclude-rule solidity.performance.use-multiple-require.use-multiple-require \
  --exclude-rule solidity.performance.use-nested-if.use-nested-if \
  src
