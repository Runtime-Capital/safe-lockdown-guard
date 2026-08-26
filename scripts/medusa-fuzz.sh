#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Prefer the self-contained Slither environment over a potentially stale or
# partially-installed user-level crytic-compile entrypoint.
UV_SLITHER_BIN="$HOME/.local/share/uv/tools/slither-analyzer/bin"
[ -d "$UV_SLITHER_BIN" ] && PATH="$UV_SLITHER_BIN:$PATH"

MEDUSA_BIN="${MEDUSA_BIN:-}"
if [[ -z "$MEDUSA_BIN" ]]; then
  if command -v medusa >/dev/null 2>&1; then
    MEDUSA_BIN="$(command -v medusa)"
  elif [[ -x "$HOME/go/bin/medusa" ]]; then
    MEDUSA_BIN="$HOME/go/bin/medusa"
  fi
fi

if [[ -z "$MEDUSA_BIN" ]]; then
  echo "medusa not installed; install with: go install github.com/crytic/medusa@latest"
  exit 0
fi

WORKERS="${MEDUSA_WORKERS:-$(nproc)}"
TEST_LIMIT="${MEDUSA_TEST_LIMIT:-500000}"
SEQ_LEN="${MEDUSA_SEQ_LEN:-80}"
CORPUS_DIR="${MEDUSA_CORPUS_DIR:-medusa-corpus}"
TARGET="${MEDUSA_TARGET:-EchidnaLockdown}"
COMPILATION_TARGET="${MEDUSA_COMPILATION_TARGET:-test/echidna/EchidnaLockdown.sol}"

mkdir -p "$CORPUS_DIR"

"$MEDUSA_BIN" fuzz \
  --config medusa.json \
  --compilation-target "$COMPILATION_TARGET" \
  --target-contracts "$TARGET" \
  --workers "$WORKERS" \
  --test-limit "$TEST_LIMIT" \
  --seq-len "$SEQ_LEN" \
  --corpus-dir "$CORPUS_DIR" \
  --use-slither \
  --fail-fast
