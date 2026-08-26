#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CHAIN_ID="${CHAIN_ID:-1}"
CONTRACT="${CONTRACT:-src/LockdownTimelock.sol:LockdownTimelock}"
ADDRESS="${LOCKDOWN_DEPLOYED_ADDRESS:-}"
CONSTRUCTOR_ARGS="${LOCKDOWN_CONSTRUCTOR_ARGS:-}"
SOURCIFY_URL="${SOURCIFY_URL:-https://sourcify.dev/server}"

echo "== Sourcify rehearsal =="
echo "Contract: $CONTRACT"
echo "Chain ID: $CHAIN_ID"
echo "Sourcify URL: $SOURCIFY_URL"

forge build --build-info --force >/dev/null

if [[ -z "$ADDRESS" ]]; then
  cat <<EOF
No LOCKDOWN_DEPLOYED_ADDRESS set, so this is a dry rehearsal only.

After deploying a candidate, run:

  LOCKDOWN_DEPLOYED_ADDRESS=0x... \\
  LOCKDOWN_CONSTRUCTOR_ARGS=0x... \\
  CHAIN_ID=$CHAIN_ID \\
  scripts/sourcify-rehearsal.sh

The script will call:

  forge verify-contract \\
    --verifier sourcify \\
    --verifier-url $SOURCIFY_URL \\
    --chain-id $CHAIN_ID \\
    <address> $CONTRACT \\
    --constructor-args <abi-encoded-constructor-args> \\
    --watch
EOF
  exit 0
fi

if [[ -z "$CONSTRUCTOR_ARGS" ]]; then
  echo "LOCKDOWN_CONSTRUCTOR_ARGS is required for deployed verification." >&2
  echo "It must be the ABI-encoded Lockdown constructor arguments." >&2
  exit 1
fi

forge verify-contract \
  --verifier sourcify \
  --verifier-url "$SOURCIFY_URL" \
  --chain-id "$CHAIN_ID" \
  "$ADDRESS" "$CONTRACT" \
  --constructor-args "$CONSTRUCTOR_ARGS" \
  --watch
