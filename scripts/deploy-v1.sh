#!/usr/bin/env bash
#
# deploy-v1.sh
#
# Deterministic CREATE2 deploy of the V1 Lockdown singleton through the
# Arachnid proxy (script/DeployLockdown.s.sol), then verify the deployed
# runtime on Etherscan (inline) and Sourcify (follow-up via
# sourcify-rehearsal.sh). BROADCASTS a real transaction unless --dry-run.
#
# Signing is passed through to forge after `--`, so the operator picks the
# key custody (hardware wallet strongly preferred for a production singleton):
#   scripts/deploy-v1.sh --rpc <url> --multi-send <addr> -- --ledger
#   scripts/deploy-v1.sh --rpc <url> --multi-send <addr> -- --account deployer
#
# Usage:
#   scripts/deploy-v1.sh --rpc <url> --multi-send <addr> \
#       [--salt <bytes32>] [--chain-id <id>] [--dry-run] \
#       [--no-etherscan] [--no-sourcify] [-- <forge signing args>]
#
# Env:
#   ETHERSCAN_API_KEY   required for Etherscan verification (unless --no-etherscan)
#   SOURCIFY_URL        override Sourcify server (default https://sourcify.dev/server)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RPC=""
MULTI_SEND=""
SALT="0x0000000000000000000000000000000000000000000000000000000000000000"
CHAIN_ID=""
DRY_RUN=0
ETHERSCAN=1
SOURCIFY=1
SOURCIFY_URL="${SOURCIFY_URL:-https://sourcify.dev/server}"
FORGE_ARGS=()

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc) RPC="$2"; shift 2 ;;
        --multi-send) MULTI_SEND="$2"; shift 2 ;;
        --salt) SALT="$2"; shift 2 ;;
        --chain-id) CHAIN_ID="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --no-etherscan) ETHERSCAN=0; shift ;;
        --no-sourcify) SOURCIFY=0; shift ;;
        -h|--help) usage 0 ;;
        --) shift; FORGE_ARGS=("$@"); break ;;
        *) echo "unknown arg: $1" >&2; usage 1 ;;
    esac
done

[[ -n "$RPC" && -n "$MULTI_SEND" ]] || { echo "--rpc and --multi-send are required" >&2; usage 1; }
[[ -n "$CHAIN_ID" ]] || CHAIN_ID="$(cast chain-id --rpc-url "$RPC")"

export MULTI_SEND_CALL_ONLY="$MULTI_SEND"
export LOCKDOWN_SALT="$SALT"

echo "== V1 singleton deploy =="
echo "RPC              : $RPC"
echo "Chain ID         : $CHAIN_ID"
echo "MultiSendCallOnly: $MULTI_SEND"
echo "Salt             : $SALT"

if [[ "$DRY_RUN" == 1 ]]; then
    echo "== DRY RUN (simulation only, no broadcast) =="
    forge script script/DeployLockdown.s.sol --rpc-url "$RPC" "${FORGE_ARGS[@]}"
    exit 0
fi

VERIFY_FLAGS=()
if [[ "$ETHERSCAN" == 1 ]]; then
    : "${ETHERSCAN_API_KEY:?set ETHERSCAN_API_KEY for Etherscan verification, or pass --no-etherscan}"
    VERIFY_FLAGS=(--verify --verifier etherscan --etherscan-api-key "$ETHERSCAN_API_KEY")
fi

echo "== Broadcasting deploy =="
forge script script/DeployLockdown.s.sol \
    --rpc-url "$RPC" --broadcast "${VERIFY_FLAGS[@]}" "${FORGE_ARGS[@]}"

# Recover the deployed address from forge's broadcast artifact (canonical
# record of what actually landed on chain).
RUN="broadcast/DeployLockdown.s.sol/$CHAIN_ID/run-latest.json"
ADDR="$(jq -r '.transactions[] | select(.contractName == "LockdownTimelock") | .contractAddress' "$RUN" | head -1)"
[[ -n "$ADDR" && "$ADDR" != "null" ]] || { echo "could not read deployed address from $RUN" >&2; exit 1; }
echo "Deployed singleton: $ADDR"

if [[ "$SOURCIFY" == 1 ]]; then
    echo "== Sourcify verification =="
    LOCKDOWN_DEPLOYED_ADDRESS="$ADDR" \
    LOCKDOWN_CONSTRUCTOR_ARGS="$(cast abi-encode 'x(address)' "$MULTI_SEND")" \
    CHAIN_ID="$CHAIN_ID" \
    SOURCIFY_URL="$SOURCIFY_URL" \
        scripts/sourcify-rehearsal.sh
fi

echo "== Done. Pin the printed EXTCODEHASH into deploy/manifest.json, then run scripts/verify-install-v1.sh =="
