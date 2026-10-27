#!/usr/bin/env bash
#
# operator-e2e-anvil.sh
#
# End-to-end test of scripts/preflight-install-v1.sh and
# scripts/verify-install-v1.sh against REAL deployed bytecode on a throwaway
# anvil chain (no mocked eth_getCode):
#
#   1. Deploy the canonical Safe v1.5.0 singleton, SafeProxyFactory and
#      MultiSendCallOnly at their canonical addresses from the exact
#      Safe Singleton Factory payloads in script/helpers/SafeDeployer.sol.
#   2. Deploy LockdownTimelock + LockdownFallbackHandler with the production
#      script/DeployLockdown.s.sol.
#   3. Create two 1-of-1 Safes through the proxy factory.
#   4. Build a per-chain manifest from codehashes read on-chain with cast.
#   5. Assert:
#        - preflight PASSES with every pin and writes an owner/module snapshot
#        - preflight FAILS when the manifest's safeMasterCopyCodehash is a
#          0xFILL placeholder
#        - the real install batch (MultiSend: setGuard, setModuleGuard,
#          setFallbackHandler, initialize) executes through execTransaction
#        - verify FAILS on the resulting dormant install, PASSES with
#          --allow-dormant, and PASSES without it once a signer is added
#        - verify FAILS with a placeholder masterCopy pin
#        - an install batch that also slips in addOwnerWithThreshold and
#          enableModule FAILS verify --snapshot on owners, threshold and
#          modules, and is only WARNed (not compared) without a snapshot
#
# Uses anvil's unlocked dev accounts (no private key in this repo). Read-only
# towards everything except the throwaway anvil instance it starts and stops.
#
# Usage: scripts/operator-e2e-anvil.sh [--keep-logs]
#   ANVIL_PORT=<port> overrides the port (default: a free port in 20000-29999)
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEEP_LOGS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-logs) KEEP_LOGS=1; shift ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

for tool in anvil cast forge jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is required (Foundry + jq)" >&2; exit 1
    fi
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/safe-lockdown-e2e.XXXXXX")"
ANVIL_PID=""
cleanup() {
    local rc=$?
    if [[ -n "$ANVIL_PID" ]]; then kill "$ANVIL_PID" 2>/dev/null || true; wait "$ANVIL_PID" 2>/dev/null || true; fi
    if [[ "$KEEP_LOGS" -eq 1 || "$rc" -ne 0 ]]; then
        echo "logs kept in $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
    exit "$rc"
}
trap cleanup EXIT

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
PORT="${ANVIL_PORT:-}"
if [[ -z "$PORT" ]]; then
    for _ in $(seq 1 50); do
        candidate=$((20000 + RANDOM % 10000))
        if port_free "$candidate"; then PORT="$candidate"; break; fi
    done
fi
[[ -n "$PORT" ]] || { echo "no free port for anvil" >&2; exit 1; }
RPC="http://127.0.0.1:$PORT"

anvil --port "$PORT" --hardfork prague --chain-id 31337 >"$WORKDIR/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 100); do
    if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || { echo "anvil did not start" >&2; cat "$WORKDIR/anvil.log" >&2; exit 1; }

PASSED=0
step() { printf '\n== %s\n' "$*"; }
die() { echo "E2E FAILURE: $*" >&2; exit 1; }
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

# expect_exit <exit-code> <number-of-[FAIL]-lines> <name> [needle...] -- <cmd...>
# Asserts the exit code, the exact number of [FAIL] lines (so a negative case
# cannot pass for an unrelated reason) and that every fixed-string needle
# appears in the output.
expect_exit() {
    local want="$1" want_fails="$2" name="$3"; shift 3
    local needles=()
    while [[ "$1" != "--" ]]; do needles+=("$1"); shift; done
    shift
    local log rc=0 fails needle
    log="$WORKDIR/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').log"
    "$@" >"$log" 2>&1 || rc=$?
    fails=$(grep -c '^  \[FAIL\]' "$log" || true)
    if [[ "$rc" -ne "$want" || "$fails" -ne "$want_fails" ]]; then
        cat "$log" >&2
        die "$name: exit $rc with $fails [FAIL] line(s), expected exit $want with $want_fails"
    fi
    for needle in "${needles[@]}"; do
        if ! grep -qF -- "$needle" "$log"; then
            cat "$log" >&2
            die "$name: output lacks '$needle'"
        fi
    done
    PASSED=$((PASSED + 1))
    printf '  [ok] %s (exit %s, %s FAIL)\n' "$name" "$rc" "$fails"
}

mapfile -t ACCOUNTS < <(cast rpc eth_accounts --rpc-url "$RPC" | jq -r '.[]')
OWNER="${ACCOUNTS[0]}"
RECOVERY_OWNER="${ACCOUNTS[1]}"
ATTACKER="${ACCOUNTS[2]}"
LOCKDOWN_SIGNER=$(lower "${ACCOUNTS[3]}")
send() { cast send --unlocked --from "$OWNER" --rpc-url "$RPC" "$@" >/dev/null; }

# ---------------------------------------------------------------------------
step "Deploy canonical Safe v1.5.0 contracts (exact SafeDeployer payloads)"
# ---------------------------------------------------------------------------
# Extract a `hex"..."` constant that follows `<NAME> =` in a Solidity file.
sol_hex_const() {
    awk -v name="$2" '
        index($0, name " =") { found = 1 }
        found && match($0, /hex"[0-9a-fA-F]*"/) {
            print "0x" substr($0, RSTART + 4, RLENGTH - 5); exit
        }' "$1"
}
SAFE_FACTORY="0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7"
SAFE_FACTORY_CODE=$(sol_hex_const script/helpers/FactoryDeployers.sol FACTORY_BYTECODE)
[[ ${#SAFE_FACTORY_CODE} -gt 10 ]] || die "could not read Safe Singleton Factory bytecode"
# The Safe Singleton Factory is a presigned-per-chain deployment; anvil has no
# such presigned tx, so place its (keyless, well-known) runtime directly.
cast rpc anvil_setCode "$SAFE_FACTORY" "$SAFE_FACTORY_CODE" --rpc-url "$RPC" >/dev/null

SAFE_SINGLETON="0xFf51A5898e281Db6DfC7855790607438dF2ca44b"
SAFE_PROXY_FACTORY="0x14F2982D601c9458F93bd70B218933A6f8165e7b"
MULTI_SEND="0xA83c336B20401Af773B6219BA5027174338D1836"
for pair in "SAFE_SETUP_CALLDATA:$SAFE_SINGLETON" \
            "SAFE_PROXY_FACTORY_SETUP_CALLDATA:$SAFE_PROXY_FACTORY" \
            "MULTI_SEND_CALL_ONLY_SETUP_CALLDATA:$MULTI_SEND"; do
    payload=$(sol_hex_const script/helpers/SafeDeployer.sol "${pair%%:*}")
    [[ ${#payload} -gt 10 ]] || die "could not read ${pair%%:*}"
    send "$SAFE_FACTORY" "$payload"
    [[ "$(cast code "${pair#*:}" --rpc-url "$RPC")" != "0x" ]] || die "${pair%%:*} did not deploy at ${pair#*:}"
done
echo "  Safe singleton $SAFE_SINGLETON, proxy factory $SAFE_PROXY_FACTORY, MultiSendCallOnly $MULTI_SEND"

# ---------------------------------------------------------------------------
step "Deploy Lockdown singleton + fallback handler (script/DeployLockdown.s.sol)"
# ---------------------------------------------------------------------------
FOUNDRY_BROADCAST="$WORKDIR/broadcast" MULTI_SEND_CALL_ONLY="$MULTI_SEND" forge script script/DeployLockdown.s.sol:DeployLockdown \
    --rpc-url "$RPC" --unlocked --sender "$OWNER" --broadcast --slow \
    >"$WORKDIR/deploy.log" 2>&1 || { cat "$WORKDIR/deploy.log" >&2; die "DeployLockdown failed"; }
SINGLETON=$(sed -n 's/.*Predicted guard: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' "$WORKDIR/deploy.log" | head -n1)
HANDLER=$(sed -n 's/.*Predicted handler: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' "$WORKDIR/deploy.log" | head -n1)
[[ -n "$SINGLETON" && -n "$HANDLER" ]] || { cat "$WORKDIR/deploy.log" >&2; die "could not parse deployed addresses"; }
[[ "$(cast code "$SINGLETON" --rpc-url "$RPC")" != "0x" ]] || die "singleton has no code"
[[ "$(cast code "$HANDLER" --rpc-url "$RPC")" != "0x" ]] || die "handler has no code"
echo "  LockdownTimelock $SINGLETON, LockdownFallbackHandler $HANDLER"

# ---------------------------------------------------------------------------
step "Create two 1-of-1 Safes and pin real codehashes"
# ---------------------------------------------------------------------------
SETUP_DATA=$(cast calldata "setup(address[],uint256,address,bytes,address,address,uint256,address)" \
    "[$OWNER]" 1 0x0000000000000000000000000000000000000000 0x \
    0x0000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000 0 \
    0x0000000000000000000000000000000000000000)
create_safe() {
    local nonce="$1" addr
    addr=$(cast call "$SAFE_PROXY_FACTORY" "createProxyWithNonce(address,bytes,uint256)(address)" \
        "$SAFE_SINGLETON" "$SETUP_DATA" "$nonce" --from "$OWNER" --rpc-url "$RPC")
    send "$SAFE_PROXY_FACTORY" "createProxyWithNonce(address,bytes,uint256)" "$SAFE_SINGLETON" "$SETUP_DATA" "$nonce"
    [[ "$(cast call "$addr" "VERSION()(string)" --rpc-url "$RPC")" == '"1.5.0"' ]] || die "Safe $addr not v1.5.0"
    printf '%s' "$addr"
}
SAFE_A=$(create_safe 1)
SAFE_B=$(create_safe 2)
echo "  Safe A $SAFE_A, Safe B $SAFE_B (owner $OWNER, threshold 1)"

codehash() { cast keccak "$(cast code "$1" --rpc-url "$RPC")"; }
SAFE_MC_HASH=$(codehash "$SAFE_SINGLETON")
MULTI_SEND_HASH=$(codehash "$MULTI_SEND")
SINGLETON_HASH=$(codehash "$SINGLETON")
HANDLER_HASH=$(codehash "$HANDLER")

write_manifest() {
    jq -n --arg mc "$1" --arg ms "$MULTI_SEND_HASH" --arg sg "$SINGLETON_HASH" \
        --arg fh "$HANDLER_HASH" --arg fa "$HANDLER" --arg msa "$MULTI_SEND" --arg sa "$SINGLETON" \
        '{chains: {"31337": {multiSendAddress: $msa, multiSendCodehash: $ms,
          fallbackHandlerAddress: $fa, fallbackHandlerCodehash: $fh,
          singletonAddress: $sa, singletonCodehash: $sg, safeMasterCopyCodehash: $mc}}}'
}
MANIFEST="$WORKDIR/manifest.json"
MANIFEST_PLACEHOLDER="$WORKDIR/manifest-placeholder.json"
write_manifest "$SAFE_MC_HASH" >"$MANIFEST"
write_manifest "0xFILL_canonical_safe_1_5_0_singleton_EXTCODEHASH" >"$MANIFEST_PLACEHOLDER"
echo "  masterCopy $SAFE_MC_HASH"
echo "  singleton  $SINGLETON_HASH"

preflight() { scripts/preflight-install-v1.sh --singleton "$SINGLETON" --rpc "$RPC" --multi-send "$MULTI_SEND" "$@"; }
verify() { scripts/verify-install-v1.sh --singleton "$SINGLETON" --rpc "$RPC" "$@"; }

# --- Safe transaction helpers (1-of-1, approved by msg.sender == owner) -----
# Pre-validated signature: r = owner, s = 0, v = 1 (Safe checkNSignatures).
PREVALIDATED_SIG="0x$(printf '%064s' "${OWNER#0x}" | tr ' ' 0)$(printf '%064d' 0)01"
exec_safe_tx() {
    local safe="$1" to="$2" data="$3" op="$4"
    send "$safe" "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)" \
        "$to" 0 "$data" "$op" 0 0 0 \
        0x0000000000000000000000000000000000000000 0x0000000000000000000000000000000000000000 \
        "$PREVALIDATED_SIG"
}
# MultiSendCallOnly packed entry: operation(1) to(20) value(32) len(32) data.
ms_entry() {
    local to data
    to=$(lower "${1#0x}"); data="${2#0x}"
    printf '00%s%064x%064x%s' "$to" 0 $(( ${#data} / 2 )) "$data"
}
exec_multisend() {
    local safe="$1"; shift
    local packed=""
    while [[ $# -gt 0 ]]; do packed+=$(ms_entry "$1" "$2"); shift 2; done
    exec_safe_tx "$safe" "$MULTI_SEND" "$(cast calldata "multiSend(bytes)" "0x$packed")" 1
}
install_calls() {
    local safe="$1" signers="$2"
    printf '%s\n' \
        "$safe" "$(cast calldata "setGuard(address)" "$SINGLETON")" \
        "$safe" "$(cast calldata "setModuleGuard(address)" "$SINGLETON")" \
        "$safe" "$(cast calldata "setFallbackHandler(address)" "$HANDLER")" \
        "$SINGLETON" "$(cast calldata "initialize(uint64,uint64,address[],bytes[])" 86400 86400 "[$RECOVERY_OWNER]" "$signers")"
}

# ---------------------------------------------------------------------------
step "Safe A: preflight"
# ---------------------------------------------------------------------------
SNAP_A="$WORKDIR/snapshot-a.json"
expect_exit 0 0 "preflight A passes with full pins + writes snapshot" "Preflight checks passed" -- \
    preflight --safe "$SAFE_A" --manifest "$MANIFEST" --snapshot-out "$SNAP_A"
jq -e --arg o "$(lower "$OWNER")" '.owners == [$o] and .threshold == "1" and .modules == []' "$SNAP_A" >/dev/null \
    || { cat "$SNAP_A" >&2; die "snapshot content unexpected"; }
expect_exit 1 1 "preflight A FAILS on placeholder masterCopy pin" "[FAIL] Safe masterCopy EXTCODEHASH" -- \
    preflight --safe "$SAFE_A" --manifest "$MANIFEST_PLACEHOLDER"
expect_exit 0 0 "preflight A downgrades unpinned masterCopy to WARN with --allow-unpinned-codehash" "[WARN] Safe masterCopy EXTCODEHASH" -- \
    preflight --safe "$SAFE_A" --manifest "$MANIFEST_PLACEHOLDER" --allow-unpinned-codehash
expect_exit 1 1 "preflight A FAILS on a wrong masterCopy pin" "[FAIL] Safe masterCopy EXTCODEHASH" -- \
    preflight --safe "$SAFE_A" --manifest "$MANIFEST" --safe-codehash "$MULTI_SEND_HASH"

# ---------------------------------------------------------------------------
step "Safe A: staged install (dormant), then add a signer"
# ---------------------------------------------------------------------------
mapfile -t CALLS < <(install_calls "$SAFE_A" "[]")
exec_multisend "$SAFE_A" "${CALLS[@]}"
expect_exit 1 1 "verify A FAILS on dormant install (no --allow-dormant)" "[FAIL] signersCount" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST" --snapshot "$SNAP_A"
expect_exit 0 0 "verify A passes dormant install with --allow-dormant" "accepted by --allow-dormant" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST" --snapshot "$SNAP_A" --allow-dormant
exec_safe_tx "$SAFE_A" "$SINGLETON" "$(cast calldata "addLockdownSigner(bytes)" "$LOCKDOWN_SIGNER")" 0
expect_exit 0 0 "verify A passes once armed, owners/threshold/modules == snapshot" \
    "[OK]   Owners == snapshot" "[OK]   Threshold == snapshot" "[OK]   Enabled modules == snapshot" \
    "[OK]   signersCount" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST" --snapshot "$SNAP_A"
expect_exit 1 1 "verify A FAILS on placeholder masterCopy pin" "[FAIL] Safe masterCopy EXTCODEHASH" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST_PLACEHOLDER" --snapshot "$SNAP_A"
expect_exit 0 0 "verify A without snapshot prints owners and WARNs not compared" "NOT compared" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST"
jq --arg s "$(lower "$SAFE_B")" '.safe = $s' "$SNAP_A" >"$WORKDIR/snapshot-wrong-safe.json"
expect_exit 1 1 "verify A FAILS on a snapshot taken for another Safe" "[FAIL] Owner/module snapshot" -- \
    verify --safe "$SAFE_A" --manifest "$MANIFEST" --snapshot "$WORKDIR/snapshot-wrong-safe.json"

# ---------------------------------------------------------------------------
step "Safe B: install batch that also smuggles addOwnerWithThreshold + enableModule"
# ---------------------------------------------------------------------------
SNAP_B="$WORKDIR/snapshot-b.json"
expect_exit 0 0 "preflight B passes + writes snapshot" "Preflight checks passed" -- \
    preflight --safe "$SAFE_B" --manifest "$MANIFEST" --snapshot-out "$SNAP_B"
mapfile -t CALLS < <(install_calls "$SAFE_B" "[$LOCKDOWN_SIGNER]")
exec_multisend "$SAFE_B" "${CALLS[@]}" \
    "$SAFE_B" "$(cast calldata "addOwnerWithThreshold(address,uint256)" "$ATTACKER" 2)" \
    "$SAFE_B" "$(cast calldata "enableModule(address)" "$ATTACKER")"
[[ "$(cast call "$SAFE_B" "isModuleEnabled(address)(bool)" "$ATTACKER" --rpc-url "$RPC")" == "true" ]] \
    || die "malicious batch did not enable the module (test setup)"
expect_exit 1 3 "verify B --snapshot FAILS on owners, threshold and modules (and nothing else)" \
    "[FAIL] Owners == snapshot" "[FAIL] Threshold == snapshot" "[FAIL] Enabled modules == snapshot" \
    "actual=$(lower "$ATTACKER")" -- \
    verify --safe "$SAFE_B" --manifest "$MANIFEST" --snapshot "$SNAP_B"
expect_exit 0 0 "verify B without snapshot prints the smuggled owner/module + WARNs" \
    "NOT compared" "[INFO] Enabled modules                    $(lower "$ATTACKER")" -- \
    verify --safe "$SAFE_B" --manifest "$MANIFEST"
expect_exit 1 1 "preflight B now FAILS (already initialised)" "[FAIL] Safe NOT yet initialised" -- \
    preflight --safe "$SAFE_B" --manifest "$MANIFEST"

echo
echo "operator e2e (anvil): $PASSED assertions passed"
