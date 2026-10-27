#!/usr/bin/env bash
#
# preflight-install-v1.sh
#
# Read-only checks before installing the V1 Lockdown singleton on a
# Safe v1.5.0. Does not send any transaction.
#
# Current ABI surface:
#   - no Guard.SAFE() immutable
#   - getConfigSnapshot returns (duration, delay, until, signersCount,
#     recoveryOwnerAllowlistCount)
#   - EIP-712 domain (ERC-5267) verifyingContract matches the singleton
#   - signersCount == 0 is a valid permanent "dormant" state
#
# Usage:
#   scripts/preflight-install-v1.sh \
#       --safe 0xSAFE --singleton 0xSINGLETON --rpc https://... \
#       --fallback-handler 0xHANDLER [--multi-send 0xA83c...] \
#       [--snapshot-out preinstall-snapshot.json]
#

set -euo pipefail

SAFE=""
SINGLETON=""
RPC=""
EXPECTED_MULTI_SEND=""
EXPECTED_FALLBACK_HANDLER=""
EXPECTED_MULTI_SEND_CODEHASH=""
EXPECTED_SINGLETON_CODEHASH=""
EXPECTED_SAFE_CODEHASH=""
EXPECTED_FALLBACK_HANDLER_CODEHASH=""
ALLOW_UNPINNED=0
MANIFEST=""
SNAPSHOT_OUT=""

usage() {
    cat <<EOF
Usage: $0 --safe <addr> --singleton <addr> --rpc <url>
          [--fallback-handler <addr>] [--fallback-handler-codehash <hash>]
          [--multi-send <addr>] [--multi-send-codehash <hash>]
          [--singleton-codehash <hash>] [--safe-codehash <hash>]
          [--allow-unpinned-codehash] [--manifest deploy/manifest.json]
          [--snapshot-out <file.json>]

V1 read-only preflight. Required checks:
  - Safe has code and VERSION() == 1.5.0
  - Singleton has code, supportsInterface ERC165 + TxGuard + ModuleGuard
  - Singleton EXTCODEHASH matches the audited runtime (--singleton-codehash)
  - Singleton MULTI_SEND_CALL_ONLY non-zero AND has code on this chain
  - MULTI_SEND_CALL_ONLY EXTCODEHASH matches canonical (--multi-send-codehash)
  - Singleton EIP-712 domain verifyingContract matches expected
  - Singleton bound constants match contract limits
  - Target Safe NOT yet initialised in this singleton
    (getConfigSnapshot(safe).lockdownDuration == 0)
  - Current Safe.guard / moduleGuard slots (warn if present)
  - LockdownFallbackHandler has code, codehash is pinned, and
    LOCKDOWN() returns the singleton
  - Current Safe fallback-handler slot (warn if present)
  - Safe masterCopy (proxy slot 0) EXTCODEHASH matches the canonical
    Safe v1.5.0 singleton (--safe-codehash / manifest safeMasterCopyCodehash)
  - Prints the Safe's owners, threshold and enabled modules

--snapshot-out <file> writes those owners, threshold and enabled modules
(read at one block) as JSON, only when every check passed. Hand the file to
scripts/verify-install-v1.sh --snapshot <file> after the install executes:
verify then FAILs if the install batch also changed owners, threshold or
modules (for example a smuggled addOwnerWithThreshold or enableModule).

Multichain note: the singleton and MULTI_SEND_CALL_ONLY are trusted by
ADDRESS, but an address does not authenticate bytecode. On any chain where
the singleton was deployed at a recognisable address (CREATE2) or where the
canonical MultiSendCallOnly differs from mainnet, supply the expected
EXTCODEHASH so this preflight rejects a same-address / different-bytecode
trust failure before install (see T-DEPLOY-1 / T-DEPLOY-2, SPEC_V1 §14.1).

Secure-by-default: codehash binding is MANDATORY. Omitting
--singleton-codehash, --multi-send-codehash, --fallback-handler-codehash or
--safe-codehash FAILS the preflight (a fake singleton can spoof VERSION() and
supportsInterface(); a fake handler can spoof install completeness; a
non-canonical Safe masterCopy can ignore the guard hooks). A manifest
placeholder (0xFILL...) counts as omitted. Pass
--allow-unpinned-codehash to consciously downgrade those to warnings for
dev/test only; do not use it for a production install.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --safe) SAFE="$2"; shift 2 ;;
        --singleton) SINGLETON="$2"; shift 2 ;;
        --rpc) RPC="$2"; shift 2 ;;
        --multi-send) EXPECTED_MULTI_SEND="$2"; shift 2 ;;
        --fallback-handler) EXPECTED_FALLBACK_HANDLER="$2"; shift 2 ;;
        --multi-send-codehash) EXPECTED_MULTI_SEND_CODEHASH="$2"; shift 2 ;;
        --singleton-codehash) EXPECTED_SINGLETON_CODEHASH="$2"; shift 2 ;;
        --safe-codehash) EXPECTED_SAFE_CODEHASH="$2"; shift 2 ;;
        --fallback-handler-codehash) EXPECTED_FALLBACK_HANDLER_CODEHASH="$2"; shift 2 ;;
        --allow-unpinned-codehash) ALLOW_UNPINNED=1; shift ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --snapshot-out) SNAPSHOT_OUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$SAFE" || -z "$SINGLETON" || -z "$RPC" ]]; then
    usage; exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
    echo "cast not found. Install Foundry." >&2; exit 1
fi

if [[ -n "$SNAPSHOT_OUT" ]] && ! command -v jq >/dev/null 2>&1; then
    echo "jq required for --snapshot-out. Install jq." >&2; exit 1
fi

# Resolve expected codehashes from the manifest (by chainId) when not given
# explicitly. A placeholder (0xFILL...) or missing entry resolves to empty, so
# the secure-by-default codehash gate still FAILs rather than passing a bogus
# hash.
if [[ -n "$MANIFEST" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
        echo "jq required for --manifest. Install jq." >&2; exit 1
    fi
    MANIFEST_CHAIN_ID=$(cast chain-id --rpc-url "$RPC" 2>/dev/null || true)
    manifest_hash() {
        local v
        v=$(jq -r --arg c "$MANIFEST_CHAIN_ID" --arg k "$1" \
            '.chains[$c][$k] // empty' "$MANIFEST" 2>/dev/null || true)
        # `|| true` keeps `set -e` from silently killing the script when the
        # manifest holds a placeholder / missing entry: the variable resolves
        # to empty and the secure-by-default codehash gate FAILs loudly below.
        [[ "$v" =~ ^0x[0-9a-fA-F]{64}$ ]] && printf '%s' "$v" || true
    }
    manifest_address() {
        local v
        v=$(jq -r --arg c "$MANIFEST_CHAIN_ID" --arg k "$1" \
            '.chains[$c][$k] // empty' "$MANIFEST" 2>/dev/null || true)
        [[ "$v" =~ ^0x[0-9a-fA-F]{40}$ ]] && printf '%s' "$v" || true
    }
    [[ -z "$EXPECTED_SINGLETON_CODEHASH" ]] && \
        EXPECTED_SINGLETON_CODEHASH=$(manifest_hash "singletonCodehash")
    [[ -z "$EXPECTED_MULTI_SEND_CODEHASH" ]] && \
        EXPECTED_MULTI_SEND_CODEHASH=$(manifest_hash "multiSendCodehash")
    [[ -z "$EXPECTED_SAFE_CODEHASH" ]] && \
        EXPECTED_SAFE_CODEHASH=$(manifest_hash "safeMasterCopyCodehash")
    [[ -z "$EXPECTED_FALLBACK_HANDLER_CODEHASH" ]] && \
        EXPECTED_FALLBACK_HANDLER_CODEHASH=$(manifest_hash "fallbackHandlerCodehash")
    [[ -z "$EXPECTED_FALLBACK_HANDLER" ]] && \
        EXPECTED_FALLBACK_HANDLER=$(manifest_address "fallbackHandlerAddress")
fi

GUARD_SLOT="0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
MODULE_GUARD_SLOT="0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"
FALLBACK_HANDLER_SLOT="0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"

ITX_GUARD_ID="0xe6d7a83a"
IMOD_GUARD_ID="0x58401ed8"
IERC165_ID="0x01ffc9a7"

LOCKDOWN_DURATION_MAX=$((30 * 24 * 60 * 60))
RESUME_DELAY_MIN=$((4 * 60 * 60))
RESUME_DELAY_MAX=$((7 * 24 * 60 * 60))
MAX_LOCKDOWN_SIGNERS=32
MAX_KEY_LENGTH=256

FAIL=0

lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
unquote() { local v="$1"; v="${v#\"}"; v="${v%\"}"; printf '%s' "$v"; }

check_ok()   { printf '  [OK]   %-38s %s\n' "$1" "${2:-}"; }
check_fail() { printf '  [FAIL] %-38s %s\n' "$1" "$2"; FAIL=1; }
check_warn() { printf '  [WARN] %-38s %s\n' "$1" "$2"; }

check_addr_eq() {
    local label="$1" actual="$2" expected="$3"
    if [[ "$(lower "$actual")" == "$(lower "$expected")" ]]; then
        check_ok "$label" "$(lower "$actual")"
    else
        check_fail "$label" "actual=$(lower "$actual") expected=$(lower "$expected")"
    fi
}

# EXTCODEHASH(addr) == keccak256(runtime bytecode). Returns empty on failure.
codehash_of() {
    local code
    code=$(cast code "$1" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$code" || "$code" == "0x" ]]; then printf ''; return; fi
    cast keccak "$code" 2>/dev/null || true
}

check_codehash_eq() {
    local label="$1" addr="$2" expected="$3"
    local actual
    actual=$(codehash_of "$addr")
    if [[ -z "$actual" ]]; then
        check_fail "$label" "no code at $(lower "$addr")"
    elif [[ "$(lower "$actual")" == "$(lower "$expected")" ]]; then
        check_ok "$label" "$(lower "$actual")"
    else
        check_fail "$label" "actual=$(lower "$actual") expected=$(lower "$expected")"
    fi
}

# Secure-by-default codehash binding: FAIL when no expected hash is supplied,
# unless --allow-unpinned-codehash was passed (then downgrade to WARN). An
# unpinned codehash lets a same-address fake (spoofed VERSION/supportsInterface)
# pass a "green" preflight - T-DEPLOY-1 / T-DEPLOY-2.
check_codehash_pin() {
    local label="$1" addr="$2" expected="$3" flag="$4"
    if [[ -n "$expected" ]]; then
        check_codehash_eq "$label" "$addr" "$expected"
    elif [[ "$ALLOW_UNPINNED" -eq 1 ]]; then
        check_warn "$label" "UNPINNED ($flag omitted; --allow-unpinned-codehash set - dev/test only)"
    else
        check_fail "$label" "not pinned - pass $flag (or --allow-unpinned-codehash for dev/test)"
    fi
}

slot_to_address() {
    local raw="$1"; local hex="${raw#0x}"
    printf '0x%s' "${hex: -40}"
}

echo "== Preflight Lockdown V1 install =="
echo "  Safe     : $(lower "$SAFE")"
echo "  Singleton: $(lower "$SINGLETON")"
if [[ -n "$EXPECTED_FALLBACK_HANDLER" ]]; then
    echo "  Handler  : $(lower "$EXPECTED_FALLBACK_HANDLER")"
else
    echo "  Handler  : <missing>"
fi
echo

safe_code=$(cast code "$SAFE" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$safe_code" || "$safe_code" == "0x" ]]; then
    check_fail "Safe code" "no contract code at Safe"
else
    check_ok "Safe code" "$(( (${#safe_code} - 2) / 2 )) bytes"
fi

safe_version=$(cast call "$SAFE" "VERSION()(string)" --rpc-url "$RPC" 2>/dev/null || true)
safe_version=$(unquote "$safe_version")
if [[ "$safe_version" == "1.5.0" ]]; then
    check_ok "Safe VERSION()" "$safe_version"
else
    check_fail "Safe VERSION()" "expected 1.5.0, got ${safe_version:-call failed}"
fi

# The Safe is authenticated by VERSION() above - the same spoofable surface the
# singleton codehash pin closes. Pin the Safe's masterCopy (slot 0) too: a
# non-canonical Safe implementation can ignore the guard hooks entirely while
# VERSION()/supportsInterface() report canonical, and a downgrade to a Safe
# without IModuleGuard leaves all three Lockdown slots looking correct while
# the module freeze silently stops existing (AR-20). Same fail-closed gate as
# the singleton / MultiSend / handler pins: an unpinned masterCopy (no
# --safe-codehash and a 0xFILL placeholder in the manifest) FAILs unless
# --allow-unpinned-codehash is set for dev/test.
safe_master_raw=$(cast storage "$SAFE" 0 --rpc-url "$RPC" 2>/dev/null || true)
safe_master=$(slot_to_address "${safe_master_raw:-0x0}")
echo "  Safe masterCopy (slot 0): $(lower "$safe_master")"
check_codehash_pin "Safe masterCopy EXTCODEHASH" "$safe_master" "$EXPECTED_SAFE_CODEHASH" "--safe-codehash"

sing_code=$(cast code "$SINGLETON" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$sing_code" || "$sing_code" == "0x" ]]; then
    check_fail "Singleton code" "no code at singleton"
else
    check_ok "Singleton code" "$(( (${#sing_code} - 2) / 2 )) bytes"
fi

# T-DEPLOY-1: the singleton is trusted by address; an address does not
# authenticate bytecode. On a chain where an attacker controls (or raced)
# the deployment at a recognisable address, the installed guard could be
# arbitrary code. Bind to the audited runtime EXTCODEHASH when supplied.
check_codehash_pin "Singleton EXTCODEHASH" "$SINGLETON" "$EXPECTED_SINGLETON_CODEHASH" "--singleton-codehash"

sing_version=$(cast call "$SINGLETON" "VERSION()(string)" --rpc-url "$RPC" 2>/dev/null || true)
sing_version=$(unquote "$sing_version")
if [[ "$sing_version" == "1.0.0" ]]; then
    check_ok "Singleton VERSION()" "$sing_version"
else
    check_fail "Singleton VERSION()" "expected 1.0.0, got ${sing_version:-call failed}"
fi

check_iface() {
    local label="$1" id="$2"
    local out
    out=$(cast call "$SINGLETON" "supportsInterface(bytes4)(bool)" "$id" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ "$out" == "true" ]]; then
        check_ok "$label" "$id"
    else
        check_fail "$label" "$id returned ${out:-call failed}"
    fi
}
check_iface "supportsInterface ERC165"      "$IERC165_ID"
check_iface "supportsInterface TxGuard"     "$ITX_GUARD_ID"
check_iface "supportsInterface ModuleGuard" "$IMOD_GUARD_ID"

if [[ -z "$EXPECTED_FALLBACK_HANDLER" ]]; then
    check_fail "LockdownFallbackHandler" "not supplied - pass --fallback-handler or manifest fallbackHandlerAddress"
else
    fh_code=$(cast code "$EXPECTED_FALLBACK_HANDLER" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$fh_code" || "$fh_code" == "0x" ]]; then
        check_fail "LockdownFallbackHandler code" "no code at $(lower "$EXPECTED_FALLBACK_HANDLER")"
    else
        check_ok "LockdownFallbackHandler code" "$(( (${#fh_code} - 2) / 2 )) bytes"
        check_codehash_pin "FallbackHandler EXTCODEHASH" "$EXPECTED_FALLBACK_HANDLER" "$EXPECTED_FALLBACK_HANDLER_CODEHASH" "--fallback-handler-codehash"
    fi

    handler_lockdown=$(cast call "$EXPECTED_FALLBACK_HANDLER" "LOCKDOWN()(address)" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$handler_lockdown" ]]; then
        check_fail "FallbackHandler LOCKDOWN()" "call failed"
    else
        check_addr_eq "FallbackHandler LOCKDOWN()" "$handler_lockdown" "$SINGLETON"
    fi
fi

multi_send=$(cast call "$SINGLETON" "MULTI_SEND_CALL_ONLY()(address)" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$multi_send" || "$(lower "$multi_send")" == "0x0000000000000000000000000000000000000000" ]]; then
    check_fail "MULTI_SEND_CALL_ONLY" "${multi_send:-call failed}"
else
    if [[ -n "$EXPECTED_MULTI_SEND" ]]; then
        check_addr_eq "MULTI_SEND_CALL_ONLY" "$multi_send" "$EXPECTED_MULTI_SEND"
    else
        check_ok "MULTI_SEND_CALL_ONLY" "$(lower "$multi_send")"
    fi
    # T-DEPLOY-2: the immutable is a fixed address baked at singleton
    # construction. Same-address-across-chains (CREATE2) forces the SAME
    # immutable on every chain, so on a chain where that address is codeless
    # the owner-path DELEGATECALL carveout becomes a silent no-op, and where
    # it holds NON-canonical code it executes arbitrary logic in the Safe's
    # context (drain). Require code present, and bind the runtime EXTCODEHASH
    # to the canonical MultiSendCallOnly when supplied. SPEC_V1 §14.1.
    ms_code=$(cast code "$multi_send" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$ms_code" || "$ms_code" == "0x" ]]; then
        check_fail "MULTI_SEND_CALL_ONLY code" "codeless on this chain (DELEGATECALL would no-op)"
    else
        check_codehash_pin "MULTI_SEND_CALL_ONLY codehash" "$multi_send" "$EXPECTED_MULTI_SEND_CODEHASH" "--multi-send-codehash"
    fi
fi

# EIP-712 domain via ERC-5267 eip712Domain() (OZ EIP712). The verifyingContract
# field binds the typed-data domain to this singleton on this chain; clear-signing
# wallets read the same domain, so a mismatch means signatures will not verify.
domain_vc=$(cast call "$SINGLETON" "eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])" --rpc-url "$RPC" 2>/dev/null | sed -n '5p' || true)
if [[ -n "$domain_vc" && "${domain_vc,,}" == "${SINGLETON,,}" ]]; then
    check_ok "EIP-712 domain verifyingContract" "$domain_vc"
else
    check_fail "EIP-712 domain verifyingContract" "mismatch or call failed (got '${domain_vc:-none}')"
fi

dmax_raw=$(cast call "$SINGLETON" "LOCKDOWN_DURATION_MAX()(uint64)" --rpc-url "$RPC" 2>/dev/null || true)
dmax=${dmax_raw%% *}
if [[ "$dmax" =~ ^[0-9]+$ ]] && [[ "$dmax" -eq "$LOCKDOWN_DURATION_MAX" ]]; then
    check_ok "LOCKDOWN_DURATION_MAX" "$dmax s"
else
    check_warn "LOCKDOWN_DURATION_MAX" "got ${dmax_raw:-call failed}"
fi

cap_raw=$(cast call "$SINGLETON" "MAX_LOCKDOWN_SIGNERS()(uint8)" --rpc-url "$RPC" 2>/dev/null || true)
cap=${cap_raw%% *}
if [[ "$cap" =~ ^[0-9]+$ ]] && [[ "$cap" -eq "$MAX_LOCKDOWN_SIGNERS" ]]; then
    check_ok "MAX_LOCKDOWN_SIGNERS" "$cap"
else
    check_warn "MAX_LOCKDOWN_SIGNERS" "got ${cap_raw:-call failed}"
fi

# getConfigSnapshot returns (uint64,uint64,uint64,uint256,uint256)
snap=$(cast call "$SINGLETON" \
    "getConfigSnapshot(address)(uint64,uint64,uint64,uint256,uint256)" \
    "$SAFE" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$snap" ]]; then
    check_fail "getConfigSnapshot(safe)" "call failed - check ABI"
else
    # One value per line; cast may append a "[8.64e4]" annotation to a line,
    # stripped below with ${var%% *}. (Joining lines and `read`ing them would
    # both misalign fields on annotations and, at EOF without a newline, make
    # `read` return 1 and abort the script under `set -e`.)
    mapfile -t snap_lines < <(printf '%s\n' "$snap")
    snap_d="${snap_lines[0]:-}"; snap_r="${snap_lines[1]:-}"; snap_u="${snap_lines[2]:-}"
    snap_cnt="${snap_lines[3]:-}"; snap_back="${snap_lines[4]:-}"
    snap_d_num=${snap_d%% *}
    if [[ "$snap_d_num" =~ ^[0-9]+$ ]] && [[ "$snap_d_num" -eq 0 ]]; then
        check_ok "Safe NOT yet initialised" "lockdownDuration=0"
    else
        check_fail "Safe NOT yet initialised" "lockdownDuration=$snap_d_num (initialize would revert)"
    fi
fi

# SPEC_V1 H.27: ERC-1271 stays disabled after install unless the batch also
# carries setErc1271Allowed(true) right after initialize (optional 5th call).
erc1271=$(cast call "$SINGLETON" "isErc1271Allowed(address)(bool)" "$SAFE" --rpc-url "$RPC" 2>/dev/null || true)
case "${erc1271%% *}" in
    false) check_ok "erc1271Allowed" "false (default after install; opt in with setErc1271Allowed(true))" ;;
    true)  check_warn "erc1271Allowed" "already true for this Safe" ;;
    *)     check_warn "erc1271Allowed" "call failed (singleton predates H.27?)" ;;
esac

raw=$(cast storage "$SAFE" "$GUARD_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
cur_guard=$(slot_to_address "${raw:-0x0}")
if [[ "$cur_guard" == "0x0000000000000000000000000000000000000000" ]]; then
    check_ok "Current Safe.guard" "none (clean install)"
elif [[ "$(lower "$cur_guard")" == "$(lower "$SINGLETON")" ]]; then
    check_warn "Current Safe.guard" "already points at this singleton"
else
    check_warn "Current Safe.guard" "$cur_guard (will be overwritten)"
fi

raw=$(cast storage "$SAFE" "$MODULE_GUARD_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
cur_mguard=$(slot_to_address "${raw:-0x0}")
if [[ "$cur_mguard" == "0x0000000000000000000000000000000000000000" ]]; then
    check_ok "Current Safe.moduleGuard" "none (clean install)"
elif [[ "$(lower "$cur_mguard")" == "$(lower "$SINGLETON")" ]]; then
    check_warn "Current Safe.moduleGuard" "already points at this singleton"
else
    check_warn "Current Safe.moduleGuard" "$cur_mguard (will be overwritten)"
fi

raw=$(cast storage "$SAFE" "$FALLBACK_HANDLER_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
cur_fallback=$(slot_to_address "${raw:-0x0}")
if [[ "$cur_fallback" == "0x0000000000000000000000000000000000000000" ]]; then
    check_ok "Current Safe.fallbackHandler" "none (will be set to LockdownFallbackHandler)"
elif [[ -n "$EXPECTED_FALLBACK_HANDLER" && "$(lower "$cur_fallback")" == "$(lower "$EXPECTED_FALLBACK_HANDLER")" ]]; then
    check_warn "Current Safe.fallbackHandler" "already points at expected handler"
else
    check_warn "Current Safe.fallbackHandler" "$cur_fallback (will be overwritten)"
fi

# T-INSTALL-1 (SPEC_V1 §14.2): an already-enabled module is the shared
# precondition of every install/upgrade-gap drain. Until BOTH the module
# guard slot, fallback-handler slot and an initialised config are in place,
# an enabled module can
# drain the module path or call initialize(...) on the singleton with
# attacker-chosen config (msg.sender == Safe). Enumerate enabled modules so
# the operator vets each one BEFORE install, and installs atomically
# (setGuard + setModuleGuard + setFallbackHandler + initialize in one
# MultiSend, SPEC §8.1).
SENTINEL_MODULES="0x0000000000000000000000000000000000000001"
ZERO_ADDRESS="0x0000000000000000000000000000000000000000"
MODULE_PAGE_SIZE=100
MODULE_MAX_PAGES=50

# Owners / threshold / modules are read at ONE block so the snapshot is
# internally consistent. Falls back to "latest" if the block number is
# unreadable (the snapshot is then refused below).
SNAP_BLOCK=$(cast block-number --rpc-url "$RPC" 2>/dev/null || true)
[[ "$SNAP_BLOCK" =~ ^[0-9]+$ ]] || SNAP_BLOCK=""
block_args=()
[[ -n "$SNAP_BLOCK" ]] && block_args=(--block "$SNAP_BLOCK")

# Prints every enabled module (lowercase, one per line), walking all pages of
# getModulesPaginated. Returns non-zero if any page cannot be read, so a
# truncated list is never mistaken for the complete set.
list_safe_modules() {
    local start="$SENTINEL_MODULES" out first next page=0
    while :; do
        out=$(cast call "$SAFE" "getModulesPaginated(address,uint256)(address[],address)" \
            "$start" "$MODULE_PAGE_SIZE" "${block_args[@]}" --rpc-url "$RPC" 2>/dev/null) || return 1
        first=$(printf '%s\n' "$out" | sed -n '1p')
        next=$(lower "$(printf '%s\n' "$out" | sed -n '2p')")
        [[ "$first" == \[* ]] || return 1
        printf '%s\n' "$first" | grep -oE '0x[0-9a-fA-F]{40}' | tr 'A-F' 'a-f' || true
        if [[ -z "$next" || "$next" == "$SENTINEL_MODULES" || "$next" == "$ZERO_ADDRESS" ]]; then
            return 0
        fi
        page=$((page + 1))
        [[ "$page" -lt "$MODULE_MAX_PAGES" ]] || return 1
        start="$next"
    done
}

owners_line=$(cast call "$SAFE" "getOwners()(address[])" "${block_args[@]}" --rpc-url "$RPC" 2>/dev/null || true)
owners=$(printf '%s\n' "$owners_line" | grep -oE '0x[0-9a-fA-F]{40}' | tr 'A-F' 'a-f' || true)
threshold_raw=$(cast call "$SAFE" "getThreshold()(uint256)" "${block_args[@]}" --rpc-url "$RPC" 2>/dev/null || true)
threshold=${threshold_raw%% *}
SNAPSHOT_READ_OK=1

if [[ "$owners_line" == \[* && -n "$owners" ]]; then
    check_ok "Safe owners" "$(printf '%s\n' "$owners" | wc -l | tr -d ' ') owner(s)"
    printf '%s\n' "$owners" | while read -r o; do printf '         owner : %s\n' "$o"; done
else
    check_warn "Safe owners" "getOwners call failed - check manually"
    SNAPSHOT_READ_OK=0
fi
if [[ "$threshold" =~ ^[0-9]+$ ]] && [[ "$threshold" -gt 0 ]]; then
    check_ok "Safe threshold" "$threshold"
else
    check_warn "Safe threshold" "getThreshold call failed - check manually"
    SNAPSHOT_READ_OK=0
fi

# T-INSTALL-1 (SPEC_V1 §14.2): an already-enabled module is the shared
# precondition of every install/upgrade-gap drain. Until BOTH the module
# guard slot, fallback-handler slot and an initialised config are in place,
# an enabled module can
# drain the module path or call initialize(...) on the singleton with
# attacker-chosen config (msg.sender == Safe). Enumerate enabled modules so
# the operator vets each one BEFORE install, and installs atomically
# (setGuard + setModuleGuard + setFallbackHandler + initialize in one
# MultiSend, SPEC §8.1).
if ! modules=$(list_safe_modules); then
    check_warn "Enabled Safe modules" "getModulesPaginated call failed - check manually"
    SNAPSHOT_READ_OK=0
    modules=""
elif [[ -z "$modules" ]]; then
    check_ok "Enabled Safe modules" "none"
else
    mod_count=$(printf '%s\n' "$modules" | wc -l | tr -d ' ')
    check_warn "Enabled Safe modules" "$mod_count enabled - VET each before install (T-INSTALL-1); an enabled module bypasses an unset module guard"
    printf '%s\n' "$modules" | while read -r m; do
        printf '         module: %s\n' "$m"
    done
fi

if [[ -n "$SNAPSHOT_OUT" ]]; then
    if [[ "$SNAPSHOT_READ_OK" -ne 1 || -z "$SNAP_BLOCK" ]]; then
        check_fail "Owner/module snapshot" "could not read owners, threshold, modules or block number; not written"
    elif [[ "$FAIL" -ne 0 ]]; then
        check_fail "Owner/module snapshot" "not written: preflight has failing checks"
    else
        snap_chain_id=$(cast chain-id --rpc-url "$RPC" 2>/dev/null || true)
        to_json_array() { printf '%s\n' "$1" | sed '/^$/d' | jq -R . | jq -s -c .; }
        if jq -n \
            --arg format "runtime-capital.safe-lockdown.owner-module-snapshot.v1" \
            --arg chainId "$snap_chain_id" \
            --arg safe "$(lower "$SAFE")" \
            --arg blockNumber "$SNAP_BLOCK" \
            --arg threshold "$threshold" \
            --argjson owners "$(to_json_array "$owners")" \
            --argjson modules "$(to_json_array "$modules")" \
            '{format: $format, chainId: $chainId, safe: $safe, blockNumber: $blockNumber,
              owners: $owners, threshold: $threshold, modules: $modules}' > "$SNAPSHOT_OUT"; then
            check_ok "Owner/module snapshot" "written to $SNAPSHOT_OUT (block $SNAP_BLOCK)"
        else
            check_fail "Owner/module snapshot" "could not write $SNAPSHOT_OUT"
        fi
    fi
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
	echo "Preflight checks passed. Safe to build the install transaction."
	echo "Reminder: the install batch should atomically perform"
	echo "  safe.setGuard(singleton)"
	echo "  safe.setModuleGuard(singleton)"
	echo "  safe.setFallbackHandler(lockdownFallbackHandler)"
	echo "  singleton.initialize(duration, delay, recoveryOwners, initialSigners)"
    echo "in a single MultiSend, with initialSigners.length >= 1 so the"
    echo "Safe is not left in a dormant (no-signer) state. A staged install"
    echo "(signers added in a later transaction) is DORMANT until then:"
    echo "verify-install-v1.sh FAILs it unless --allow-dormant is passed."
    if [[ -n "$SNAPSHOT_OUT" ]]; then
        echo "After the install executes, run verify-install-v1.sh --snapshot $SNAPSHOT_OUT"
        echo "so any owner / threshold / module change in the batch FAILs."
    else
        echo "Tip: re-run with --snapshot-out <file> and pass it to"
        echo "verify-install-v1.sh --snapshot <file> to catch owner/module changes."
    fi
    exit 0
fi

echo "Preflight checks failed. Do not install this singleton on this Safe."
exit 1
