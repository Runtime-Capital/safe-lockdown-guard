#!/usr/bin/env bash
#
# verify-install-v1.sh
#
# Post-install verification for the V1 Lockdown singleton on a
# Safe v1.5.0:
#
#   1. Safe.guard slot points to singleton
#   2. Safe.moduleGuard slot points to singleton
#   3. Safe fallback-handler slot points to a LockdownFallbackHandler whose
#      LOCKDOWN() returns the singleton
#   4. Singleton supports ERC-165 + ITransactionGuard + IModuleGuard
#   5. Singleton MULTI_SEND_CALL_ONLY non-zero
#   6. Singleton VERSION == "1.0.0"
#   7. Per-Safe config in singleton initialised
#      (lockdownDuration in (0, LOCKDOWN_DURATION_MAX])
#      (resumeDelay in [RESUME_DELAY_MIN, RESUME_DELAY_MAX])
#      (recoveryOwnerAllowlistCount > 0)
#      (lockdownUntil == 0)
#   8. signersCount > 0 (warn at 0: Safe is dormant)
#
# Read-only. Exit 0 on success, 1 on any failed check.
#

set -euo pipefail

SAFE=""
SINGLETON=""
RPC=""
EXPECTED_MULTI_SEND_CODEHASH=""
EXPECTED_SINGLETON_CODEHASH=""
EXPECTED_SAFE_CODEHASH=""
EXPECTED_FALLBACK_HANDLER=""
EXPECTED_FALLBACK_HANDLER_CODEHASH=""
ALLOW_UNPINNED=0
MANIFEST=""

usage() {
    cat <<EOF
Usage: $0 --safe <addr> --singleton <addr> --rpc <url>
          [--multi-send-codehash <hash>] [--singleton-codehash <hash>]
          [--safe-codehash <hash>]
          [--fallback-handler <addr>] [--fallback-handler-codehash <hash>]
          [--allow-unpinned-codehash] [--manifest deploy/manifest.json]
V1 read-only post-install verifier. Codehash binding is MANDATORY by default:
omitting --singleton-codehash / --multi-send-codehash /
--fallback-handler-codehash FAILs (a same-address fake can spoof
VERSION/supportsInterface; a fake handler can spoof install completeness).
Pass --allow-unpinned-codehash to
downgrade to warnings for dev/test only. Binds the singleton and its
MULTI_SEND_CALL_ONLY to audited/canonical bytecode (multichain same-address
trust, T-DEPLOY-1 / T-DEPLOY-2, SPEC_V1 §14.1).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --safe)      SAFE="$2";      shift 2 ;;
        --singleton) SINGLETON="$2"; shift 2 ;;
        --rpc)       RPC="$2";       shift 2 ;;
        --multi-send-codehash) EXPECTED_MULTI_SEND_CODEHASH="$2"; shift 2 ;;
        --singleton-codehash)  EXPECTED_SINGLETON_CODEHASH="$2";  shift 2 ;;
        --safe-codehash)       EXPECTED_SAFE_CODEHASH="$2";       shift 2 ;;
        --fallback-handler)     EXPECTED_FALLBACK_HANDLER="$2";   shift 2 ;;
        --fallback-handler-codehash) EXPECTED_FALLBACK_HANDLER_CODEHASH="$2"; shift 2 ;;
        --allow-unpinned-codehash) ALLOW_UNPINNED=1; shift ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "$SAFE" || -z "$SINGLETON" || -z "$RPC" ]]; then
    usage; exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
    echo "cast not found." >&2; exit 1
fi

# Resolve expected codehashes from the manifest (by chainId) when not given
# explicitly. A placeholder or missing entry resolves to empty so the
# secure-by-default codehash gate still FAILs.
if [[ -n "$MANIFEST" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
        echo "jq required for --manifest." >&2; exit 1
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

FAIL=0
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

redact_rpc() {
    local url="$1"
    if [[ "$url" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@]+@)?([^/?#]+) ]]; then
        printf '%s%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
    else
        printf '<redacted>'
    fi
}
unquote() { local v="$1"; v="${v#\"}"; v="${v%\"}"; printf '%s' "$v"; }

SINGLETON_LC=$(lower "$SINGLETON")
SAFE_LC=$(lower "$SAFE")

slot_to_address() {
    local raw="$1"; local hex="${raw#0x}"
    printf '0x%s' "${hex: -40}"
}

check_eq_addr() {
    local label="$1" actual="$2" expected="$3"
    local a e
    a=$(lower "$actual"); e=$(lower "$expected")
    if [[ "$a" == "$e" ]]; then
        printf '  [OK]   %-34s %s\n' "$label" "$a"
    else
        printf '  [FAIL] %-34s actual=%s expected=%s\n' "$label" "$a" "$e"
        FAIL=1
    fi
}

# EXTCODEHASH(addr) == keccak256(runtime bytecode). Empty on failure.
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
        printf '  [FAIL] %-34s no code at %s\n' "$label" "$(lower "$addr")"; FAIL=1
    elif [[ "$(lower "$actual")" == "$(lower "$expected")" ]]; then
        printf '  [OK]   %-34s %s\n' "$label" "$(lower "$actual")"
    else
        printf '  [FAIL] %-34s actual=%s expected=%s\n' "$label" "$(lower "$actual")" "$(lower "$expected")"; FAIL=1
    fi
}

# Secure-by-default: FAIL when no expected hash is supplied, unless
# --allow-unpinned-codehash downgrades to WARN. An unpinned codehash lets a
# same-address fake pass a "green" verify (T-DEPLOY-1 / T-DEPLOY-2).
check_codehash_pin() {
    local label="$1" addr="$2" expected="$3" flag="$4"
    if [[ -n "$expected" ]]; then
        check_codehash_eq "$label" "$addr" "$expected"
    elif [[ "$ALLOW_UNPINNED" -eq 1 ]]; then
        printf '  [WARN] %-34s UNPINNED (%s omitted; dev/test only)\n' "$label" "$flag"
    else
        printf '  [FAIL] %-34s not pinned - pass %s (or --allow-unpinned-codehash)\n' "$label" "$flag"; FAIL=1
    fi
}

echo "== Verifying V1 Lockdown install =="
echo "  Safe     : $SAFE_LC"
echo "  Singleton: $SINGLETON_LC"
echo "  RPC      : $(redact_rpc "$RPC")"
echo

raw=$(cast storage "$SAFE" "$GUARD_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
check_eq_addr "Safe.transactionGuard slot" "$(slot_to_address "${raw:-0x0}")" "$SINGLETON"

raw=$(cast storage "$SAFE" "$MODULE_GUARD_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
check_eq_addr "Safe.moduleGuard slot" "$(slot_to_address "${raw:-0x0}")" "$SINGLETON"

raw=$(cast storage "$SAFE" "$FALLBACK_HANDLER_SLOT" --rpc-url "$RPC" 2>/dev/null || true)
fallback_handler=$(slot_to_address "${raw:-0x0}")
if [[ "$fallback_handler" == "0x0000000000000000000000000000000000000000" ]]; then
    printf '  [FAIL] %-34s unset\n' "Safe.fallbackHandler slot"; FAIL=1
else
    printf '  [OK]   %-34s %s\n' "Safe.fallbackHandler slot" "$(lower "$fallback_handler")"
    if [[ -n "$EXPECTED_FALLBACK_HANDLER" ]]; then
        check_eq_addr "Expected fallbackHandler" "$fallback_handler" "$EXPECTED_FALLBACK_HANDLER"
    fi
    check_codehash_pin "FallbackHandler EXTCODEHASH" "$fallback_handler" "$EXPECTED_FALLBACK_HANDLER_CODEHASH" "--fallback-handler-codehash"
    handler_lockdown=$(cast call "$fallback_handler" "LOCKDOWN()(address)" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$handler_lockdown" ]]; then
        printf '  [FAIL] %-34s call failed\n' "FallbackHandler LOCKDOWN()"; FAIL=1
    else
        check_eq_addr "FallbackHandler LOCKDOWN()" "$handler_lockdown" "$SINGLETON"
    fi
fi

# Pin the Safe's masterCopy (slot 0) codehash: a non-canonical Safe impl can
# ignore the guard hooks while reporting a canonical VERSION(). WARN when
# unpinned (operator-owned wallet, weaker anchor than the shared singleton).
raw=$(cast storage "$SAFE" 0 --rpc-url "$RPC" 2>/dev/null || true)
safe_master=$(slot_to_address "${raw:-0x0}")
if [[ -n "$EXPECTED_SAFE_CODEHASH" ]]; then
    check_codehash_eq "Safe masterCopy EXTCODEHASH" "$safe_master" "$EXPECTED_SAFE_CODEHASH"
else
    printf '  [WARN] %-34s unpinned (masterCopy=%s; --safe-codehash)\n' "Safe masterCopy EXTCODEHASH" "$safe_master"
fi

check_iface() {
    local label="$1" id="$2"
    local out
    out=$(cast call "$SINGLETON" "supportsInterface(bytes4)(bool)" "$id" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ "$out" == "true" ]]; then
        printf '  [OK]   %-34s %s\n' "$label" "$id"
    else
        printf '  [FAIL] %-34s %s returned %s\n' "$label" "$id" "${out:-call failed}"
        FAIL=1
    fi
}
check_iface "supportsInterface ERC165"      "$IERC165_ID"
check_iface "supportsInterface TxGuard"     "$ITX_GUARD_ID"
check_iface "supportsInterface ModuleGuard" "$IMOD_GUARD_ID"

multi_send=$(cast call "$SINGLETON" "MULTI_SEND_CALL_ONLY()(address)" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$multi_send" || "$(lower "$multi_send")" == "0x0000000000000000000000000000000000000000" ]]; then
    printf '  [FAIL] %-34s %s\n' "MULTI_SEND_CALL_ONLY" "${multi_send:-call failed}"
    FAIL=1
else
    printf '  [OK]   %-34s %s\n' "MULTI_SEND_CALL_ONLY" "$(lower "$multi_send")"
    # T-DEPLOY-2: bind the DELEGATECALL target to canonical bytecode. A
    # codeless address silently no-ops the carveout; non-canonical code runs
    # in Safe context (drain). See SPEC_V1 §14.1.
    ms_code=$(cast code "$multi_send" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$ms_code" || "$ms_code" == "0x" ]]; then
        printf '  [FAIL] %-34s codeless on this chain\n' "MULTI_SEND_CALL_ONLY code"; FAIL=1
    else
        check_codehash_pin "MULTI_SEND_CALL_ONLY codehash" "$multi_send" "$EXPECTED_MULTI_SEND_CODEHASH" "--multi-send-codehash"
    fi
fi

# T-DEPLOY-1: bind the installed guard to the audited runtime bytecode.
check_codehash_pin "Singleton EXTCODEHASH" "$SINGLETON" "$EXPECTED_SINGLETON_CODEHASH" "--singleton-codehash"

sing_version=$(cast call "$SINGLETON" "VERSION()(string)" --rpc-url "$RPC" 2>/dev/null || true)
sing_version=$(unquote "$sing_version")
if [[ "$sing_version" == "1.0.0" ]]; then
    printf '  [OK]   %-34s %s\n' "Singleton VERSION" "$sing_version"
else
    printf '  [FAIL] %-34s expected 1.0.0, got %s\n' "Singleton VERSION" "${sing_version:-call failed}"
    FAIL=1
fi

snap=$(cast call "$SINGLETON" \
    "getConfigSnapshot(address)(uint64,uint64,uint64,uint256,uint256)" \
    "$SAFE" --rpc-url "$RPC" 2>/dev/null || true)
if [[ -z "$snap" ]]; then
    printf '  [FAIL] %-34s call failed\n' "getConfigSnapshot(safe)"
    FAIL=1
else
    read -r snap_d snap_r snap_u snap_cnt snap_back \
        < <(printf '%s\n' "$snap" | tr '\n' ' ' | tr -s ' ')
    snap_d_num=${snap_d%% *}
    snap_r_num=${snap_r%% *}
    snap_u_num=${snap_u%% *}
    snap_cnt_num=${snap_cnt%% *}
    snap_back_num=${snap_back%% *}

    if [[ "$snap_d_num" =~ ^[0-9]+$ ]] && [[ "$snap_d_num" -gt 0 ]] && [[ "$snap_d_num" -le "$LOCKDOWN_DURATION_MAX" ]]; then
        printf '  [OK]   %-34s %s s\n' "lockdownDuration" "$snap_d_num"
    else
        printf '  [FAIL] %-34s value=%s out of bounds\n' "lockdownDuration" "$snap_d_num"
        FAIL=1
    fi

    if [[ "$snap_r_num" =~ ^[0-9]+$ ]] && [[ "$snap_r_num" -ge "$RESUME_DELAY_MIN" ]] && [[ "$snap_r_num" -le "$RESUME_DELAY_MAX" ]]; then
        printf '  [OK]   %-34s %s s\n' "resumeDelay" "$snap_r_num"
    else
        printf '  [FAIL] %-34s value=%s out of bounds\n' "resumeDelay" "$snap_r_num"
        FAIL=1
    fi

    # Anti-fat-finger: surface the worst-case freeze a single trigger (real,
    # drill, or false-positive) costs - lockdownDuration + resumeDelay - so the
    # operator confirms they did not transpose or over-size the values.
    if [[ "$snap_d_num" =~ ^[0-9]+$ ]] && [[ "$snap_r_num" =~ ^[0-9]+$ ]]; then
        worst=$((snap_d_num + snap_r_num))
        printf '  [INFO] %-34s %s s (~%dh, ~%dd) = duration + resumeDelay\n' \
            "worst-case freeze per trigger" "$worst" "$((worst / 3600))" "$((worst / 86400))"
    fi

    if [[ "$snap_u_num" == "0" ]]; then
        printf '  [OK]   %-34s 0 (Normal state)\n' "lockdownUntil"
    else
        printf '  [FAIL] %-34s expected 0, got %s\n' "lockdownUntil" "$snap_u_num"
        FAIL=1
    fi

    if [[ "$snap_back_num" =~ ^[0-9]+$ ]] && [[ "$snap_back_num" -gt 0 ]]; then
        printf '  [OK]   %-34s %s entries\n' "recoveryOwnerAllowlistCount" "$snap_back_num"
        if [[ "$snap_back_num" -lt 2 ]]; then
            printf '  [WARN] %-34s contract allows 1, runbook recommends >= 2\n' "allowlist policy"
        fi
    else
        printf '  [FAIL] %-34s empty\n' "recoveryOwnerAllowlistCount"
        FAIL=1
    fi

    if [[ "$snap_cnt_num" =~ ^[0-9]+$ ]] && [[ "$snap_cnt_num" -gt 0 ]]; then
        printf '  [OK]   %-34s %s registered\n' "signersCount" "$snap_cnt_num"
    else
        printf '  [WARN] %-34s 0 - Safe is DORMANT (cannot lockdown)\n' "signersCount"
    fi
fi

# INV-LIVE-1 (SPEC §14.2): a Safe with timelockDelay == 0 has NO delay on
# owner-path guard removal / signer disarm, so a coerced quorum can strip
# protection in a single tx. The timelock is THE coercion-resistance lever;
# surface its absence loudly (not a FAIL: timelock is opt-in by design).
tl_delay=$(cast call "$SINGLETON" "getTimelockDelay(address)(uint64)" "$SAFE" --rpc-url "$RPC" 2>/dev/null || true)
tl_delay_num=${tl_delay%% *}
if [[ "$tl_delay_num" =~ ^[0-9]+$ ]] && [[ "$tl_delay_num" -gt 0 ]]; then
    printf '  [OK]   %-34s %s s (coercion-resistant)\n' "timelockDelay" "$tl_delay_num"
    # T-LIVE-2 / INV-LIVE-3 (SPEC §14.2): the contract now enforces
    # lockdownDuration >= timelockDelay, so the self-induced-lockdown disarm
    # shortcut cannot be cheaper than timelockDelay. Confirm the on-chain
    # relation as a defence-in-depth read-back (it should never fail).
    if [[ "${snap_d_num:-}" =~ ^[0-9]+$ ]] && [[ "$snap_d_num" -lt "$tl_delay_num" ]]; then
        printf '  [FAIL] %-34s lockdownDuration %s s < timelockDelay %s s\n' "INV-LIVE-3 violated" "$snap_d_num" "$tl_delay_num"
        printf '         %-34s (contract should have prevented this; investigate)\n' ""
        FAIL=1
    fi
else
    printf '  [WARN] %-34s 0 - NO coercion resistance: a quorum can remove the\n' "timelockDelay"
    printf '         %-34s guard or disarm signers instantly (INV-LIVE-1)\n' ""
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
    echo "All V1 checks passed."
    exit 0
fi
echo "One or more V1 checks failed."
exit 1
