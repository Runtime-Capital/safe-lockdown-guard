#!/usr/bin/env bash
#
# gen-manifest-codehashes.sh
#
# Helper to populate deploy/manifest.json codehashes.
#
#   - Always prints the build codehashes for the bundled verifiers, derived
#     from the local forge build.
#   - With --rpc and one or more deployed addresses, also prints the
#     on-chain EXTCODEHASH for the singleton and/or MultiSendCallOnly so you
#     can paste them into the per-chain manifest entry.
#
# The Lockdown singleton codehash is per-chain (it bakes the
# MULTI_SEND_CALL_ONLY immutable), so it can only be read post-deploy from
# chain, never from the artifact template.
#
# Usage:
#   scripts/gen-manifest-codehashes.sh
#   scripts/gen-manifest-codehashes.sh --check-manifest deploy/manifest.json
#   scripts/gen-manifest-codehashes.sh --rpc <url> \
#       [--singleton <addr>] [--multi-send <addr>]
#

set -euo pipefail

RPC=""
SINGLETON=""
MULTI_SEND=""
CHECK_MANIFEST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc) RPC="$2"; shift 2 ;;
        --singleton) SINGLETON="$2"; shift 2 ;;
        --multi-send) MULTI_SEND="$2"; shift 2 ;;
        --check-manifest) CHECK_MANIFEST="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

if ! command -v cast >/dev/null 2>&1; then
    echo "cast not found. Install Foundry." >&2; exit 1
fi
if ! command -v forge >/dev/null 2>&1; then
    echo "forge not found. Install Foundry." >&2; exit 1
fi

onchain_codehash() {
    local addr="$1" code
    code=$(cast code "$addr" --rpc-url "$RPC" 2>/dev/null || true)
    if [[ -z "$code" || "$code" == "0x" ]]; then
        echo "ERROR: no code at $addr" >&2; return 1
    fi
    cast keccak "$code"
}

compare_manifest_hash() {
    local key="$1" actual="$2" expected
    if ! expected=$(jq -er ".build.${key}" "$CHECK_MANIFEST"); then
        echo "ERROR: deploy manifest has no string .build.${key}" >&2
        return 1
    fi
    if [[ "${expected,,}" != "${actual,,}" ]]; then
        echo "ERROR: .build.${key} is stale" >&2
        echo "  manifest: ${expected}" >&2
        echo "  build:    ${actual}" >&2
        return 1
    fi
    printf '[OK] .build.%s matches %s\n' "$key" "$actual"
}

# The UV policy is a compile-time constant (`_requireUV`), not a constructor
# immutable: OZ declares it `internal pure`, so it cannot read an immutable.
# Each policy is therefore its own contract with its own runtime, and the two
# runtimes are read directly rather than bytecode-patched.
verifier_runtime() {
    local contract="$1" bc
    bc=$(forge inspect "src/verifiers/WebAuthnVerifier.sol:${contract}" deployedBytecode)
    if [[ -z "$bc" || "$bc" == "0x" ]]; then
        echo "ERROR: empty deployedBytecode for ${contract}. Run 'forge build' first." >&2
        return 1
    fi
    printf '%s\n' "$bc"
}

echo "== build codehashes =="
password_bc=$(forge inspect PasswordVerifier deployedBytecode)
webauthn_false_bc=$(verifier_runtime WebAuthnVerifierNoUV)
webauthn_true_bc=$(verifier_runtime WebAuthnVerifier)
password_hash=$(cast keccak "$password_bc")
webauthn_false_hash=$(cast keccak "$webauthn_false_bc")
webauthn_true_hash=$(cast keccak "$webauthn_true_bc")

# Guard: the two policies MUST be distinguishable. If they collapse to one hash
# the UV policy is not actually being pinned, and an operator could install the
# wrong verifier while passing every codehash check.
if [[ "$webauthn_false_hash" == "$webauthn_true_hash" ]]; then
    echo "ERROR: WebAuthnVerifier and WebAuthnVerifierNoUV have the same codehash." >&2
    echo "  The UV policy is not being pinned. Check the _requireUV overrides." >&2
    exit 1
fi
printf '  build.passwordVerifierCodehash = %s\n' "$password_hash"
printf '  build.webAuthnVerifierCodehashRequireUVFalse = %s\n' "$webauthn_false_hash"
printf '  build.webAuthnVerifierCodehashRequireUVTrue = %s\n' "$webauthn_true_hash"

if [[ -n "$CHECK_MANIFEST" ]]; then
    if [[ ! -f "$CHECK_MANIFEST" ]]; then
        echo "ERROR: manifest not found: $CHECK_MANIFEST" >&2
        exit 1
    fi
    echo
    echo "== manifest consistency =="
    manifest_status=0
    compare_manifest_hash "passwordVerifierCodehash" "$password_hash" || manifest_status=1
    compare_manifest_hash "webAuthnVerifierCodehashRequireUVFalse" "$webauthn_false_hash" || manifest_status=1
    compare_manifest_hash "webAuthnVerifierCodehashRequireUVTrue" "$webauthn_true_hash" || manifest_status=1
    if [[ "$manifest_status" -ne 0 ]]; then
        echo "Regenerate deploy/manifest.json from the frozen build." >&2
        exit "$manifest_status"
    fi
fi

if [[ -n "$RPC" ]]; then
    echo
    echo "== on-chain codehashes (paste into .chains[<chainId>]) =="
    chain_id=$(cast chain-id --rpc-url "$RPC" 2>/dev/null || echo "?")
    printf '  chainId = %s\n' "$chain_id"
    if [[ -n "$SINGLETON" ]]; then
        printf '  singletonCodehash = %s\n' "$(onchain_codehash "$SINGLETON")"
    fi
    if [[ -n "$MULTI_SEND" ]]; then
        printf '  multiSendCodehash = %s\n' "$(onchain_codehash "$MULTI_SEND")"
    fi
fi
