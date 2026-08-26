#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

forge build >/dev/null

limit=24576

printf '%-34s %10s %10s\n' "Contract" "Runtime" "EIP-170 margin"
printf '%-34s %10s %10s\n' "--------" "-------" "-------------"

for contract in Lockdown LockdownTimelock LockdownFallbackHandler; do
    artifact=$(find out -path "*/${contract}.json" -type f | sort | head -n1)
    if [[ -z "$artifact" ]]; then
        printf '%-34s %10s %10s\n' "$contract" "missing" "missing"
        exit 1
    fi
    bytecode=$(jq -r '.deployedBytecode.object // empty' "$artifact")
    if [[ -z "$bytecode" || "$bytecode" == "null" || "$bytecode" == "0x" ]]; then
        printf '%-34s %10s %10s\n' "$contract" "empty" "empty"
        exit 1
    fi
    size=$(( (${#bytecode} - 2) / 2 ))
    margin=$(( limit - size ))
    printf '%-34s %8d B %8d B\n' "$contract" "$size" "$margin"
done
