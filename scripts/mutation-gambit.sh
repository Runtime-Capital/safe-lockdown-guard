#!/usr/bin/env bash
#
# Targeted Gambit mutation pass.
#
# Gambit (the Certora/ToB CLI) only GENERATES mutants; it has no
# `--test-command`. It also cannot compile this contract: Lockdown.sol needs
# `--via-ir` (stack-too-deep otherwise) and the gambit CLI cannot pass it. So
# we generate mutants with `--skip_validate` (gambit only needs the AST, which
# compiles without via-ir) and kill them with `forge test`, which DOES use
# via-ir. A mutant is "killed" when the suite fails (or the mutant fails to
# build); a "survivor" is a mutant the suite still passes -> a coverage gap.
#
# Env knobs:
#   GAMBIT_TARGET_FILE   Solidity file to mutate (default src/Lockdown.sol).
#   GAMBIT_SAMPLE_EVERY  sample 1-in-N mutants (default 40; set 1 for the full
#                        campaign, which takes hours on via-ir).
#   GAMBIT_WORKDIR       output dir (default mutation-work/gambit-<target>).
#   GAMBIT_RESULTS       result file (default mutation-work/kill-results-<target>.txt).
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# solc-select / solc ship in the slither uv-tool venv; put it on PATH.
UV_SLITHER_BIN="$HOME/.local/share/uv/tools/slither-analyzer/bin"
[ -d "$UV_SLITHER_BIN" ] && PATH="$UV_SLITHER_BIN:$PATH"

if ! command -v gambit >/dev/null 2>&1; then
  echo "gambit not installed; see docs/GAMBIT_MUTATION_PLAN.md"; exit 0
fi
if ! command -v solc >/dev/null 2>&1; then
  echo "solc not found (install via 'solc-select install 0.8.35 && solc-select use 0.8.35')"; exit 0
fi

TARGET_FILE="${GAMBIT_TARGET_FILE:-src/Lockdown.sol}"
TARGET_SLUG="${TARGET_FILE//\//-}"
TARGET_SLUG="${TARGET_SLUG%.sol}"
WORKDIR="${GAMBIT_WORKDIR:-mutation-work/gambit-$TARGET_SLUG}"
SAMPLE_EVERY="${GAMBIT_SAMPLE_EVERY:-40}"
RESULTS="${GAMBIT_RESULTS:-mutation-work/kill-results-$TARGET_SLUG.txt}"
JSON="$WORKDIR/gambit_results.json"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR" "$(dirname "$RESULTS")"

echo "Generating mutants for $TARGET_FILE (skip_validate; via-ir kill via forge)..."
gambit mutate --filename "$TARGET_FILE" --outdir "$WORKDIR" --skip_validate \
  --solc_evm_version prague \
  --solc_remappings \
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/" \
    "openzeppelin-contracts/=lib/openzeppelin-contracts/" \
    "@safe-global/safe-smart-account/=lib/safe-smart-account/contracts/"

total_mutants=$(jq 'length' "$JSON")
if [ "$total_mutants" -eq 0 ]; then
  echo "Generated 0 mutants for $TARGET_FILE; treating this as a failed campaign." >&2
  exit 1
fi
echo "Generated $total_mutants mutants. Sampling 1-in-$SAMPLE_EVERY and killing with 'forge test'."

ORIG=$(mktemp)
cp "$TARGET_FILE" "$ORIG"
trap 'cp "$ORIG" "$TARGET_FILE"' EXIT

ids=$(jq -r '.[].id' "$JSON" | awk -v n="$SAMPLE_EVERY" 'NR % n == 1')
killed=0; survived=0; total=0
: > "$RESULTS"
for id in $ids; do
  mfile="$WORKDIR/mutants/$id/$TARGET_FILE"
  [ -f "$mfile" ] || continue
  cp "$mfile" "$TARGET_FILE"
  total=$((total + 1))
  desc=$(jq -r ".[] | select(.id==\"$id\") | .description" "$JSON")
  if forge test >/dev/null 2>&1; then
    survived=$((survived + 1))
    echo "SURVIVED id=$id $desc" >> "$RESULTS"
  else
    killed=$((killed + 1))
    echo "killed   id=$id $desc" >> "$RESULTS"
  fi
done
cp "$ORIG" "$TARGET_FILE"

echo "TOTAL=$total KILLED=$killed SURVIVED=$survived" | tee -a "$RESULTS"
echo "Survivors (if any) listed in $RESULTS - each is a coverage gap to close."
