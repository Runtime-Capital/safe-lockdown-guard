#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTML="$ROOT/deploy/guard-install.local.html"
ARTIFACT="$ROOT/out/LockdownTimelock.sol/LockdownTimelock.json"

if [[ ! -f "$HTML" ]]; then
    echo "missing local deployment helper: $HTML" >&2
    echo "copy or restore deploy/guard-install.local.html before syncing bytecode" >&2
    exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
    echo "missing artifact: $ARTIFACT" >&2
    echo "run: forge build --sizes" >&2
    exit 1
fi

node -e '
const fs = require("fs");
const htmlPath = process.argv[1];
const artifactPath = process.argv[2];
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
const bytecode = artifact.bytecode.object;
const html = fs.readFileSync(htmlPath, "utf8");
const q = String.fromCharCode(39);
const marker = new RegExp("const GUARD_CREATION_BYTECODE = " + q + "0x[0-9a-fA-F]+" + q + ";");
const replacement = "const GUARD_CREATION_BYTECODE = " + q + bytecode + q + ";";
if (!marker.test(html)) {
  console.error("GUARD_CREATION_BYTECODE marker not found");
  process.exit(1);
}
const next = html.replace(marker, replacement);
fs.writeFileSync(htmlPath, next);
console.log(`synced guard-install bytecode (${(bytecode.length - 2) / 2} bytes)`);
' "$HTML" "$ARTIFACT"

"$ROOT/scripts/check-embedded-bytecode.sh"
