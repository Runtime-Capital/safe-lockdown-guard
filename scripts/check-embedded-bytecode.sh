#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTML="$ROOT/deploy/guard-install.local.html"
ARTIFACT="$ROOT/out/LockdownTimelock.sol/LockdownTimelock.json"

if [[ ! -f "$HTML" ]]; then
    echo "missing local deployment helper: $HTML" >&2
    echo "copy or restore deploy/guard-install.local.html before running this optional deployment check" >&2
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
const html = fs.readFileSync(htmlPath, "utf8");
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
const match = html.match(/const GUARD_CREATION_BYTECODE = '\''([^'\'']+)'\''/);
if (!match) {
  console.error("GUARD_CREATION_BYTECODE marker not found");
  process.exit(1);
}
if (match[1] !== artifact.bytecode.object) {
  console.error("embedded bytecode mismatch");
  console.error(`html bytes:     ${(match[1].length - 2) / 2}`);
  console.error(`artifact bytes: ${(artifact.bytecode.object.length - 2) / 2}`);
  process.exit(1);
}
console.log("embedded-bytecode-ok");
' "$HTML" "$ARTIFACT"
