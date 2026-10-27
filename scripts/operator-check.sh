#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Operator artifact checks =="

if ! command -v node >/dev/null 2>&1; then
    echo "node is required for JSON validation" >&2
    exit 1
fi

node -e 'for (const p of ["deploy/manifest.json", "docs/clear-signing/calldata-safe-lockdown-1.json", "docs/clear-signing/eip712-lockdown-1.json", "package.json"]) { JSON.parse(require("fs").readFileSync(p, "utf8")); console.log(`[OK] JSON ${p}`); }'

if grep -R "0xFILL_" deploy/manifest.json >/dev/null 2>&1; then
    echo "[WARN] deploy/manifest.json still contains pre-deploy 0xFILL_ placeholders"
fi

bash -n scripts/preflight-install-v1.sh
bash -n scripts/verify-install-v1.sh
bash -n scripts/operator-e2e-anvil.sh
bash -n scripts/gen-manifest-codehashes.sh
bash -n scripts/package-audit.sh
echo "[OK] operator shell scripts parse"

printf '%s  %s\n' \
    "c8550f9644492f2d1278467b301c615c768a0d61d5c22d5bcd107ec7c9cbd329" \
    "deploy/vendor/ethers-6.13.5.umd.min.js" | sha256sum --check --status
test -f LICENSES/ethers-6.13.5-MIT.txt
echo "[OK] vendored ethers 6.13.5 integrity and MIT notice"

tmp_zip="$(mktemp /tmp/safe-lockdown-audit.XXXXXX.zip)"
tmp_zip_repeat="$(mktemp /tmp/safe-lockdown-audit-repeat.XXXXXX.zip)"
scripts/package-audit.sh "$tmp_zip" >/dev/null
scripts/package-audit.sh "$tmp_zip_repeat" >/dev/null
unzip -t "$tmp_zip" >/dev/null
if ! cmp -s "$tmp_zip" "$tmp_zip_repeat"; then
    echo "Audit package is not deterministic for the same Git tree" >&2
    rm -f "$tmp_zip" "$tmp_zip_repeat"
    exit 1
fi
rm -f "$tmp_zip" "$tmp_zip_repeat"
echo "[OK] audit package builds, verifies, and is deterministic"

scripts/browser-smoke-lockdown-lifecycle.sh
