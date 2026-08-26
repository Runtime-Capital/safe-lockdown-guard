#!/usr/bin/env bash
set -euo pipefail
#
# package-audit.sh
#
# Optional utility that produces a clean filesystem snapshot of tracked
# repository files. It intentionally starts from `git archive`, not from a copy
# of the working tree, so untracked local files (including secrets) cannot be
# swept into the audit bundle.
#
# Primary audit handoff is the git repository itself. This script is provided
# for reviewers who prefer a single zip/tarball without .git history or any
# locally-ignored files.
#
# Usage: scripts/package-audit.sh [output.zip]
#

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/tmp/safe-lockdown-audit.zip}"
STAGING="$(mktemp -d /tmp/safe-lockdown-package.XXXXXX)"

if ! command -v git >/dev/null 2>&1; then
    echo "git not found" >&2
    exit 1
fi

if ! command -v zip >/dev/null 2>&1; then
    echo "zip not found" >&2
    exit 1
fi

secret_path_re='(\.env($|\.)|(^|/)\.?(secret|seed)s?(/|$)|(credential|mnemonic|passphrase|privkey|private[_-]?key|keystore)|(secret|seed).*\.(json|ya?ml|toml|txt)$|\.(pem|key|keystore|p12|pfx|jks|asc|gpg|pkcs8|der)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)|(^|/)UTC--)'
if git -C "$ROOT" ls-files | grep -Eiq "$secret_path_re"; then
    echo "Refusing to package: tracked secret-like paths detected." >&2
    echo "Review tracked filenames matching: $secret_path_re" >&2
    exit 1
fi

if git -C "$ROOT" submodule status --recursive | grep -Eq '^[-+U]'; then
    echo "Refusing to package: one or more pinned submodules are uninitialized, conflicted, or not at the recorded gitlink." >&2
    echo "Run: git submodule update --init --recursive" >&2
    exit 1
fi

rm -f "$OUT"
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/safe-lockdown"
git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$STAGING/safe-lockdown"
export AUDIT_STAGING="$STAGING/safe-lockdown"
git -C "$ROOT" submodule foreach --recursive '
    mkdir -p "$AUDIT_STAGING/$displaypath"
    git archive --format=tar HEAD | tar -x -C "$AUDIT_STAGING/$displaypath"
' >/dev/null
cd "$STAGING"

zip -qXDr "$OUT" safe-lockdown \
    -x 'safe-lockdown/.env' \
    -x 'safe-lockdown/.env.*' \
    -x 'safe-lockdown/.secrets/*' \
    -x 'safe-lockdown/secret/*' \
    -x 'safe-lockdown/secrets/*' \
    -x 'safe-lockdown/CLAUDE.md' \
    -x 'safe-lockdown/config/*.local.json' \
    -x 'safe-lockdown/clear-signing/*.rendered.json' \
    -x 'safe-lockdown/clear-signing/*.local.json' \
    -x 'safe-lockdown/deploy/*.local.*' \
    -x 'safe-lockdown/deploy/*-rabby.txt' \
    -x 'safe-lockdown/deploy/HANDOVER.local.md' \
    -x 'safe-lockdown/cache/*' \
    -x 'safe-lockdown/out/*' \
    -x 'safe-lockdown/broadcast/*' \
    -x 'safe-lockdown/crytic-export/*' \
    -x 'safe-lockdown/medusa-corpus/*' \
    -x 'safe-lockdown/reproducibility/*' \
    -x 'safe-lockdown/.forge-snapshots/*' \
    -x 'safe-lockdown/slither-report*.json' \
    -x 'safe-lockdown/test/echidna/corpus/*' \
    -x 'safe-lockdown/test/echidna/covered.*.html' \
    -x 'safe-lockdown/test/echidna/crytic-export/*'

echo "$OUT"
