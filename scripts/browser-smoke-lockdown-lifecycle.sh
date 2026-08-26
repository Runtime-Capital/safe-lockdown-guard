#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to run the browser smoke test" >&2
  exit 1
fi

if [ ! -d node_modules/@playwright/test ]; then
  if [ ! -f package-lock.json ]; then
    echo "package-lock.json is required for reproducible browser smoke dependencies" >&2
    exit 1
  fi
  npm ci
fi

if ! command -v google-chrome >/dev/null 2>&1 \
  && ! command -v google-chrome-stable >/dev/null 2>&1 \
  && ! command -v chromium >/dev/null 2>&1 \
  && ! command -v chromium-browser >/dev/null 2>&1; then
  echo "Chrome/Chromium is required by tests/browser/playwright.config.js (channel: chrome)" >&2
  echo "Install Chrome or adjust the Playwright config intentionally." >&2
  exit 1
fi

npm run browser-smoke
