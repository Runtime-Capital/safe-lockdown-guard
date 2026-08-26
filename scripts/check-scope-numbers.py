#!/usr/bin/env python3
"""Recompute every scope number the audit package states, and fail on drift.

The RFQ package repeats the same handful of figures across the repository, an
HTML/PDF scope sheet, and the Areta answer files in four formats. Nothing
recomputed them, so they could only be checked by hand, and a stale one is not a
cosmetic problem: the LOC/nSLOC totals are what an auditor prices from.

Usage:
    scripts/check-scope-numbers.py                 # repository files only
    scripts/check-scope-numbers.py --also DIR      # plus the RFQ package in DIR
    scripts/check-scope-numbers.py --report        # just print what is computed

No path outside the repository is hard-coded: the RFQ package lives outside it
and is passed with --also, so this script stays publishable as-is.

Exit codes: 0 all claims agree, 1 at least one drifted, 2 a metric could not be
computed.

The public snapshot deliberately omits two internal documents that repeat four
of these claims. Those four checks are reported as skipped when the publication
script is absent; the same missing files remain hard failures in the private
source-of-truth repository.
"""

import argparse
import html
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The audited scope, in the order the AUDIT_BRIEF table lists it.
SCOPE_FILES = [
    "src/Lockdown.sol",
    "src/LockdownTimelock.sol",
    "src/base/Timelock.sol",
    "src/base/StateMachine.sol",
    "src/handlers/LockdownFallbackHandler.sol",
    "src/base/LockdownSigners.sol",
    "src/base/RecoveryOwners.sol",
    "src/utils/LockdownLib.sol",
    "src/verifiers/WebAuthnVerifier.sol",
    "src/verifiers/PasswordVerifier.sol",
]

EIP170_LIMIT = 24576

# `scripts/publish-public.sh` is itself removed by the publication boundary, so
# its absence distinguishes a published snapshot from the private source of
# truth without relying on a configured Git remote. Only claims in files that
# the boundary intentionally removes may use this exception.
PUBLIC_BOUNDARY_SENTINEL = "scripts/publish-public.sh"
PUBLIC_OMITTED_CLAIM_FILES = frozenset(
    {
        "CLAUDE.md",
        "docs/AUDIT_READINESS_ADVERSARIAL_PROMPT.md",
    }
)

# Which documents state which metric. A metric is checked against every file
# listed here; "external" entries are relative to --also and are SKIPPED (not
# failed) when it is not passed.
CLAIMS = {
    "loc_total": {
        "label": "physical LOC across the scope files",
        "repo": ["README.md", "AUDIT_BRIEF.md"],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf",
            "grant/ARETA_APPLICATION_ANSWERS.md",
        ],
    },
    "nsloc_total": {
        "label": "nSLOC across the scope files",
        "repo": ["README.md", "AUDIT_BRIEF.md"],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf",
            "grant/ARETA_APPLICATION_ANSWERS.md",
        ],
    },
    "scope_file_count": {
        "label": "number of Solidity files in scope",
        "repo": ["README.md", "AUDIT_BRIEF.md"],
        "external": ["SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html"],
    },
    "test_total": {
        "label": "forge test total",
        "repo": [
            "README.md",
            "AUDIT_BRIEF.md",
            "docs/V1_REVIEW_PROMPT.md",
            "docs/DEV_ENVIRONMENT.md",
            "docs/AUDIT_READINESS_ADVERSARIAL_PROMPT.md",
        ],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf",
            "grant/ARETA_APPLICATION_ANSWERS.md",
        ],
    },
    "poc_test_total": {
        "label": "adversarial PoC tests in test/poc/",
        "repo": ["AUDIT_BRIEF.md", "docs/V1_REVIEW_PROMPT.md", "docs/PRE_TAG_REVIEW_DISPOSITIONS.md"],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html",
            "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf",
            "grant/ARETA_APPLICATION_ANSWERS.md",
        ],
    },
    "poc_file_count": {
        "label": "files in test/poc/",
        "repo": ["docs/V1_REVIEW_PROMPT.md", "docs/PRE_TAG_REVIEW_DISPOSITIONS.md"],
        "external": [],
    },
    "lockdown_timelock_runtime": {
        "label": "LockdownTimelock runtime bytecode size",
        "repo": ["AUDIT_BRIEF.md", "CLAUDE.md"],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
        ],
    },
    "lockdown_timelock_margin": {
        "label": "LockdownTimelock EIP-170 margin",
        "repo": ["AUDIT_BRIEF.md", "CLAUDE.md"],
        "external": [],
    },
    "lockdown_runtime": {
        "label": "Lockdown runtime bytecode size",
        "repo": ["AUDIT_BRIEF.md", "CLAUDE.md"],
        "external": [
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html",
            "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf",
        ],
    },
}

# Each pattern identifies the semantic claim and captures the number it states.
# Searching for the expected digits anywhere in a document is not a check: `10`
# matches `110`, and a stale claim can coexist with an unrelated correct number.
N = r"(?P<value>(?<!\d)\d+(?:[,  ]\d{3})*(?!\d))"
U = r"\d+(?:[,  ]\d{3})*"

PATTERNS = {
    "loc_total": {
        "README.md": rf"Solidity \| {N} physical lines",
        "AUDIT_BRIEF.md": rf"Total \(10 files\)\*\*\s*\|\s*\*\*{N}\*\*\s*\|\s*\*\*{U}\*\*",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"Total {N} {U}",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"{N} {U} Total",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt": rf"10 production Solidity files.*?{N} physical lines",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html": rf"10 production Solidity files.*?{N} physical lines",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf": rf"10 production Solidity files.*?{N} physical lines",
        "grant/ARETA_APPLICATION_ANSWERS.md": rf"production scope contains 10 Solidity files, {N} physical lines",
    },
    "nsloc_total": {
        "README.md": rf"10 source files, {N} nSLOC",
        "AUDIT_BRIEF.md": rf"Total \(10 files\)\*\*\s*\|\s*\*\*{U}\*\*\s*\|\s*\*\*{N}\*\*",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"In scope: 10 files, {N} nSLOC",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"In scope: 10 files, {N} nSLOC",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt": rf"10 production Solidity files, {N} non-blank non-comment source lines",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html": rf"10 production Solidity files, {N} non-blank non-comment source lines",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf": rf"10 production Solidity files, {N} non-blank non-comment source lines",
        "grant/ARETA_APPLICATION_ANSWERS.md": rf"production scope contains 10 Solidity files, {U} physical lines and {N} non-blank",
    },
    "scope_file_count": {
        "README.md": rf"physical lines across {N} source files",
        "AUDIT_BRIEF.md": rf"Total \({N} files\)",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"In scope: {N} files",
    },
    "test_total": {
        "README.md": rf"Tests \| {N} Foundry",
        "AUDIT_BRIEF.md": rf"forge test.*?{N} passed total",
        "docs/V1_REVIEW_PROMPT.md": rf"Run tests:.*?Expected: \D{{0,4}}{N} passed",
        "docs/DEV_ENVIRONMENT.md": rf"forge test # {N} passing",
        "docs/AUDIT_READINESS_ADVERSARIAL_PROMPT.md": rf"forge test: {N} passing",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"{N} Foundry unit, fuzz, integration",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"{N} Foundry unit, fuzz, integration",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt": rf"{N} Foundry unit, fuzz, integration",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html": rf"{N} Foundry unit, fuzz, integration",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf": rf"{N} Foundry unit, fuzz, integration",
        "grant/ARETA_APPLICATION_ANSWERS.md": rf"production scope contains 10 Solidity files.*?repository contains {N} Foundry",
    },
    "poc_test_total": {
        "AUDIT_BRIEF.md": rf"\+ {N} [^+]{{0,100}}test/poc/.*?adversarial proofs",
        "docs/V1_REVIEW_PROMPT.md": rf"{N} executable adversarial proofs",
        "docs/PRE_TAG_REVIEW_DISPOSITIONS.md": rf"test/poc/.*?12 files, {N} tests",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"and {N} adversarial PoCs",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"and {N} adversarial PoCs",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.txt": rf"and {N} adversarial PoCs",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.html": rf"and {N} adversarial PoCs",
        "grant/ARETA_MARKETPLACE_AUDIT_REQUEST.pdf": rf"and {N} adversarial PoCs",
        "grant/ARETA_APPLICATION_ANSWERS.md": rf"production scope contains 10 Solidity files.*?and {N} adversarial PoCs",
    },
    "poc_file_count": {
        "docs/V1_REVIEW_PROMPT.md": rf"across the {N} files in.*?test/poc/",
        "docs/PRE_TAG_REVIEW_DISPOSITIONS.md": rf"test/poc/.*?{N} files",
    },
    "lockdown_timelock_runtime": {
        "AUDIT_BRIEF.md": rf"LockdownTimelock\.sol.*?production singleton \({N} B runtime",
        "CLAUDE.md": rf"src/LockdownTimelock\.sol` \({N} B runtime",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"LockdownTimelock is the production singleton \({N} B runtime",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"LockdownTimelock is the production singleton \({N} B runtime",
    },
    "lockdown_timelock_margin": {
        "AUDIT_BRIEF.md": rf"{N} B EIP-170 margin",
        "CLAUDE.md": rf"EIP-170 margin {N} B",
    },
    "lockdown_runtime": {
        "AUDIT_BRIEF.md": rf"Lockdown\.sol.*?lockdown-only base \({N} B runtime",
        "CLAUDE.md": rf"src/Lockdown\.sol` \({N} B runtime",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.html": rf"Lockdown is the no-timelock base it inherits \({N} B",
        "SAFE_LOCKDOWN_GUARD_AUDIT_SCOPE.pdf": rf"Lockdown is the no-timelock base it inherits \({N} B",
    },
}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def nsloc(path):
    """Non-blank, non-comment source lines.

    Block comments are stripped first, then blank and `//` lines are dropped.
    This convention reproduces all ten per-file figures in the AUDIT_BRIEF
    table exactly, which is what pins it as the right one.
    """
    text = BLOCK_COMMENT.sub("", path.read_text())
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("//"))


def run(cmd, cwd=REPO):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def forge_test_count(extra_args=()):
    rc, out = run(["forge", "test", *extra_args])
    m = re.search(r"(\d+) tests? passed, (\d+) failed, (\d+) skipped", out)
    if rc != 0 or not m:
        return None, out
    passed, failed, skipped = (int(g) for g in m.groups())
    if failed or skipped:
        return None, f"suite is not green: {passed} passed, {failed} failed, {skipped} skipped"
    return passed, out


def contract_runtime_size(contract):
    artifact = REPO / "out" / f"{contract}.sol" / f"{contract}.json"
    if not artifact.is_file():
        return None
    obj = json.loads(artifact.read_text()).get("deployedBytecode", {}).get("object", "")
    if not obj or obj == "0x":
        return None
    return (len(obj) - 2) // 2


def compute():
    metrics, errors = {}, []

    missing = [f for f in SCOPE_FILES if not (REPO / f).is_file()]
    if missing:
        errors.append(f"scope files missing from the tree: {missing}")

    present = [REPO / f for f in SCOPE_FILES if (REPO / f).is_file()]
    metrics["scope_file_count"] = len(present)
    metrics["loc_total"] = sum(len(p.read_text().splitlines()) for p in present)
    metrics["nsloc_total"] = sum(nsloc(p) for p in present)
    metrics["per_file"] = {
        str(p.relative_to(REPO)): (len(p.read_text().splitlines()), nsloc(p)) for p in present
    }

    metrics["poc_file_count"] = len(sorted((REPO / "test" / "poc").glob("*.t.sol")))

    total, detail = forge_test_count()
    if total is None:
        errors.append(f"could not read the forge test total: {detail.strip()[:200]}")
    metrics["test_total"] = total

    poc, detail = forge_test_count(["--match-path", "test/poc/*"])
    if poc is None:
        errors.append(f"could not read the test/poc total: {detail.strip()[:200]}")
    metrics["poc_test_total"] = poc

    rc, _ = run(["forge", "build"])
    if rc != 0:
        errors.append("forge build failed; bytecode sizes unavailable")
    for key, contract in (
        ("lockdown_runtime", "Lockdown"),
        ("lockdown_timelock_runtime", "LockdownTimelock"),
    ):
        size = contract_runtime_size(contract)
        if size is None:
            errors.append(f"no build artifact for {contract}")
        metrics[key] = size
    if metrics.get("lockdown_timelock_runtime"):
        metrics["lockdown_timelock_margin"] = EIP170_LIMIT - metrics["lockdown_timelock_runtime"]
    else:
        metrics["lockdown_timelock_margin"] = None

    return metrics, errors


# ---------------------------------------------------------------------------
# Claim checking
# ---------------------------------------------------------------------------


def read_text_any(path):
    """Plain text of a .md/.txt/.html/.pdf document, or None if unreadable."""
    if path.suffix.lower() == ".pdf":
        rc, out = run(["pdftotext", str(path), "-"], cwd=None)
        text = out if rc == 0 else None
    else:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return None
    if text is None:
        return None
    if path.suffix.lower() == ".html":
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    # One representation for Markdown, HTML and pdftotext: patterns describe
    # semantic neighbours, not renderer-specific line wrapping or NBSPs.
    return " ".join(text.replace(" ", " ").replace(" ", " ").split())


def parse_claimed_integer(raw):
    return int(raw.replace(",", "").replace(" ", "").replace(" ", ""))


def extract_claims(text, pattern):
    return [parse_claimed_integer(m.group("value")) for m in re.finditer(pattern, text)]


def intentionally_omitted_public_claim(rel):
    return rel in PUBLIC_OMITTED_CLAIM_FILES and not (REPO / PUBLIC_BOUNDARY_SENTINEL).is_file()


def check(metrics, also):
    failures, skipped, checked = [], [], 0

    for key, spec in CLAIMS.items():
        value = metrics.get(key)
        if value is None:
            failures.append(f"{key}: NOT COMPUTED, cannot verify any claim")
            continue
        targets = [(REPO / rel, rel, "repo") for rel in spec["repo"]]
        if also:
            targets += [(Path(also) / rel, rel, "external") for rel in spec["external"]]
        else:
            skipped += [f"{key}: {rel} (pass --also to check the RFQ package)" for rel in spec["external"]]

        for path, rel, origin in targets:
            if not path.is_file():
                if origin == "repo" and intentionally_omitted_public_claim(rel):
                    skipped.append(f"{key}: {rel} (intentionally omitted from public snapshot)")
                    continue
                failures.append(f"{key}: {origin} file not found: {rel}")
                continue
            text = read_text_any(path)
            if text is None:
                failures.append(f"{key}: could not read {rel} (pdftotext missing?)")
                continue
            checked += 1
            pattern = PATTERNS.get(key, {}).get(rel)
            if pattern is None:
                failures.append(f"{key}: checker has no anchored claim pattern for {rel}")
                continue
            stated = extract_claims(text, pattern)
            if not stated:
                failures.append(
                    f"{key}: could not locate the labelled claim ({spec['label']}) in {rel}"
                )
            elif any(claim != value for claim in stated):
                failures.append(
                    f"{key} = {value} ({spec['label']}) but {rel} states {stated}"
                )
    return failures, skipped, checked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--also", help="Directory holding the RFQ package (scope sheet, Areta answers).")
    ap.add_argument("--report", action="store_true", help="Print the computed metrics and exit 0.")
    args = ap.parse_args()

    metrics, errors = compute()

    print("== computed ==")
    for f, (loc, ns) in metrics.get("per_file", {}).items():
        print(f"   {f:46s} LOC {loc:>5}  nSLOC {ns:>5}")
    for key in (
        "scope_file_count",
        "loc_total",
        "nsloc_total",
        "test_total",
        "poc_test_total",
        "poc_file_count",
        "lockdown_runtime",
        "lockdown_timelock_runtime",
        "lockdown_timelock_margin",
    ):
        print(f"   {key:30s} {metrics.get(key)}")

    if errors:
        print("\n== could not compute ==")
        for e in errors:
            print(f"   {e}")
        return 2

    if args.report:
        return 0

    failures, skipped, checked = check(metrics, args.also)

    if skipped:
        print(f"\n== skipped ({len(skipped)} external claims) ==")
        for s in skipped[:3]:
            print(f"   {s}")
        if len(skipped) > 3:
            print(f"   ... and {len(skipped) - 3} more")

    print(f"\n== {checked} claims checked ==")
    if failures:
        print(f"\n== {len(failures)} DRIFTED ==")
        for f in failures:
            print(f"   FAIL {f}")
        return 1
    print("   all stated figures match what the tree actually contains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
