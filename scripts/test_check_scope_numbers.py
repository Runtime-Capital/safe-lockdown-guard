#!/usr/bin/env python3
"""Unit tests for the anchored scope-claim checker (no Forge invocation)."""

import importlib.util
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_scope_numbers", HERE / "check-scope-numbers.py")
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


@case
def test_expected_digits_elsewhere_do_not_mask_a_stale_labelled_claim():
    pattern = scope.PATTERNS["test_total"]["README.md"]
    text = "483 appears in unrelated prose. | Tests | 482 Foundry unit tests |"
    assert scope.extract_claims(text, pattern) == [482]


@case
def test_small_values_are_not_substring_matches():
    pattern = scope.PATTERNS["scope_file_count"]["README.md"]
    text = "| Solidity | 2,314 physical lines across 110 source files, 1,121 nSLOC |"
    assert scope.extract_claims(text, pattern) == [110]


@case
def test_duplicate_current_claims_are_all_visible_to_the_checker():
    pattern = scope.PATTERNS["test_total"]["README.md"]
    text = "| Tests | 483 Foundry tests | later | Tests | 482 Foundry tests |"
    assert scope.extract_claims(text, pattern) == [483, 482]


@case
def test_scope_table_columns_are_extracted_independently():
    text = "| **Total (10 files)** | **2,312** | **9,999** |"
    assert scope.extract_claims(text, scope.PATTERNS["loc_total"]["AUDIT_BRIEF.md"]) == [2312]
    assert scope.extract_claims(text, scope.PATTERNS["nsloc_total"]["AUDIT_BRIEF.md"]) == [9999]


@case
def test_every_declared_target_has_an_anchored_pattern():
    missing = []
    for key, spec in scope.CLAIMS.items():
        for rel in spec["repo"] + spec["external"]:
            if rel not in scope.PATTERNS.get(key, {}):
                missing.append((key, rel))
    assert not missing, missing


@case
def test_current_repository_claims_are_located_and_exact():
    metrics = {
        "loc_total": 2312,
        "nsloc_total": 1118,
        "scope_file_count": 10,
        "test_total": 483,
        "poc_test_total": 137,
        "poc_file_count": 12,
        "lockdown_timelock_runtime": 17590,
        "lockdown_timelock_margin": 6986,
        "lockdown_runtime": 12320,
    }
    failures, skipped, checked = scope.check(metrics, None)
    expected_checked = sum(
        1
        for claim in scope.CLAIMS.values()
        for rel in claim["repo"]
        if (scope.REPO / rel).is_file()
    )
    expected_omitted = sum(
        1
        for claim in scope.CLAIMS.values()
        for rel in claim["repo"]
        if scope.intentionally_omitted_public_claim(rel)
    )
    assert checked == expected_checked, (checked, expected_checked)
    public_omissions = [item for item in skipped if "intentionally omitted" in item]
    assert len(public_omissions) == expected_omitted, (public_omissions, expected_omitted)
    assert not failures, failures


@case
def test_public_snapshot_skips_only_declared_internal_claim_files():
    original_repo = scope.REPO
    try:
        with tempfile.TemporaryDirectory() as tmp:
            scope.REPO = Path(tmp)
            assert scope.intentionally_omitted_public_claim("CLAUDE.md")
            assert scope.intentionally_omitted_public_claim(
                "docs/AUDIT_READINESS_ADVERSARIAL_PROMPT.md"
            )
            assert not scope.intentionally_omitted_public_claim("AUDIT_BRIEF.md")
    finally:
        scope.REPO = original_repo


@case
def test_private_repository_never_skips_a_missing_internal_claim_file():
    original_repo = scope.REPO
    try:
        with tempfile.TemporaryDirectory() as tmp:
            scope.REPO = Path(tmp)
            sentinel = scope.REPO / scope.PUBLIC_BOUNDARY_SENTINEL
            sentinel.parent.mkdir(parents=True)
            sentinel.touch()
            assert not scope.intentionally_omitted_public_claim("CLAUDE.md")
    finally:
        scope.REPO = original_repo


@case
def test_nonzero_forge_exit_cannot_be_reported_as_a_green_count():
    original = scope.run
    try:
        scope.run = lambda *_args, **_kwargs: (1, "483 tests passed, 0 failed, 0 skipped")
        total, _ = scope.forge_test_count()
        assert total is None
    finally:
        scope.run = original


def main():
    failed = []
    for fn in CASES:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:
            failed.append(fn.__name__)
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(CASES) - len(failed)} passed, {len(failed)} failed, {len(CASES)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
