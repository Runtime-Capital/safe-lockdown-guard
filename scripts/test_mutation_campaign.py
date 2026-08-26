#!/usr/bin/env python3
"""Safety tests for `scripts/mutation-campaign.py`.

These test the runner's GUARDRAILS, not a mutation campaign: nothing here runs
Forge or mutates production source. Every filesystem case uses a controlled
`tempfile` directory containing a sentinel file, and each refusal test asserts
afterwards that the sentinel still exists - the point of the guardrails is that
a refused path is left untouched, never cleaned up.

Run with:
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_mutation_campaign.py
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "mutation-campaign.py"

spec = importlib.util.spec_from_file_location("mutation_campaign", RUNNER)
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


# ---------------------------------------------------------------------------
# Tiny harness (no pytest dependency: this must run anywhere forge runs)
# ---------------------------------------------------------------------------

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def seeded_dir(parent=None):
    """A temp directory holding a sentinel file, to prove nothing deletes it."""
    d = Path(tempfile.mkdtemp(dir=parent))
    (d / "SENTINEL.txt").write_text("must survive")
    return d


def assert_survived(d):
    assert (d / "SENTINEL.txt").is_file(), f"guardrail deleted content under {d}"


@case
def test_workspace_copy_contains_only_tracked_files():
    base = Path(tempfile.mkdtemp())
    try:
        repo, ws = base / "repo", base / "workspace"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Target.sol").write_text("contract Target {}\n")
        (repo / ".gitignore").write_text("ignored-local.txt\n")
        (repo / "ignored-local.txt").write_text("must never enter the workspace\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "add", ".gitignore", "src/Target.sol"], check=True
        )

        pristine, error = mc.populate_workspace(ws, {"src/Target.sol"}, repo=repo)

        assert error is None, error
        assert (ws / "src" / "Target.sol").read_text() == "contract Target {}\n"
        assert (ws / ".gitignore").is_file()
        assert not (ws / "ignored-local.txt").exists(), "ignored file leaked into workspace"
        assert not (ws / ".git").exists(), "git metadata leaked into workspace"
        assert (pristine / "src" / "Target.sol").is_file()
    finally:
        shutil.rmtree(base)


# ---------------------------------------------------------------------------
# Workspace path safety
# ---------------------------------------------------------------------------


@case
def test_workspace_equal_to_repo_is_refused():
    repo = seeded_dir()
    try:
        reason = mc.check_workspace_path(repo, repo=repo)
        assert reason and "must not be the repository" in reason, reason
        assert_survived(repo)
    finally:
        shutil.rmtree(repo)


@case
def test_workspace_inside_repo_is_refused():
    repo = seeded_dir()
    try:
        ws = seeded_dir(parent=repo)
        reason = mc.check_workspace_path(ws, repo=repo)
        assert reason and "must not live inside the repository" in reason, reason
        assert_survived(ws)
        assert_survived(repo)
    finally:
        shutil.rmtree(repo)


@case
def test_workspace_containing_repo_is_refused():
    parent = seeded_dir()
    try:
        repo = seeded_dir(parent=parent)
        reason = mc.check_workspace_path(parent, repo=repo)
        assert reason and "must not contain the repository" in reason, reason
        assert_survived(parent)
        assert_survived(repo)
    finally:
        shutil.rmtree(parent)


@case
def test_non_empty_workspace_is_refused_and_not_deleted():
    repo = seeded_dir()
    ws = seeded_dir()
    try:
        reason = mc.check_workspace_path(ws, repo=repo)
        assert reason and "must be empty" in reason, reason
        assert "never deletes" in reason, reason
        # The whole point: refusal, not cleanup.
        assert_survived(ws)
        assert list(ws.iterdir()), "workspace content was removed"
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(ws)


@case
def test_empty_workspace_is_accepted():
    repo = seeded_dir()
    ws = Path(tempfile.mkdtemp())  # exactly what `mktemp -d` produces
    try:
        assert mc.check_workspace_path(ws, repo=repo) is None
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(ws)


@case
def test_missing_workspace_path_is_accepted():
    repo = seeded_dir()
    base = Path(tempfile.mkdtemp())
    try:
        ws = base / "not-created-yet"
        assert mc.check_workspace_path(ws, repo=repo) is None
        assert not ws.exists(), "the predicate must not create the workspace"
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(base)


@case
def test_workspace_file_path_is_refused():
    repo = seeded_dir()
    base = Path(tempfile.mkdtemp())
    try:
        f = base / "a-file"
        f.write_text("x")
        reason = mc.check_workspace_path(f, repo=repo)
        assert reason and "not a directory" in reason, reason
        assert f.is_file()
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(base)


# ---------------------------------------------------------------------------
# --out safety
# ---------------------------------------------------------------------------


@case
def test_existing_out_is_refused():
    ws = Path(tempfile.mkdtemp())
    base = Path(tempfile.mkdtemp())
    try:
        out = base / "campaign.jsonl"
        out.write_text("previous campaign\n")
        reason = mc.check_out_path(out, ws)
        assert reason and "refusing to overwrite" in reason, reason
        assert out.read_text() == "previous campaign\n", "previous campaign was modified"
    finally:
        shutil.rmtree(ws)
        shutil.rmtree(base)


@case
def test_out_inside_workspace_is_refused():
    ws = Path(tempfile.mkdtemp())
    try:
        reason = mc.check_out_path(ws / "campaign.jsonl", ws)
        assert reason and "outside the workspace" in reason, reason
    finally:
        shutil.rmtree(ws)


@case
def test_out_inside_the_repository_is_refused():
    # Writing results under REPO would make the runner dirty the very worktree
    # whose cleanliness it just certified, blocking the NEXT campaign.
    repo = seeded_dir()
    ws = Path(tempfile.mkdtemp())
    try:
        reason = mc.check_out_path(repo / "evidence" / "campaign.jsonl", ws, repo=repo)
        assert reason and "outside the repository" in reason, reason
        reason = mc.check_out_path(repo / "campaign.jsonl", ws, repo=repo)
        assert reason and "outside the repository" in reason, reason
        assert_survived(repo)
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(ws)


@case
def test_fresh_out_beside_the_workspace_is_accepted():
    ws = Path(tempfile.mkdtemp())
    base = Path(tempfile.mkdtemp())
    try:
        assert mc.check_out_path(base / "campaign.jsonl", ws) is None
    finally:
        shutil.rmtree(ws)
        shutil.rmtree(base)


@case
def test_log_directory_must_not_overlap_workspace_or_repo():
    repo = seeded_dir()
    base = Path(tempfile.mkdtemp())
    try:
        ws = base / "campaign-logs"
        ws.mkdir()
        reason = mc.check_logdir_path(ws, ws, repo=repo)
        assert reason and "disjoint" in reason, reason
        reason = mc.check_logdir_path(repo / "logs", ws, repo=repo)
        assert reason and "outside the repository" in reason, reason
    finally:
        shutil.rmtree(repo)
        shutil.rmtree(base)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def _git(cwd, *args):
    import subprocess

    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _tiny_repo():
    d = Path(tempfile.mkdtemp())
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@example.com")
    _git(d, "config", "user.name", "t")
    (d / "f.txt").write_text("committed\n")
    _git(d, "add", "f.txt")
    _git(d, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
    return d


@case
def test_clean_repo_provenance_is_accepted_and_records_sha_and_tree():
    repo = _tiny_repo()
    try:
        prov, refusal = mc.collect_provenance(repo)
        assert refusal is None, refusal
        assert prov["baseline_dirty"] is False
        assert len(prov["baseline_sha"]) == 40, prov
        assert len(prov["baseline_tree"]) == 40, prov
        assert "submodules" in prov
    finally:
        shutil.rmtree(repo)


@case
def test_dirty_worktree_is_refused():
    repo = _tiny_repo()
    try:
        (repo / "f.txt").write_text("locally modified\n")
        prov, refusal = mc.collect_provenance(repo)
        assert refusal and "dirty" in refusal, refusal
        assert prov["baseline_dirty"] is True
    finally:
        shutil.rmtree(repo)


@case
def test_untracked_file_is_refused():
    repo = _tiny_repo()
    try:
        (repo / "stray.txt").write_text("untracked\n")
        prov, refusal = mc.collect_provenance(repo)
        assert refusal and "dirty" in refusal, refusal
        assert prov["baseline_dirty"] is True
    finally:
        shutil.rmtree(repo)


@case
def test_there_is_no_way_to_record_a_dirty_baseline():
    # The CLI must expose no flag that would let a dirty tree be classified.
    src = RUNNER.read_text()
    assert "--fresh-workspace" not in src, "the destructive --fresh-workspace flag is back"
    assert "shutil.rmtree" not in src, "the runner must never rmtree anything"


# ---------------------------------------------------------------------------
# Forge output classification
# ---------------------------------------------------------------------------

FAIL_LINE = "[FAIL: assertion failed] test_something() (gas: 1)"
PASS_LINE = "[PASS] test_other() (gas: 1)"


@case
def test_compile_error_is_invalid():
    state, why = mc.classify_run(1, "Error: Compiler run failed\nsome detail", False)
    assert state == "COMPILE_FAIL", state
    assert "does not compile" in why


@case
def test_solar_parse_error_is_invalid():
    state, _ = mc.classify_run(1, "Error: solar run failed:\nexpected token", False)
    assert state == "COMPILE_FAIL", state


@case
def test_timeout_is_timeout_even_with_failures_in_partial_output():
    state, _ = mc.classify_run(124, FAIL_LINE, True)
    assert state == "TIMEOUT", state


@case
def test_no_test_executed_is_invalid():
    state, why = mc.classify_run(0, "Ran 0 test suites\n", False)
    assert state == "NO_TESTS", state
    assert "no test was executed" in why


@case
def test_nonzero_exit_without_fail_line_is_infrastructure_not_a_kill():
    out = f"{PASS_LINE}\nsomething exploded in the harness\n"
    state, why = mc.classify_run(137, out, False)
    assert state == "INFRA", state
    assert "without reporting any failing test" in why


@case
def test_nonzero_exit_with_fail_line_is_a_kill():
    state, _ = mc.classify_run(1, f"{PASS_LINE}\n{FAIL_LINE}\n", False)
    assert state == "FAILURES", state


@case
def test_green_run_is_green():
    state, _ = mc.classify_run(0, f"{PASS_LINE}\n", False)
    assert state == "GREEN", state


@case
def test_zero_exit_with_failures_is_treated_as_infrastructure_anomaly():
    state, _ = mc.classify_run(0, f"{PASS_LINE}\n{FAIL_LINE}\n", False)
    assert state == "INFRA", state


@case
def test_fail_detection_is_indentation_insensitive_and_deduplicated():
    out = f"    {FAIL_LINE}\n{FAIL_LINE}\n        {PASS_LINE}\n"
    fails = mc.failing_tests(out)
    assert fails == [FAIL_LINE], fails
    assert mc.passing_tests(out) == [PASS_LINE]
    state, _ = mc.classify_run(1, out, False)
    assert state == "FAILURES", state


# ---------------------------------------------------------------------------
# Verdict mapping across the two phases (targeted sub-suite -> full suite)
# ---------------------------------------------------------------------------


def verdict_for(targeted, full=None):
    """Drive the SHIPPED decision function, `mc.decide_verdict`.

    Deliberately not a re-implementation of main()'s logic: a test that
    re-derives the decision proves only that the copy agrees with itself, and
    would keep passing after the production path drifted. `calls` records
    whether the full suite was consulted at all, which is itself a property
    worth pinning (a mutant must never be declared SURVIVED without it).
    """
    calls = []

    def run_full_suite():
        calls.append(True)
        assert full is not None, "the full suite was run when it should not have been"
        return full

    d = mc.decide_verdict(targeted, run_full_suite)
    return d["verdict"], d["killed_by"], bool(calls)


@case
def test_green_targeted_then_green_full_suite_is_survived():
    assert verdict_for((0, PASS_LINE, False), (0, PASS_LINE, False)) == ("SURVIVED", None, True)


@case
def test_green_targeted_then_real_regression_in_full_suite_is_killed():
    v = verdict_for((0, PASS_LINE, False), (1, f"{PASS_LINE}\n{FAIL_LINE}", False))
    assert v == ("KILLED", "full_suite", True), v


@case
def test_failing_targeted_is_killed_by_targeted():
    v = verdict_for((1, f"{PASS_LINE}\n{FAIL_LINE}", False), None)
    # The full suite must NOT be consulted once the targeted sub-suite killed it.
    assert v == ("KILLED", "targeted", False), v


@case
def test_full_suite_infrastructure_failure_is_invalid_not_killed():
    v = verdict_for((0, PASS_LINE, False), (137, "harness crashed", False))
    assert v == ("INVALID", None, True), v


@case
def test_full_suite_timeout_is_timeout_not_survived():
    v = verdict_for((0, PASS_LINE, False), (124, "", True))
    assert v == ("TIMEOUT", None, True), v


# ---------------------------------------------------------------------------
# Mutation anchoring
# ---------------------------------------------------------------------------


@case
def test_anchor_must_occur_exactly_once():
    base = Path(tempfile.mkdtemp())
    try:
        ws, pristine = base / "ws", base / "pristine"
        (pristine / "src").mkdir(parents=True)
        (ws / "src").mkdir(parents=True)
        body = "line one\nUNIQUE_ANCHOR;\nDUP;\nDUP;\n"
        (pristine / "src" / "X.sol").write_text(body)
        (ws / "src" / "X.sol").write_text(body)

        ok, line, diff, why = mc.apply_mutant(
            ws, pristine, {"target": "src/X.sol", "match": "UNIQUE_ANCHOR;", "replace": "// MUT"}
        )
        assert ok and line == 2, (ok, line)
        assert "// MUT" in (ws / "src" / "X.sol").read_text()
        assert "-UNIQUE_ANCHOR;" in diff and "+// MUT" in diff, diff

        ok, _, _, why = mc.apply_mutant(
            ws, pristine, {"target": "src/X.sol", "match": "DUP;", "replace": "// MUT"}
        )
        assert not ok and "occurs 2 times" in why, why

        ok, _, _, why = mc.apply_mutant(
            ws, pristine, {"target": "src/X.sol", "match": "ABSENT", "replace": "x"}
        )
        assert not ok and "occurs 0 times" in why, why
    finally:
        shutil.rmtree(base)


@case
def test_restore_all_reverts_a_mutated_workspace_file():
    base = Path(tempfile.mkdtemp())
    try:
        ws, pristine = base / "ws", base / "pristine"
        (pristine / "src").mkdir(parents=True)
        (ws / "src").mkdir(parents=True)
        (pristine / "src" / "X.sol").write_text("original\n")
        (ws / "src" / "X.sol").write_text("MUTATED\n")
        mc.restore_all(ws, pristine)
        assert (ws / "src" / "X.sol").read_text() == "original\n"
    finally:
        shutil.rmtree(base)


@case
def test_apply_mutant_refuses_a_symlink_target():
    base = Path(tempfile.mkdtemp())
    try:
        ws, pristine = base / "ws", base / "pristine"
        outside = base / "outside.sol"
        outside.write_text("ANCHOR\n")
        (ws / "src").mkdir(parents=True)
        (pristine / "src").mkdir(parents=True)
        (ws / "src" / "X.sol").symlink_to(outside)
        (pristine / "src" / "X.sol").write_text("ANCHOR\n")
        ok, _, _, why = mc.apply_mutant(
            ws, pristine, {"target": "src/X.sol", "match": "ANCHOR", "replace": "MUT"}
        )
        assert not ok and "unsafe" in why, why
        assert outside.read_text() == "ANCHOR\n", "symlink target was mutated"
    finally:
        shutil.rmtree(base)


# ---------------------------------------------------------------------------
# Log archiving
# ---------------------------------------------------------------------------


@case
def test_archive_log_writes_the_raw_output_and_a_matching_sha256():
    base = Path(tempfile.mkdtemp())
    try:
        text = "raw forge output\nwith two lines\n"
        path, digest = mc.archive_log(base / "logs", "M1.targeted", text)
        assert Path(path).read_text() == text
        assert digest == mc.sha256_text(text)
        assert Path(path).name == "M1.targeted.log"
    finally:
        shutil.rmtree(base)


# ---------------------------------------------------------------------------
# Toolchain fingerprint and log fidelity
# ---------------------------------------------------------------------------


@case
def test_environment_fingerprint_records_the_toolchain():
    env = mc.collect_environment()
    for key in ("platform", "machine", "python", "foundry_profile"):
        assert env.get(key), f"missing environment key: {key}"
    # forge is expected in this repo's dev environment; if it is absent the
    # runner must still record the attempt rather than crash.
    assert "forge_version" in env
    assert "solc" in env or "forge_config_error" in env


@case
def test_combined_stream_preserves_chronological_order():
    # stdout and stderr captured separately and concatenated would yield
    # "one\nthree\ntwo\n"; a real combined stream keeps the emission order.
    rc, out, _, timed_out = mc.sh(
        ["sh", "-c", "echo one; echo two 1>&2; echo three"]
    )
    assert rc == 0 and not timed_out
    assert out.splitlines() == ["one", "two", "three"], out


@case
def test_archive_log_records_a_path_relative_to_the_campaign_directory():
    base = Path(tempfile.mkdtemp())
    try:
        text = "forge output\n"
        path, digest = mc.archive_log(base / "camp-logs", "M1.full", text, relative_to=base)
        # Relative, so the evidence bundle survives being moved or copied.
        assert path == "camp-logs/M1.full.log", path
        assert not Path(path).is_absolute()
        assert (base / path).read_text() == text
        assert digest == mc.sha256_text(text)
    finally:
        shutil.rmtree(base)


@case
def test_archive_log_falls_back_to_an_absolute_path_when_outside_the_campaign_dir():
    base = Path(tempfile.mkdtemp())
    other = Path(tempfile.mkdtemp())
    try:
        path, _ = mc.archive_log(other / "logs", "M1.full", "x", relative_to=base)
        assert Path(path).is_absolute(), path
    finally:
        shutil.rmtree(base)
        shutil.rmtree(other)


# ---------------------------------------------------------------------------
# Manifest sanity
# ---------------------------------------------------------------------------


@case
def test_manifest_has_no_catch_all_kill_filters():
    mutants = json.load(open(mc.MANIFEST))
    broad = [m["id"] for m in mutants if m["kill_tests"].strip() in (".", "", ".*")]
    assert not broad, f"catch-all kill filters left in the manifest: {broad}"


@case
def test_shipped_manifest_is_safe_and_complete():
    mutants = json.load(open(mc.MANIFEST))
    assert mc.validate_manifest(mutants) is None


@case
def test_manifest_refuses_traversal_absolute_and_duplicate_ids():
    mutants = json.load(open(mc.MANIFEST))
    traversing = [dict(m) for m in mutants]
    traversing[0]["target"] = "../outside.sol"
    reason = mc.validate_manifest(traversing)
    assert reason and "confined" in reason, reason

    absolute = [dict(m) for m in mutants]
    absolute[0]["target"] = str((mc.REPO / absolute[0]["target"]).resolve())
    reason = mc.validate_manifest(absolute)
    assert reason and "confined" in reason, reason

    duplicate = [dict(m) for m in mutants]
    duplicate[1]["id"] = duplicate[0]["id"]
    reason = mc.validate_manifest(duplicate)
    assert reason and "duplicate id" in reason, reason


@case
def test_manifest_refuses_unsafe_log_id_and_catch_all_filter():
    mutants = json.load(open(mc.MANIFEST))
    unsafe_id = [dict(m) for m in mutants]
    unsafe_id[0]["id"] = "../../escaped"
    reason = mc.validate_manifest(unsafe_id)
    assert reason and "unsafe id" in reason, reason

    broad = [dict(m) for m in mutants]
    broad[0]["kill_tests"] = ".*"
    reason = mc.validate_manifest(broad)
    assert reason and "non-catch-all" in reason, reason


@case
def test_selection_refuses_unknown_and_status_hidden_ids():
    mutants = json.load(open(mc.MANIFEST))
    selected, reason = mc.select_mutants(mutants, "ALL", "M1_initMaxSigners,TYPO")
    assert not selected and reason and "unknown" in reason, reason
    pending = dict(mutants[0])
    pending["id"] = "UNIT-PENDING"
    pending["status"] = "PENDING-FIX"
    selected, reason = mc.select_mutants(mutants + [pending], "ACTIVE", "UNIT-PENDING")
    assert not selected and reason and "excluded by --status" in reason, reason


@case
def test_inconclusive_campaign_has_nonzero_exit():
    assert mc.campaign_exit_code({"KILLED": 2, "SURVIVED": 1}) == 0
    assert mc.campaign_exit_code({"KILLED": 2, "INVALID": 1}) == mc.EXIT_INCONCLUSIVE
    assert mc.campaign_exit_code({"TIMEOUT": 1}) == mc.EXIT_INCONCLUSIVE


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
    if failed:
        print("failing:", ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
