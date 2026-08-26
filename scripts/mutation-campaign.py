#!/usr/bin/env python3
"""Deterministic mutation-campaign runner for the pre-tag freeze.

Why this exists next to `scripts/mutation-gambit.sh`: Gambit only generates
syntactic mutants from the AST, so it cannot express the two mutation families
this campaign needs - a STATEMENT ORDER swap (surface B) and the removal of ONE
named enforcement check (surface C). It also kills mutants by editing the target
file in the main worktree and restoring it afterwards, which this campaign
forbids: a crash mid-run would leave a mutated `src/` behind.

Evidence properties this runner enforces, in the order they matter for an audit:

  PROVENANCE   The recorded SHA must describe exactly the bytes that were
               tested. The run is refused unless the worktree is clean
               (including untracked files) and every recursive submodule is
               initialised and clean. `baseline_dirty` is always false; there is
               deliberately no flag to override this.
  ISOLATION    Mutations only ever happen inside an explicit, disjoint,
               throwaway workspace. The runner NEVER deletes a directory it did
               not create: a non-empty `--workspace` is refused, not cleaned.
               An existing `--out` is refused rather than overwritten.
  STRICTNESS   A mutant is KILLED only when Forge actually reports a failing
               test. A non-zero exit with no `[FAIL]` line is an infrastructure
               incident (INVALID), never a kill. Non-compiling is INVALID, a
               timeout is TIMEOUT, and SURVIVED requires a green FULL suite.
  TRACEABILITY Every Forge invocation is archived verbatim next to `--out`,
               with its SHA-256 recorded in the JSONL row. Rows are flushed as
               soon as each verdict is known.

Usage:
    scripts/mutation-campaign.py \\
        --workspace "$(mktemp -d)" \\
        --out /path/outside/the/workspace/campaign.jsonl \\
        [--only M1_initMaxSigners,T5_inlineBypasserDelegate] \\
        [--status ACTIVE|PENDING-FIX|ALL] [--timeout 900]
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from difflib import unified_diff
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.resolve()
MANIFEST = REPO / "mutation" / "mutants.json"

EXIT_USAGE = 1
EXIT_RED_BASELINE = 2
EXIT_PROVENANCE = 3
EXIT_INCONCLUSIVE = 4

REQUIRED_MUTANT_FIELDS = {
    "id",
    "target",
    "invariant",
    "kill_tests",
    "match",
    "replace",
    "status",
    "historical_result",
    "family",
    "note",
}


def sh(cmd, cwd=None, timeout=None):
    """Run a command, returning (returncode, combined_output, seconds, timed_out).

    stderr is redirected INTO stdout at spawn time rather than captured
    separately and concatenated afterwards: an archived log has to preserve the
    chronological interleaving a human would have seen on a terminal, otherwise
    "verbatim" is a lie and a compiler error appears detached from the test line
    that provoked it.
    """
    start = time.monotonic()
    try:
        p = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout
        )
        return p.returncode, p.stdout or "", time.monotonic() - start, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        return 124, out, time.monotonic() - start, True


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def collect_environment(repo=REPO):
    """Toolchain fingerprint.

    A SHA pins the sources but not the compiler: the same mutant can be killed
    under one solc/evm target and survive under another, so a campaign that
    records only the SHA is not reproducible. Everything below is recorded
    verbatim rather than parsed into a verdict.
    """
    env = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "foundry_profile": os.environ.get("FOUNDRY_PROFILE", "default"),
    }
    rc, forge_v, _, _ = sh(["forge", "--version"], cwd=repo)
    env["forge_version"] = forge_v.strip() if rc == 0 else None

    # `forge config` resolves the profile actually in force, which is what the
    # mutant builds will use - not merely what foundry.toml's default section says.
    rc, cfg, _, _ = sh(["forge", "config", "--json"], cwd=repo)
    if rc == 0:
        try:
            parsed = json.loads(cfg)
            env["solc"] = parsed.get("solc") or parsed.get("solc_version")
            env["evm_version"] = parsed.get("evm_version")
            env["optimizer"] = parsed.get("optimizer")
            env["optimizer_runs"] = parsed.get("optimizer_runs")
            env["via_ir"] = parsed.get("via_ir")
        except json.JSONDecodeError:
            env["forge_config_error"] = "forge config --json did not return JSON"
    else:
        env["forge_config_error"] = "forge config --json failed"
    return env


def collect_provenance(repo=REPO):
    """Return (provenance_dict, refusal_reason_or_None).

    A campaign must never record a clean SHA while copying local edits, so a
    dirty worktree or a dirty/uninitialised submodule is a hard refusal rather
    than a warning.
    """
    rc, head, _, _ = sh(["git", "rev-parse", "HEAD"], cwd=repo)
    if rc != 0:
        return {}, "cannot resolve HEAD (not a git repository?)"
    rc, tree, _, _ = sh(["git", "rev-parse", "HEAD^{tree}"], cwd=repo)
    if rc != 0:
        return {}, "cannot resolve HEAD^{tree}"

    prov = {"baseline_sha": head.strip(), "baseline_tree": tree.strip(), "baseline_dirty": False}
    prov["environment"] = collect_environment(repo)

    rc, porcelain, _, _ = sh(
        ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"], cwd=repo
    )
    if rc != 0:
        return prov, "cannot read git status"
    if porcelain.strip():
        prov["baseline_dirty"] = True
        listed = "\n".join(porcelain.strip().splitlines()[:20])
        return prov, f"worktree is dirty (including untracked files):\n{listed}"

    # `git submodule status` reports the checked-out gitlink, so it catches a
    # wrong SHA but NOT arbitrary edits inside a submodule, and the top-level
    # `git status` hides them whenever `diff.ignoreSubmodules` /
    # `submodule.<n>.ignore` is set locally. Both are therefore checked
    # explicitly: `--ignore-submodules=none` overrides any local configuration,
    # and a real `git status` is run inside each submodule.
    rc, subs, _, _ = sh(["git", "submodule", "status", "--recursive"], cwd=repo)
    if rc != 0:
        return prov, "cannot read submodule status"
    submodules, unclean = {}, []
    for line in subs.splitlines():
        if not line.strip():
            continue
        marker, rest = line[0], line[1:].strip()
        parts = rest.split()
        if len(parts) < 2:
            continue
        sha, path = parts[0], parts[1]
        submodules[path] = sha
        if marker == "-":
            unclean.append(f"{path}: not initialised")
        elif marker == "+":
            unclean.append(f"{path}: checked out at {sha}, not the recorded gitlink")
        elif marker == "U":
            unclean.append(f"{path}: merge conflict")
    prov["submodules"] = submodules
    if unclean:
        return prov, "submodules are not reproducible:\n" + "\n".join(unclean)

    # Per-submodule working-tree cleanliness, independent of local git config.
    rc, dirty_subs, _, _ = sh(
        [
            "git",
            "submodule",
            "foreach",
            "--recursive",
            "--quiet",
            'test -z "$(git status --porcelain --untracked-files=all)" '
            '|| echo "DIRTY $displaypath"',
        ],
        cwd=repo,
    )
    if rc != 0:
        return prov, "cannot inspect submodule working trees"
    dirty_list = [l.strip() for l in dirty_subs.splitlines() if l.strip().startswith("DIRTY ")]
    if dirty_list:
        return prov, "submodule working trees are dirty:\n" + "\n".join(dirty_list)

    return prov, None


# ---------------------------------------------------------------------------
# Workspace safety
# ---------------------------------------------------------------------------


def check_workspace_path(ws, repo=REPO):
    """Return a refusal reason, or None when `ws` is an admissible workspace.

    Purely a path/emptiness predicate: it NEVER creates, moves or deletes
    anything, so it is safe to unit-test against sentinel directories.
    """
    ws = Path(ws).expanduser()
    repo = Path(repo).resolve()
    # `resolve()` on a non-existent path still normalises it, which is what the
    # containment checks below need.
    ws_abs = ws.resolve()

    if ws_abs == repo:
        return "the workspace must not be the repository worktree"
    if repo in ws_abs.parents:
        return f"the workspace must not live inside the repository ({ws_abs} is under {repo})"
    if ws_abs in repo.parents:
        return f"the workspace must not contain the repository ({repo} is under {ws_abs})"

    if ws_abs.exists():
        if not ws_abs.is_dir():
            return f"the workspace path exists and is not a directory: {ws_abs}"
        entries = list(ws_abs.iterdir())
        if entries:
            # Deliberately a refusal and not a cleanup: this runner never
            # deletes a directory it did not create.
            sample = ", ".join(sorted(e.name for e in entries)[:5])
            return (
                f"the workspace must be empty; {ws_abs} contains {len(entries)} entr"
                f"{'y' if len(entries) == 1 else 'ies'} ({sample}). "
                "Pass a fresh `mktemp -d` path; this runner never deletes an existing directory."
            )
    return None


def check_out_path(out, ws, repo=REPO):
    """Validate --out: new, outside the workspace, and outside the repository.

    The repository clause is not cosmetic. The runner refuses to start on a
    dirty worktree; writing results (and a whole log directory) under REPO
    would make the runner dirty the very tree whose cleanliness it just
    certified, so the next campaign would refuse to start because of the
    previous one's evidence.
    """
    out_abs = Path(out).expanduser().resolve()
    ws_abs = Path(ws).expanduser().resolve()
    repo_abs = Path(repo).resolve()
    if out_abs.exists():
        return f"--out already exists, refusing to overwrite a previous campaign: {out_abs}"
    if out_abs == ws_abs or ws_abs in out_abs.parents:
        return (
            f"--out must live outside the workspace so the evidence survives its cleanup: {out_abs}"
        )
    if out_abs == repo_abs or repo_abs in out_abs.parents:
        return (
            f"--out must live outside the repository, otherwise the campaign dirties the "
            f"clean worktree it just certified: {out_abs} is under {repo_abs}"
        )
    if not out_abs.parent.is_dir():
        return f"the --out parent directory does not exist: {out_abs.parent}"
    return None


def check_logdir_path(logdir, ws, repo=REPO):
    """Validate that the derived log directory is disjoint from mutable trees."""
    log_abs = Path(logdir).expanduser().resolve()
    ws_abs = Path(ws).expanduser().resolve()
    repo_abs = Path(repo).resolve()
    if log_abs == ws_abs or ws_abs in log_abs.parents or log_abs in ws_abs.parents:
        return f"the log directory and workspace must be disjoint: {log_abs} vs {ws_abs}"
    if log_abs == repo_abs or repo_abs in log_abs.parents:
        return f"the log directory must live outside the repository: {log_abs}"
    return None


def _confined_regular_file(root, relative):
    """Return a confined regular path, or None for traversal/absolute/symlink paths."""
    rel = Path(relative)
    root = Path(root).resolve()
    if rel.is_absolute() or ".." in rel.parts:
        return None
    candidate = root / rel
    if candidate.is_symlink():
        return None
    resolved = candidate.resolve()
    if resolved == root or root not in resolved.parents or not resolved.is_file():
        return None
    return resolved


def validate_manifest(mutants, repo=REPO):
    """Return a refusal reason unless every manifest row is safe and complete."""
    if not isinstance(mutants, list):
        return "manifest root must be a JSON array"
    seen = set()
    for index, mutant in enumerate(mutants):
        if not isinstance(mutant, dict):
            return f"manifest row {index} is not an object"
        missing = sorted(REQUIRED_MUTANT_FIELDS - mutant.keys())
        if missing:
            return f"manifest row {index} is missing fields: {', '.join(missing)}"
        mutant_id = mutant["id"]
        if not isinstance(mutant_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", mutant_id):
            return f"manifest row {index} has an unsafe id: {mutant_id!r}"
        if mutant_id in seen:
            return f"manifest contains duplicate id: {mutant_id}"
        seen.add(mutant_id)
        if mutant["status"] not in ("ACTIVE", "PENDING-FIX"):
            return f"{mutant_id}: unsupported status {mutant['status']!r}"
        if not isinstance(mutant["match"], str) or not mutant["match"]:
            return f"{mutant_id}: match must be a non-empty string"
        if not isinstance(mutant["replace"], str):
            return f"{mutant_id}: replace must be a string"
        kill_filter = mutant["kill_tests"]
        if not isinstance(kill_filter, str) or not kill_filter.strip() or kill_filter.strip() in (".", ".*"):
            return f"{mutant_id}: kill_tests must be a non-catch-all regex"
        if not isinstance(mutant["target"], str) or _confined_regular_file(repo, mutant["target"]) is None:
            return f"{mutant_id}: target is not a regular file confined to the repository: {mutant['target']!r}"
    return None


def select_mutants(mutants, status, only):
    """Select rows without silently accepting misspelled or status-hidden ids."""
    by_id = {m["id"]: m for m in mutants}
    wanted = [item.strip() for item in only.split(",") if item.strip()] if only else []
    unknown = sorted(set(wanted) - by_id.keys())
    if unknown:
        return [], f"unknown mutant id(s): {', '.join(unknown)}"
    selected = mutants if status == "ALL" else [m for m in mutants if m["status"] == status]
    if wanted:
        visible = {m["id"] for m in selected}
        hidden = sorted(set(wanted) - visible)
        if hidden:
            return [], (
                f"selected mutant id(s) excluded by --status {status}: {', '.join(hidden)}; "
                "use --status ALL or the matching status"
            )
        wanted_set = set(wanted)
        selected = [m for m in selected if m["id"] in wanted_set]
    if not selected:
        return [], "no mutant selected"
    return selected, None


def populate_workspace(ws: Path, targets, repo=REPO):
    """Copy tracked bytes only, then snapshot the mutable sources.

    `git status --untracked-files=all` deliberately does not report ignored
    files. Copying the worktree wholesale would therefore import local build
    output, editor state and potentially ignored credentials into a throwaway
    workspace while still claiming that the recorded SHA describes every byte
    tested. `git ls-files --recurse-submodules` is the allowlist: it includes
    every tracked submodule file needed by Forge and excludes every untracked or
    ignored path without reading it.

    Returns (pristine_dir, error_or_None). The copied source worktree was already
    verified clean, so each selected tracked file has the bytes recorded by the
    superproject SHA and its pinned recursive gitlinks.
    """
    repo = Path(repo).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--recurse-submodules", "-z"],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if listed.returncode != 0:
        return None, f"cannot enumerate tracked workspace files:\n{listed.stdout.decode(errors='replace')}"

    for raw in listed.stdout.split(b"\0"):
        if not raw:
            continue
        rel = Path(os.fsdecode(raw))
        if rel.is_absolute() or ".." in rel.parts:
            return None, f"git returned an unsafe tracked path: {rel}"
        src = repo / rel
        if not src.is_file() and not src.is_symlink():
            return None, f"tracked workspace file is missing: {rel}"
        dst = ws / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst, follow_symlinks=False)

    pristine = ws / ".pristine"
    for rel in sorted(targets):
        src = _confined_regular_file(ws, rel)
        if src is None:
            return None, f"manifest target is missing, unsafe, or escapes the copied workspace: {rel}"
        dst = pristine / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return pristine, None


def restore_all(ws: Path, pristine: Path):
    for src in pristine.rglob("*"):
        if src.is_file():
            shutil.copy2(src, ws / src.relative_to(pristine))


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------


def apply_mutant(ws: Path, pristine: Path, mutant):
    """Returns (ok, logical_line, unified_diff, reason)."""
    rel = mutant["target"]
    source = _confined_regular_file(pristine, rel)
    target = _confined_regular_file(ws, rel)
    if source is None or target is None:
        return False, None, "", "target is missing, unsafe, or escapes the workspace"
    original = source.read_text()
    match, replace = mutant["match"], mutant["replace"]
    count = original.count(match)
    if count != 1:
        return False, None, "", f"anchor occurs {count} times (expected exactly 1)"
    line = original[: original.index(match)].count("\n") + 1
    mutated = original.replace(match, replace)
    target.write_text(mutated)
    diff = "".join(
        unified_diff(
            original.splitlines(keepends=True),
            mutated.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
            n=1,
        )
    )
    return True, line, diff, ""


# ---------------------------------------------------------------------------
# Forge output classification
# ---------------------------------------------------------------------------

COMPILE_MARKERS = ("Compiler run failed", "compilation failed", "Error: solar run failed")


def is_compile_failure(out):
    return any(m in out for m in COMPILE_MARKERS)


def failing_tests(out):
    """Real `[FAIL...]` test lines, de-duplicated, indentation-insensitive."""
    seen, ordered = set(), []
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("[FAIL") and line not in seen:
            seen.add(line)
            ordered.append(line)
    return ordered


def passing_tests(out):
    return [l.strip() for l in out.splitlines() if l.strip().startswith("[PASS")]


def classify_run(rc, out, timed_out):
    """Classify ONE forge invocation.

    Returns (state, reason) where state is one of:
      TIMEOUT | COMPILE_FAIL | NO_TESTS | FAILURES | GREEN | INFRA
    The caller maps these onto mutant verdicts. `INFRA` is the important one: a
    non-zero exit with no identified failing test is a runner/Forge incident and
    must never be credited to the mutant as a kill.
    """
    if timed_out:
        return "TIMEOUT", "forge exceeded the timeout"
    if is_compile_failure(out):
        return "COMPILE_FAIL", "mutant does not compile"
    fails = failing_tests(out)
    passes = passing_tests(out)
    if not fails and not passes:
        return "NO_TESTS", "no test was executed (kill filter matched nothing?)"
    if rc != 0:
        if fails:
            return "FAILURES", ""
        return "INFRA", f"forge exited {rc} without reporting any failing test"
    if fails:
        # Defensive: forge reporting failures with a zero exit would itself be
        # an anomaly, so treat it as one rather than silently calling it green.
        return "INFRA", "forge exited 0 while reporting failing tests"
    return "GREEN", ""


def decide_verdict(targeted, run_full_suite):
    """Map one mutant's Forge runs onto a verdict. THE decision, used by main().

    `targeted` is the `(returncode, output, timed_out)` triple of the targeted
    sub-suite. `run_full_suite` is a zero-argument callable returning the same
    triple for the full suite; it is invoked ONLY when the targeted sub-suite
    came back green, so a mutant is never declared SURVIVED on its own tests.

    Returns a dict: `verdict`, `killed_by`, `invalid_reason`, and `full` (the
    full-suite triple, or None when the full suite was not needed). Kept out of
    main() so the tests exercise the shipped decision rather than a re-implementation
    of it.
    """
    state, why = classify_run(*targeted)
    if state == "TIMEOUT":
        return {"verdict": "TIMEOUT", "killed_by": None, "invalid_reason": why, "full": None}
    if state in ("COMPILE_FAIL", "NO_TESTS", "INFRA"):
        return {"verdict": "INVALID", "killed_by": None, "invalid_reason": why, "full": None}
    if state == "FAILURES":
        return {"verdict": "KILLED", "killed_by": "targeted", "invalid_reason": None, "full": None}

    full = run_full_suite()
    state2, why2 = classify_run(*full)
    if state2 == "TIMEOUT":
        return {"verdict": "TIMEOUT", "killed_by": None, "invalid_reason": why2, "full": full}
    if state2 in ("COMPILE_FAIL", "NO_TESTS", "INFRA"):
        return {"verdict": "INVALID", "killed_by": None, "invalid_reason": why2, "full": full}
    if state2 == "FAILURES":
        return {"verdict": "KILLED", "killed_by": "full_suite", "invalid_reason": None, "full": full}
    return {"verdict": "SURVIVED", "killed_by": None, "invalid_reason": None, "full": full}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def archive_log(logdir: Path, name, text, relative_to=None):
    """Write a raw forge log; return (path, sha256).

    The recorded path is relative to the campaign directory (`relative_to`, i.e.
    the parent of --out) so the evidence bundle stays self-describing when it is
    moved or archived elsewhere. An absolute path would silently rot the moment
    the folder is copied to another machine. The SHA-256 is what actually binds
    the row to the bytes.
    """
    logdir.mkdir(parents=True, exist_ok=True)
    path = logdir / f"{name}.log"
    path.write_text(text)
    if relative_to is not None:
        try:
            return str(path.relative_to(Path(relative_to))), sha256_text(text)
        except ValueError:
            pass
    return str(path), sha256_text(text)


def campaign_exit_code(tally):
    """An archived campaign is successful only when every row is conclusive."""
    return EXIT_INCONCLUSIVE if tally.get("INVALID", 0) or tally.get("TIMEOUT", 0) else 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Run the pre-tag mutation campaign in a disposable, disjoint workspace."
    )
    ap.add_argument(
        "--workspace",
        required=True,
        help="Path to a NEW or strictly EMPTY directory (e.g. `mktemp -d`), outside the repo. "
        "Never deleted or cleaned by this runner.",
    )
    ap.add_argument("--out", required=True, help="JSONL results path; must not already exist, and must be outside the workspace.")
    ap.add_argument("--only", default="", help="Comma-separated mutant ids.")
    ap.add_argument("--status", default="ACTIVE", choices=["ACTIVE", "PENDING-FIX", "ALL"])
    ap.add_argument("--timeout", type=int, default=900, help="Per targeted sub-suite, in seconds. The full suite gets 4x.")
    args = ap.parse_args(argv)

    # 1. Provenance first: never copy anything from an unreproducible source.
    prov, refusal = collect_provenance()
    if refusal:
        print(f"REFUSING to run: {refusal}", file=sys.stderr)
        return EXIT_PROVENANCE

    # 2. Path safety, before any write.
    reason = check_workspace_path(args.workspace)
    if reason:
        print(f"REFUSING to run: {reason}", file=sys.stderr)
        return EXIT_USAGE
    reason = check_out_path(args.out, args.workspace)
    if reason:
        print(f"REFUSING to run: {reason}", file=sys.stderr)
        return EXIT_USAGE

    with open(MANIFEST) as manifest_file:
        all_mutants = json.load(manifest_file)
    reason = validate_manifest(all_mutants)
    if reason:
        print(f"REFUSING to run: invalid manifest: {reason}", file=sys.stderr)
        return EXIT_USAGE
    mutants, reason = select_mutants(all_mutants, args.status, args.only)
    if reason:
        print(f"REFUSING to run: {reason}", file=sys.stderr)
        return EXIT_USAGE
    all_targets = {m["target"] for m in all_mutants}

    ws = Path(args.workspace).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    campaign_dir = out_path.parent
    logdir = campaign_dir / f"{out_path.stem}-logs"
    reason = check_logdir_path(logdir, ws)
    if reason:
        print(f"REFUSING to run: {reason}", file=sys.stderr)
        return EXIT_USAGE
    if logdir.exists() and any(logdir.iterdir()):
        print(f"REFUSING to run: log directory already exists and is not empty: {logdir}", file=sys.stderr)
        return EXIT_USAGE

    pristine, err = populate_workspace(ws, all_targets)
    if err:
        print(f"REFUSING to run: {err}", file=sys.stderr)
        return EXIT_USAGE

    print(f"baseline {prov['baseline_sha']} (tree {prov['baseline_tree']})", flush=True)
    print(f"workspace {ws}", flush=True)
    print("verifying the workspace suite is green ...", flush=True)

    rc, out, dur, timed_out = sh(["forge", "test"], cwd=ws, timeout=args.timeout * 4)
    state, _ = classify_run(rc, out, timed_out)
    log_path, log_sha = archive_log(logdir, "baseline", out, relative_to=campaign_dir)
    print(f"  baseline suite: {state} ({dur:.0f}s) -> {log_path}", flush=True)
    if state != "GREEN":
        print("  REFUSING to classify mutants against a baseline that is not green.", flush=True)
        for line in failing_tests(out)[:10]:
            print(f"    {line}", flush=True)
        return EXIT_RED_BASELINE

    results = []
    try:
        with open(out_path, "w") as fh:
            for m in mutants:
                restore_all(ws, pristine)
                rec = dict(prov)
                rec.update(
                    id=m["id"],
                    family=m["family"],
                    status=m["status"],
                    target=m["target"],
                    invariant=m["invariant"],
                    kill_tests=m["kill_tests"],
                    historical_result=m["historical_result"],
                    note=m["note"],
                    timeout_s=args.timeout,
                    baseline_log=log_path,
                    baseline_log_sha256=log_sha,
                )
                ok, line, diff, why = apply_mutant(ws, pristine, m)
                rec["logical_line"] = line
                rec["patch"] = diff
                if not ok:
                    rec.update(
                        verdict="INVALID",
                        invalid_reason=f"anchor: {why}",
                        killed_by=None,
                        command=None,
                        exit_code=None,
                        duration_s=0.0,
                        failing_tests=[],
                    )
                    print(f"{m['id']:32s} INVALID   ({why})", flush=True)
                    fh.write(json.dumps(rec) + "\n")
                    fh.flush()
                    results.append(rec)
                    continue

                cmd = ["forge", "test", "--match-test", m["kill_tests"]]
                rc, out, dur, timed_out = sh(cmd, cwd=ws, timeout=args.timeout)
                tlog, tsha = archive_log(logdir, f"{m['id']}.targeted", out, relative_to=campaign_dir)
                rec.update(
                    command=" ".join(cmd),
                    exit_code=rc,
                    duration_s=round(dur, 1),
                    failing_tests=failing_tests(out),
                    targeted_log=tlog,
                    targeted_log_sha256=tsha,
                    killed_by=None,
                )

                # The full suite is run only if the targeted one came back green.
                full_cmd = ["forge", "test"]
                full_timing = {}

                def run_full_suite():
                    rc2, out2, dur2, to2 = sh(full_cmd, cwd=ws, timeout=args.timeout * 4)
                    full_timing["duration"] = dur2
                    full_timing["output"] = out2
                    return rc2, out2, to2

                decision = decide_verdict((rc, out, timed_out), run_full_suite)
                rec["verdict"] = decision["verdict"]
                rec["killed_by"] = decision["killed_by"]
                if decision["invalid_reason"]:
                    rec["invalid_reason"] = decision["invalid_reason"]
                if decision["full"] is not None:
                    rc2, out2, _ = decision["full"]
                    flog, fsha = archive_log(
                        logdir, f"{m['id']}.full", out2, relative_to=campaign_dir
                    )
                    rec.update(
                        full_suite_command=" ".join(full_cmd),
                        full_suite_exit_code=rc2,
                        full_suite_duration_s=round(full_timing.get("duration", 0.0), 1),
                        full_suite_failing_tests=failing_tests(out2),
                        full_suite_log=flog,
                        full_suite_log_sha256=fsha,
                    )

                shown = rec["failing_tests"][:1] or rec.get("full_suite_failing_tests", [])[:1]
                print(f"{m['id']:32s} {rec['verdict']:9s} ({rec['duration_s']}s) {shown}", flush=True)
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                results.append(rec)
    finally:
        # Always leave the workspace unmutated, even on an exception. The main
        # worktree is never touched by any path in this runner.
        restore_all(ws, pristine)

    # Recount from the rows actually written, never from a running tally.
    rows = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\nRECOUNT FROM RESULT ROWS:", json.dumps(tally, sort_keys=True))
    print(f"total rows: {len(rows)}  (results: {out_path}, logs: {logdir})")
    exit_code = campaign_exit_code(tally)
    if exit_code:
        print("campaign is inconclusive: INVALID/TIMEOUT rows require operator action", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
