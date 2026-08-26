#!/usr/bin/env bash
set -euo pipefail

ROOT_UNDER_TEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_PUBLIC_LIB_ONLY=1 source "$ROOT_UNDER_TEST/scripts/publish-public.sh"

passed=0
check() {
    "$@"
    passed=$((passed + 1))
}

test_canonical_github_urls() {
    [ "$(github_slug_of git@github.com:Runtime-Capital/safe-lockdown.git)" = "Runtime-Capital/safe-lockdown" ]
    [ "$(github_slug_of ssh://git@github.com/Runtime-Capital/safe-lockdown.git)" = "Runtime-Capital/safe-lockdown" ]
    [ "$(github_slug_of https://github.com/Runtime-Capital/safe-lockdown)" = "Runtime-Capital/safe-lockdown" ]
}

test_lookalike_hosts_and_credentials_are_rejected() {
    ! github_slug_of git@attacker.example:Runtime-Capital/safe-lockdown.git >/dev/null
    ! github_slug_of https://github.com.attacker.example/Runtime-Capital/safe-lockdown.git >/dev/null
    ! github_slug_of https://token@github.com/Runtime-Capital/safe-lockdown.git >/dev/null
    ! github_slug_of http://github.com/Runtime-Capital/safe-lockdown.git >/dev/null
}

test_alignment_check_does_not_change_git_metadata() {
    local base remote repo before after
    base="$(mktemp -d)"
    remote="$base/remote.git"
    repo="$base/repo"
    git init -q --bare "$remote"
    git init -q -b main "$repo"
    git -C "$repo" config user.email test@example.com
    git -C "$repo" config user.name test
    printf 'tracked\n' > "$repo/tracked.txt"
    git -C "$repo" add tracked.txt
    git -C "$repo" -c commit.gpgsign=false commit -qm initial
    git -C "$repo" remote add origin "$remote"
    git -C "$repo" push -q -u origin main

    before="$(cd "$repo" && find .git -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)"
    assert_branch_clean_and_aligned "$repo" main synthetic >/dev/null
    after="$(cd "$repo" && find .git -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)"
    [ "$before" = "$after" ]
    rm -rf "${base:?}"
}

check test_canonical_github_urls
check test_lookalike_hosts_and_credentials_are_rejected
check test_alignment_check_does_not_change_git_metadata

printf '%s passed, 0 failed\n' "$passed"
