#!/usr/bin/env bash
# Positive and negative controls for the commit staging-integrity guard.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
hook="$root/.githooks/commit-msg"
tmp=$(mktemp -d)
msg=$(mktemp)
trap 'rm -rf "$tmp" "$msg"' EXIT

git -C "$tmp" init -q
git -C "$tmp" config user.name 'Chris Watkins'
git -C "$tmp" config user.email 'chris@watkinslabs.com'
printf 'base\n' >"$tmp/tracked"
git -C "$tmp" add tracked
git -C "$tmp" -c core.hooksPath="$root/.githooks" commit -qm baseline
printf 'test\n' >"$msg"

# A complete index is accepted.
printf 'changed\n' >"$tmp/tracked"
git -C "$tmp" add tracked
(
  cd "$tmp"
  "$hook" "$msg"
)
git -C "$tmp" -c core.hooksPath="$root/.githooks" commit --dry-run -F "$msg" >/dev/null

# A valid staged edit plus a remaining tracked edit is rejected.
printf 'staged\n' >"$tmp/tracked"
git -C "$tmp" add tracked
printf 'unstaged\n' >>"$tmp/tracked"
if (cd "$tmp" && "$hook" "$msg") >/dev/null 2>&1; then
  echo 'expected partial staging to be rejected' >&2
  exit 1
fi
git -C "$tmp" restore --staged tracked
git -C "$tmp" restore tracked

# An untracked file is also rejected, even when the tracked index is clean.
printf 'orphan\n' >"$tmp/orphan"
if (cd "$tmp" && "$hook" "$msg") >/dev/null 2>&1; then
  echo 'expected untracked file to be rejected' >&2
  exit 1
fi

echo 'commit-staging-guard: PASS'
