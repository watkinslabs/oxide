#!/usr/bin/env bash
# Derive the next branch counter for a type from git itself, so the number can
# never be stale relative to history. `metadata/index.md` stays authoritative
# for RESERVATIONS (numbers claimed by a live lane that has not merged yet);
# git is authoritative for what has already been USED. The answer is the max of
# both, which is correct whichever one is behind.
#
#   tools/next-branch.sh B                  -> next B number (READ ONLY)
#   tools/next-branch.sh B my-fix-title     -> full branch name (READ ONLY)
#   tools/next-branch.sh --claim B my-title -> CLAIM the number, then print it
#   tools/next-branch.sh --dry-run --claim B my-title -> show, claim nothing
#   tools/next-branch.sh --check            -> non-zero if index.md is behind git
#   tools/next-branch.sh --check B          -> same, one type
#
# Types: F B D R Z C, plus phase branches P<n>.
#
# READING THE COUNTER IS NOT CLAIMING IT. Every concurrent lane that reads gets
# the SAME answer, and the number is only really taken once something reaches
# the remote — so three lanes drew B1667 on one day and an entire
# implementation was discarded as the duplicate.
#
# `--claim` closes that window: it pushes a ref under `refs/claims/` to origin BEFORE
# returning the name. The ref carries a commit unique to this lane, so two lanes
# racing for one number push DIFFERENT values to the SAME ref and the remote
# rejects the loser — the atomicity is the remote's, not a check-then-act here.
# The loser retries with the next number. Claim refs are never deleted: they are
# the record of which numbers have been handed out, and `git_max` counts them.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
index="$root/metadata/index.md"

TYPES="F B D R Z C"

# Highest counter of TYPE observed anywhere in git: local branches, remote
# branches, and merge-commit subjects (the only surviving trace of a branch
# deleted on merge).
git_max() {
  local t=$1
  {
    git for-each-ref --format='%(refname:short)' refs/heads refs/remotes refs/claims
    git log --all --format='%s'
  } | grep -oE "(^|[^A-Za-z0-9])${t}[0-9]{2,4}(-|$)" \
    | grep -oE "${t}[0-9]{2,4}" \
    | sed "s/^${t}//" \
    | sort -n | tail -1
}

# Refresh the claim namespace from origin, so `next_for` sees numbers other
# lanes have taken but not yet built anything on. Failure is not fatal: a lane
# with no network still gets the git-and-index answer it always got.
fetch_claims() {
  git fetch -q origin '+refs/claims/*:refs/claims/*' 2>/dev/null || true
}

# Take NUMBER for TYPE by creating `refs/claims/<TYPE><nn>` on the remote. NOT
# under refs/heads — a claim is not a branch and must never appear in the branch
# list. Remote ref creation is atomic in any namespace, so this loses nothing.
# The pushed
# commit is empty and unique to this invocation, so a second lane pushing to the
# same ref is a non-fast-forward and is refused. Returns non-zero if the number
# is already taken.
claim_number() {
  local name=$1 base tree sha
  base=$(git rev-parse origin/main 2>/dev/null || git rev-parse HEAD)
  tree=$(git rev-parse "${base}^{tree}")
  sha=$(git commit-tree "$tree" -p "$base" \
        -m "claim ${name} by $(hostname)/$$ at $(date -u +%Y-%m-%dT%H:%M:%SZ)")
  git push -q origin "${sha}:refs/claims/${name}" 2>/dev/null
}

# The `next` value recorded in the index table for TYPE.
index_next() {
  local t=$1
  awk -v t="$t" -F'|' '
    $2 ~ "^[[:space:]]*"t"[[:space:]]*$" { gsub(/[^0-9]/, "", $3); if ($3 != "") { print $3; exit } }
  ' "$index"
}

next_for() {
  local t=$1
  local g i n
  g=$(git_max "$t"); g=${g:-0}
  i=$(index_next "$t"); i=${i:-0}
  n=$(( g + 1 ))
  if [ "$i" -gt "$n" ]; then n=$i; fi
  printf '%d' "$n"
}

pad() {
  local n=$1
  if [ "$n" -lt 100 ]; then printf '%02d' "$n"; else printf '%d' "$n"; fi
}

if [ "${1:-}" = "--check" ]; then
  shift
  types=${*:-$TYPES}
  rc=0
  for t in $types; do
    g=$(git_max "$t"); g=${g:-0}
    i=$(index_next "$t"); i=${i:-0}
    if [ "$i" -le "$g" ]; then
      echo "STALE: metadata/index.md says ${t} next=${i}, but ${t}${g} already exists in git" >&2
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] && echo "metadata/index.md counters are ahead of git for: $types"
  exit "$rc"
fi

claim=0
dry=0
while true; do
  case "${1:-}" in
    --claim)   claim=1; shift ;;
    --dry-run) dry=1;   shift ;;
    *) break ;;
  esac
done

type=${1:-}
if [ -z "$type" ]; then
  echo "usage: $0 [--claim] [--dry-run] <TYPE> [kebab-title] | --check [TYPE...]" >&2
  exit 2
fi
title=${2:-}

full() {
  if [ -z "$title" ]; then printf '%s%s' "$type" "$1"; else printf '%s%s-%s' "$type" "$1" "$title"; fi
}

# Read-only: the historical behaviour, and what `--dry-run` reports. Says
# nothing about whether another lane is about to take the same number.
if [ "$claim" -eq 0 ] || [ "$dry" -eq 1 ]; then
  n=$(pad "$(next_for "$type")")
  full "$n"; echo
  if [ "$dry" -eq 1 ]; then
    echo "next-branch: --dry-run — nothing claimed, this number is NOT yours" >&2
  fi
  exit 0
fi

# Claiming: re-derive the number against the freshly fetched claim namespace on
# every attempt, so a lane that loses a race does not retry the same number.
ATTEMPTS=25
fetch_claims
a=1
while [ "$a" -le "$ATTEMPTS" ]; do
  n=$(pad "$(next_for "$type")")
  name=$(full "$n")
  if claim_number "${type}${n}"; then
    echo "next-branch: CLAIMED ${type}${n} as ${name} (attempt ${a})" >&2
    echo "$name"
    exit 0
  fi
  echo "next-branch: ${type}${n} was taken by another lane — retrying" >&2
  fetch_claims
  a=$(( a + 1 ))
done

echo "next-branch: FAILED to claim a ${type} number in ${ATTEMPTS} attempts" >&2
exit 1
