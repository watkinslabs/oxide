#!/usr/bin/env bash
# Derive the next branch counter for a type from git itself, so the number can
# never be stale relative to history. `metadata/index.md` stays authoritative
# for RESERVATIONS (numbers claimed by a live lane that has not merged yet);
# git is authoritative for what has already been USED. The answer is the max of
# both, which is correct whichever one is behind.
#
#   tools/next-branch.sh B                  -> next B number
#   tools/next-branch.sh B my-fix-title     -> full branch name
#   tools/next-branch.sh --check            -> non-zero if index.md is behind git
#   tools/next-branch.sh --check B          -> same, one type
#
# Types: F B D R Z C, plus phase branches P<n>.
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
    git for-each-ref --format='%(refname:short)' refs/heads refs/remotes
    git log --all --format='%s'
  } | grep -oE "(^|[^A-Za-z0-9])${t}[0-9]{2,4}-" \
    | grep -oE "${t}[0-9]{2,4}" \
    | sed "s/^${t}//" \
    | sort -n | tail -1
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

type=${1:-}
if [ -z "$type" ]; then
  echo "usage: $0 <TYPE> [kebab-title] | --check [TYPE...]" >&2
  exit 2
fi

n=$(pad "$(next_for "$type")")
title=${2:-}
if [ -z "$title" ]; then
  echo "${type}${n}"
else
  echo "${type}${n}-${title}"
fi
