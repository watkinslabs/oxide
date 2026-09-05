#!/usr/bin/env bash
# Enforce one active checkout per clone. Worktree creation is an integration
# decision; allowing several writers in one clone recreates the stale-tree and
# unreviewed-WIP failure this guard is intended to stop.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
count=$(git worktree list --porcelain | awk '$1 == "worktree" { n++ } END { print n + 0 }')
if [ "$count" -ne 1 ]; then
    echo "worktree-guard: REJECTED — this clone has $count active worktrees" >&2
    echo "worktree-guard: close every secondary checkout before committing, pushing, or checking out" >&2
    git worktree list >&2
    exit 1
fi

echo "worktree-guard: PASS — one active worktree ($root)"
