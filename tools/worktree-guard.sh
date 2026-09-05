#!/usr/bin/env bash
# Enforce reconciliation of linked checkouts. Fan-out is allowed, but an old
# worktree must be merged, refreshed, or removed before more work is published.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
max_hours=${OXIDE_WORKTREE_MAX_AGE_HOURS:-2}
case "$max_hours" in (*[!0-9]*|'') echo "worktree-guard: invalid OXIDE_WORKTREE_MAX_AGE_HOURS=$max_hours" >&2; exit 1;; esac
now=$(date +%s)
admin_root=$(git rev-parse --git-path worktrees)
stale=0

for admin in "$admin_root"/*; do
    [ -f "$admin/gitdir" ] || continue
    linked_gitdir=$(sed -n '1p' "$admin/gitdir")
    linked_root=${linked_gitdir%/.git}
    [ -d "$linked_root" ] || continue
    age=$((now - $(stat -c %Y "$admin/gitdir")))
    limit=$((max_hours * 3600))
    if [ "$age" -gt "$limit" ]; then
        branch=$(git -C "$linked_root" symbolic-ref --short -q HEAD || echo detached)
        printf 'worktree-guard: STALE — %s branch=%s age=%ss limit=%ss\n' \
            "$linked_root" "$branch" "$age" "$limit" >&2
        stale=1
    fi
done

if [ "$stale" -ne 0 ]; then
    echo "worktree-guard: REJECTED — reconcile stale worktrees before publishing" >&2
    echo "  merge/PR and remove it, refresh it from origin/main, or explicitly close the lane" >&2
    git worktree list >&2
    exit 1
fi

echo "worktree-guard: PASS — no linked worktree exceeds ${max_hours}h ($root)"
