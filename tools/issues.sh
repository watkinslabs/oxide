#!/usr/bin/env bash
# Render the issue ledger.
#
# `scratch/known_issues.md` is the ONE place an issue lives. A lane that finds
# something adds its row there in the same PR that finds it; a lane that fixes
# one flips it to `FIXED <sha>` and moves it to `scratch/fixed-issues.md`.
#
#   tools/issues.sh                 render the ledger
#   tools/issues.sh --count         row count
#   tools/issues.sh --status-count  `STATUS<TAB>n` totals
set -euo pipefail

root=$(git rev-parse --show-toplevel)
curated="$root/scratch/known_issues.md"

rows() { grep -c '^| \(OPEN\|IN-PROGRESS\|FIXED\)' "$1" 2>/dev/null || true; }

# Status is the first cell. `FIXED` carries a SHA (`| FIXED C247 |`), so match
# the keyword and ignore the rest of the cell.
status_rows() {
  grep -ho '^| \(OPEN\|IN-PROGRESS\|FIXED\)' "$@" 2>/dev/null | sed 's/^| //' || true
}

case "${1:-}" in
  --status-count)
    for st in OPEN IN-PROGRESS FIXED; do
      printf '%s\t%s\n' "$st" "$(status_rows "$curated" | grep -cx "$st" || true)"
    done
    ;;
  --count)
    printf '%-40s %s\n' "$(basename "$curated")" "$(rows "$curated")"
    ;;
  *)
    cat "$curated"
    ;;
esac
