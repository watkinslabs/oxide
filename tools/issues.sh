#!/usr/bin/env bash
# Render the full issue ledger: the curated file plus every lane's own drop file.
#
# A single shared markdown table cannot survive ~15 concurrent lanes — every PR
# conflicted on it and each conflict cost a rebase round-trip. Lanes now write
# rows to `scratch/issues.d/<branch>.md`, one file per lane, which cannot
# conflict. The integration owner folds them into `scratch/known_issues.md` and
# deletes the drop file.
#
#   tools/issues.sh            render curated + all drops
#   tools/issues.sh --drops    render only the un-folded drops
#   tools/issues.sh --count    row counts per source
set -euo pipefail

root=$(git rev-parse --show-toplevel)
curated="$root/scratch/known_issues.md"
drops="$root/scratch/issues.d"

rows() { grep -c '^| \(OPEN\|IN-PROGRESS\|FIXED\)' "$1" 2>/dev/null || true; }

case "${1:-}" in
  --count)
    printf '%-40s %s\n' "$(basename "$curated")" "$(rows "$curated")"
    for f in "$drops"/*.md; do
      [ -e "$f" ] || continue
      printf '%-40s %s\n' "issues.d/$(basename "$f")" "$(rows "$f")"
    done
    ;;
  --drops)
    for f in "$drops"/*.md; do
      [ -e "$f" ] || continue
      echo "## $(basename "$f" .md)"; echo; cat "$f"; echo
    done
    ;;
  *)
    cat "$curated"
    echo
    echo "# Un-folded lane drops"
    echo
    "$0" --drops
    ;;
esac
