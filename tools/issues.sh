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
#   tools/issues.sh --summary       live class/severity totals
#   tools/issues.sh --check         validate the live-ledger shape and count
set -euo pipefail

root=$(git rev-parse --show-toplevel)
curated=${ISSUES_LEDGER:-"$root/scratch/known_issues.md"}

rows() { grep -c '^| \(OPEN\|IN-PROGRESS\|FIXED\)' "$1" 2>/dev/null || true; }

# Status is the first cell. `FIXED` carries a SHA (`| FIXED C247 |`), so match
# the keyword and ignore the rest of the cell.
status_rows() {
  grep -ho '^| \(OPEN\|IN-PROGRESS\|FIXED\)' "$@" 2>/dev/null | sed 's/^| //' || true
}

summary() {
  awk -F'|' '
    function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
    BEGIN {
      classes[1]="COVERAGE"; classes[2]="DEFECT"; classes[3]="INFRA"; classes[4]="MISSING"
      sevs[1]="blocker"; sevs[2]="critical"; sevs[3]="high"; sevs[4]="med"; sevs[5]="low"
      for (i=1; i<=4; i++) class_ok[classes[i]]=1
      for (i=1; i<=5; i++) sev_ok[sevs[i]]=1
    }
    /^\| *(OPEN|IN-PROGRESS)/ {
      class=trim($3); sev=tolower(trim($4))
      if (!(class in class_ok)) { printf "issues: unknown class %s\n", class > "/dev/stderr"; bad=1; next }
      if (!(sev in sev_ok)) { printf "issues: unknown severity %s\n", sev > "/dev/stderr"; bad=1; next }
      count[class,sev]++; class_total[class]++; sev_total[sev]++; total++
    }
    END {
      if (bad) exit 2
      print "| Class | blocker | critical | high | med | low | Total |"
      print "|---|---:|---:|---:|---:|---:|---:|"
      for (i=1; i<=4; i++) {
        class=classes[i]
        printf "| %s", class
        for (j=1; j<=5; j++) printf " | %d", count[class,sevs[j]]
        printf " | %d |\n", class_total[class]
      }
      printf "| **Total**"
      for (j=1; j<=5; j++) printf " | **%d**", sev_total[sevs[j]]
      printf " | **%d** |\n", total
    }
  ' "$curated"
}

check() {
  local fixed live advertised
  fixed=$(grep -c '^| FIXED ' "$curated" 2>/dev/null || true)
  if [ "$fixed" -ne 0 ]; then
    printf 'issues: known_issues.md contains %s FIXED rows; move them to scratch/fixed-issues.md\n' "$fixed" >&2
    return 1
  fi
  live=$(grep -c '^| \(OPEN\|IN-PROGRESS\)' "$curated" 2>/dev/null || true)
  advertised=$(sed -n 's/^\*\*Live issue count: \([0-9][0-9]*\)\*\*.*/\1/p' "$curated" | head -1)
  if [ -z "$advertised" ] || [ "$advertised" -ne "$live" ]; then
    printf 'issues: top live count is %s, table contains %s live rows\n' "${advertised:-missing}" "$live" >&2
    return 1
  fi
  if [ "$(grep -c '^| Status | Class | Sev | Issue | Evidence | Owner |$' "$curated" || true)" -ne 1 ]; then
    printf 'issues: known_issues.md must contain exactly one issue table\n' >&2
    return 1
  fi
}

case "${1:-}" in
  --summary)
    summary
    ;;
  --check)
    check
    ;;
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
