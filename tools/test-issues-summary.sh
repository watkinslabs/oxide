#!/usr/bin/env bash
# Positive controls for the issue-ledger tooling (tools/issues.sh / issues.py).
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tool=${ISSUES_TOOL:-"$root/tools/issues.sh"}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export ISSUES_LEDGER="$tmp/known.md" ISSUES_ARCHIVE="$tmp/fixed.md"

cat >"$tmp/known.md" <<'EOF'
# Known issues

**Live issue count: 5** — 4 `OPEN`, 1 `IN-PROGRESS`.

| Id | Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|---|
| KI-0001 | OPEN | DEFECT | high | a | e | — |
| KI-0002 | IN-PROGRESS B1-x | DEFECT | low | b | e | B1-x |
| KI-0003 | OPEN | MISSING | blocker | c | e | — |
| KI-0004 | OPEN | COVERAGE | med | d | e | — |
| KI-0005 | OPEN | INFRA | critical | e | e | — |
EOF
: >"$tmp/fixed.md"

cat >"$tmp/expected" <<'EOF'
| Class | blocker | critical | high | med | low | Total |
|---|---:|---:|---:|---:|---:|---:|
| COVERAGE | 0 | 0 | 0 | 1 | 0 | 1 |
| DEFECT | 0 | 0 | 1 | 0 | 1 | 2 |
| INFRA | 0 | 1 | 0 | 0 | 0 | 1 |
| MISSING | 1 | 0 | 0 | 0 | 0 | 1 |
| PERF | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **1** | **1** | **1** | **1** | **1** | **5** |
EOF
"$tool" --summary >"$tmp/actual"
diff -u "$tmp/expected" "$tmp/actual"

"$tool" --check

# query filters and briefs
[ "$("$tool" --query class=DEFECT | wc -l)" -eq 2 ]
"$tool" --query sev=blocker | grep -q '^KI-0003'
"$tool" --query grep='^| KI-0005' | grep -q INFRA
! "$tool" --query class=PERF 2>/dev/null

# add assigns the next unused id and keeps the count line true
[ "$("$tool" --add PERF med me 'slow thing' 'measured 5s')" = "KI-0006" ]
"$tool" --check
grep -q 'Live issue count: 6' "$tmp/known.md"

# claim flips OPEN -> IN-PROGRESS with a claim marker
"$tool" --claim KI-0001 B9-test
"$tool" --show KI-0001 | grep -q 'CLAIMED B9-test'
! "$tool" --claim KI-0001 B9-test 2>/dev/null   # double-claim refused

# fix moves the row to the archive, id preserved
"$tool" --fix KI-0003 C999
grep -q '^| KI-0003 | FIXED C999 ' "$tmp/fixed.md"
! grep -q '^| KI-0003 ' "$tmp/known.md"
"$tool" --check
[ "$("$tool" --add DEFECT low x y z)" = "KI-0007" ]   # archived id never reused

# NEGATIVE controls: the checker must go red on each defect class
break_check() { ! "$tool" --check >/dev/null 2>&1; }
cp "$tmp/known.md" "$tmp/save"
echo '| OPEN | DEFECT | high | id-less | e | — |' >>"$tmp/known.md"; break_check
cp "$tmp/save" "$tmp/known.md"
echo '| KI-0007 | OPEN | DEFECT | high | dup id | e | — |' >>"$tmp/known.md"; break_check
cp "$tmp/save" "$tmp/known.md"
echo '| KI-0100 | OPEN | DEFECT | high | bare | pipe | e | — |' >>"$tmp/known.md"; break_check
cp "$tmp/save" "$tmp/known.md"
sed -i 's/Live issue count: 6/Live issue count: 99/' "$tmp/known.md"; break_check
cp "$tmp/save" "$tmp/known.md"
python3 - "$tmp/known.md" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read().replace("| e | — |", "| " + "x" * 2100 + " | — |", 1)
open(p, "w").write(s)
EOF
break_check
cp "$tmp/save" "$tmp/known.md"
! "$tool" --add DEFECT low x y "$(printf 'x%.0s' $(seq 2100))" 2>/dev/null

echo "issues tooling: all controls pass"
