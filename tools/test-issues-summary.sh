#!/usr/bin/env bash
# Positive control for the generated issue-ledger summary.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tool=${ISSUES_TOOL:-"$root/tools/issues.sh"}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/known.md" <<'EOF'
| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | high | a | e | — |
| IN-PROGRESS B1-x | DEFECT | low | b | e | B1-x |
| OPEN | MISSING | blocker | c | e | — |
| OPEN | COVERAGE | med | d | e | — |
| OPEN | INFRA | critical | e | e | — |
| FIXED B2 | DEFECT | high | ignored | e | B2 |
EOF

cat >"$tmp/expected" <<'EOF'
| Class | blocker | critical | high | med | low | Total |
|---|---:|---:|---:|---:|---:|---:|
| COVERAGE | 0 | 0 | 0 | 1 | 0 | 1 |
| DEFECT | 0 | 0 | 1 | 0 | 1 | 2 |
| INFRA | 0 | 1 | 0 | 0 | 0 | 1 |
| MISSING | 1 | 0 | 0 | 0 | 0 | 1 |
| **Total** | **1** | **1** | **1** | **1** | **1** | **5** |
EOF

ISSUES_LEDGER="$tmp/known.md" "$tool" --summary >"$tmp/actual"
diff -u "$tmp/expected" "$tmp/actual"
