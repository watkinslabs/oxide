#!/usr/bin/env bash
# Issue ledger front-end. Engine: tools/issues.py.
#
# `scratch/known_issues.md` is the ONE place a live issue lives; each row has a
# stable `KI-NNNN` id. NEVER read or grep the whole ledger to find work — query:
#
#   tools/issues.sh --query [status=..] [class=..] [sev=..] [owner=..] [grep=RE]
#                                   brief matching live rows (id + first line)
#   tools/issues.sh --show KI-NNNN  full row
#   tools/issues.sh --add CLASS SEV OWNER ISSUE EVIDENCE   append row, prints id
#   tools/issues.sh --claim KI-NNNN BRANCH                 OPEN -> IN-PROGRESS
#   tools/issues.sh --fix KI-NNNN SHA    flip FIXED + move to archive ledger
#   tools/issues.sh --count / --status-count / --summary   totals
#   tools/issues.sh --check         validate shape, ids, caps, count line
#   tools/issues.sh                 render the full ledger (rarely needed)
#
# Fixed rows keep their id in scratch/archive/fixed-issues.md. Evidence cells
# are capped at 2000 chars — park longer detail in scratch/archive/.
set -euo pipefail
exec python3 "$(git rev-parse --show-toplevel)/tools/issues.py" "$@"
