#!/usr/bin/env bash
# Guest-visible devpts gate: allocate through the mounted /dev/ptmx, then
# inspect the slave node created by that mount's devpts instance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SMOKE_ALIVE_CMD="python3 -c 'import os;m,s=os.openpty();p=os.ttyname(s);q=os.stat(p);print(f\"PTS{q.st_mode&511:o}:{q.st_uid}:{q.st_gid}\")'"
export SMOKE_ALIVE_MARKER="${DEVPTS_SMOKE_MARKER:-PTS620:0:5}"
exec "$ROOT/tools/boot-smoke.sh" "$@"
