#!/usr/bin/env bash
# Is a fan-out of lanes actually working, or queued behind each other?
#
# Answers the one question an orchestrator cannot answer by looking at an
# agent's status: a lane reported "running" is not a lane making progress. The
# expensive failure this catches is N lanes sharing one cargo target directory,
# where every build serialises on the build-directory lock and the whole wave
# runs at the speed of one lane. Four lanes lost ~40 minutes to it before
# anyone looked, because "running" and "queued" are indistinguishable from
# outside.
#
#   tools/lane-health.sh [worktree]   default: the current directory
#
# Exit status is 1 when something is wrong, so it can gate a wait loop.

set -uo pipefail
root=${1:-$(pwd)}
cd "$root" || { echo "lane-health: no such worktree: $root" >&2; exit 1; }

rc=0
say() { printf '%-22s %s\n' "$1" "$2"; }

# 1. Build-lock contention. One target dir plus several cargo processes is the
#    signature: they are not working in parallel, they are taking turns.
# `pgrep -c` prints 0 AND exits non-zero when nothing matches, so a `|| echo 0`
# fallback appends a second zero and every later comparison errors out. Count
# the lines instead.
cargos=$(pgrep -x cargo 2>/dev/null | wc -l)
targets=$(tr '\0' '\n' < /dev/null; for p in $(pgrep -x cargo 2>/dev/null); do
    tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | sed -n 's/^CARGO_TARGET_DIR=//p'
done | sort -u | wc -l)
if [ "$cargos" -gt 1 ] && [ "$targets" -le 1 ]; then
    say "build lock" "CONTENDED — $cargos cargo processes, one target dir"
    echo "    Every build is serialising. Give each lane its own:"
    echo "    CARGO_TARGET_DIR=<scratch>/tgt-<lane> cargo test -p <crate>"
    rc=1
else
    say "build lock" "ok ($cargos cargo running)"
fi

# 2. Does the crate compile? A tree broken by one lane blocks every other lane,
#    and none of them owns the broken file. This is the deadlock shape: each
#    lane waits on a build that cannot succeed until somebody else moves.
for crate in $(git diff --name-only HEAD -- 'crates/*/*/src' 2>/dev/null |
               cut -d/ -f1-3 | sort -u); do
    name=$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$crate/Cargo.toml" 2>/dev/null | head -1)
    [ -n "$name" ] || continue
    if err=$(cargo build -p "$name" --message-format short 2>&1 | grep -m3 '^error'); then
        say "build $name" "BROKEN — every lane in this worktree is blocked"
        echo "$err" | sed 's/^/    /'
        rc=1
    else
        say "build $name" "ok"
    fi
done

# 3. A module declared before the file it names breaks the crate for everyone.
#    It has a distinctive error, so name it rather than leaving it in the pile.
missing=$(cargo build --message-format short 2>&1 | grep -c "couldn't read" || true)
[ "$missing" -gt 0 ] && { say "missing modules" "$missing declared-but-absent"; rc=1; }

# 4. Liveness. Silence in the source tree while lanes are "running" means they
#    are blocked on something, not thinking about something.
recent=$(find crates -name '*.rs' -newermt '-5 minutes' 2>/dev/null | wc -l)
if [ "$recent" -eq 0 ] && [ "$cargos" -gt 0 ]; then
    say "lane activity" "SILENT — no source touched in 5 min while builds run"
    rc=1
else
    say "lane activity" "$recent files touched in the last 5 min"
fi

exit $rc
