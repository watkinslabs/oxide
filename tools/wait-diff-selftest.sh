#!/usr/bin/env bash
# Falsification gate for the wait_diff probe. Host-only, no boot, ~9min
# (one baseline run plus one run per mutant, each ~27s).
#
# A differential probe that cannot fail is worse than no probe: it makes a
# green boot look like evidence. Every case in userspace/wait_diff carries
# a WAIT_DIFF_MUTANT that breaks exactly that case, and this script asserts
# the mutant changes the records it is supposed to change AND NOTHING ELSE.
# Run it whenever a probe case is added or its record format changes.
#
# The two `sleep|rel_*` records have no dedicated mutant: they assert the
# ABSENCE of a restart (signal(7) puts the sleep family in the
# never-restarted list, so SA_RESTART must change nothing), which no
# userspace mutation can manufacture. `nosig` covers them instead by
# removing the interruption entirely.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
DIR="$ROOT/userspace/wait_diff"
PROBE="$DIR/wait_diff"
WORK="$(mktemp -d /tmp/wait-diff-selftest-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
rc=0

records() { grep '^wdiff|' "$1" | sed 's/^wdiff|//'; }
keys_changed() {
    diff <(records "$1") <(records "$2") |
        sed -n 's/^[<>] \([a-z_]*|[a-z0-9_]*\)|.*/\1/p' |
        LC_ALL=C sort -u
}

run() { # run <outfile> [mutant]
    local out="$1" m="${2:-}"
    if [ -n "$m" ]; then WAIT_DIFF_MUTANT="$m" timeout 300 "$PROBE" >"$out" 2>&1
    else timeout 300 "$PROBE" >"$out" 2>&1; fi
    grep -q '^wdiff|meta|complete|status=DONE$' "$out"
}

check() { # check <mutant> <expected-key>...
    local m="$1"; shift
    local out="$WORK/$m.txt"
    if ! run "$out" "$m"; then
        echo "wait-diff-selftest: FAIL - mutant $m did not complete" >&2
        rc=1; return
    fi
    local want got
    want="$(printf '%s\n' "$@" | LC_ALL=C sort -u)"
    got="$(keys_changed "$WORK/base.txt" "$out")"
    if [ "$want" != "$got" ]; then
        echo "wait-diff-selftest: FAIL - mutant $m changed the wrong records" >&2
        diff <(echo "$want") <(echo "$got") | sed 's/^/    /' >&2
        rc=1; return
    fi
    echo "wait-diff-selftest: ok   $m ($(echo "$got" | wc -l) records)"
}

make -B -C "$DIR" all >"$WORK/build.log" 2>&1 || {
    tail -n 40 "$WORK/build.log" >&2
    echo "wait-diff-selftest: FAIL - probe build failed" >&2
    exit 1
}
run "$WORK/base.txt" || {
    tail -n 40 "$WORK/base.txt" >&2
    echo "wait-diff-selftest: FAIL - baseline did not complete" >&2
    exit 1
}
echo "wait-diff-selftest: baseline $(records "$WORK/base.txt" | wc -l) records"

check fpuclobber 'sigfpu|simd_preserved'
check fpunopat   'sigfpu|uc_fpstate'
check eintr \
    'lock|flock_sarestart' 'lock|setlkw_sarestart' 'fd|pipe_read_sarestart' \
    'fd|unix_recv_sarestart' 'fd|tcp_recv_sarestart' 'mqueue|recv_sarestart'
check restartall \
    'lock|flock_norestart' 'lock|setlkw_norestart' 'fd|pipe_read_norestart' \
    'fd|unix_recv_norestart' 'fd|tcp_recv_norestart' 'mqueue|recv_norestart'
check nopeerwrite \
    'ready|pty_master_poll_in' 'ready|pty_slave_poll_in' \
    'ready|fifo_poll_in' 'ready|mq_poll_in' 'ready|epoll_pty_in'
check nodrain \
    'ready|unix_pollout_backpressure' 'ready|tcp_pollout_backpressure' \
    'ready|epoll_unix_out_backpressure'
check nofill \
    'ready|unix_pollout_backpressure' 'ready|tcp_pollout_backpressure' \
    'ready|epoll_unix_out_backpressure'
check absrem   'sleep|abs_sarestart'
check handler  'sleep|stopcont_restart_block' \
    'sysv_msg|rcv_stopcont_restarts' 'sysv_msg|snd_stopcont_restarts'
check nofg     'jobctl|sigttin_stops_background' 'jobctl|read_resumes_after_fg'
check wallcpu  'cputime|single_thread_no_progress'
check noburn   'cputime|sibling_burn_completes'
check mqnokill 'mqueue|sigkill_kills_blocked_receiver'
# B1460: `latnowait` removes the wait entirely (the degenerate
# return-immediately implementation) so the lower bound must flip;
# `latslow` spends the ~100 ms-per-wait floor this branch removed, so the
# conformance budget must flip. Two edges, two mutants — a ladder whose top
# rung cannot be moved is only half proven.
check latnowait 'latency|nanosleep_short' 'latency|epoll_wait_short'
check latslow   'latency|nanosleep_short' 'latency|epoll_wait_short'
check mqnoprio   'mqapi|priority_order'
check mqnonotify 'mqapi|notify_signal'
check mqnothread 'mqapi|notify_thread'
check mqnostate  'mqapi|read_state_line'
# inotify event LAYOUT — the host kernel is the oracle for the exact bytes, so
# each mutant corrupts one part of what the reader recovers.
check inoname \
    'inotify|create_name' 'inotify|pad_fills_one' 'inotify|pad_spills_two' \
    'inotify|mkdir_isdir' 'inotify|move_names' 'inotify|child_modify' \
    'inotify|short_buf'
check inolen \
    'inotify|create_name' 'inotify|pad_fills_one' 'inotify|pad_spills_two' \
    'inotify|mkdir_isdir' 'inotify|child_modify'
check inobuf   'inotify|short_buf'
check inochild 'inotify|child_modify'
check nosig \
    'sleep|rel_norestart' 'sleep|rel_sarestart' 'sleep|abs_sarestart' \
    'lock|flock_sarestart' 'lock|flock_norestart' \
    'lock|setlkw_sarestart' 'lock|setlkw_norestart' \
    'fd|pipe_read_sarestart' 'fd|pipe_read_norestart' \
    'fd|unix_recv_sarestart' 'fd|unix_recv_norestart' \
    'fd|unix_recv_timed_sarestart' \
    'fd|tcp_recv_sarestart' 'fd|tcp_recv_norestart' \
    'mqueue|recv_sarestart' 'mqueue|recv_norestart' \
    'sysv_sem|signal_sarestart' 'sysv_sem|signal_norestart' \
    'sysv_msg|rcv_signal_sarestart' 'sysv_msg|rcv_signal_norestart' \
    'sysv_msg|snd_signal_sarestart' 'sysv_msg|snd_signal_norestart'
check sysvavail \
    'sysv_sem|nowait_eagain' 'sysv_msg|rcv_nowait_enomsg' 'sysv_msg|snd_nowait_eagain'
check sysvnopost \
    'sysv_sem|block_until_posted' 'sysv_sem|wait_for_zero' \
    'sysv_msg|rcv_blocks_until_sent' 'sysv_msg|snd_blocks_until_drained'
check sysvnormid  'sysv_sem|rmid_eidrm' 'sysv_msg|rmid_eidrm'
check sysvnoundo  'sysv_sem|undo_reverted_on_exit'
check sysvmsgflags \
    'sysv_msg|rcv_noerror_truncates' 'sysv_msg|negative_msgtyp_lowest' \
    'sysv_msg|msg_except_skips'
check sysvdt1page 'sysv_shm|detach_whole_segment' 'sysv_shm|detach_twice_einval'
check sysvdtbase \
    'sysv_shm|detach_interior_einval' 'sysv_shm|detach_unaligned_einval' \
    'sysv_shm|detach_foreign_mapping_einval'
check sysvnofork  'sysv_shm|nattch_tracks_fork'

[ "$rc" -eq 0 ] && echo "wait-diff-selftest: PASS - every probe case is falsifiable"
exit "$rc"
