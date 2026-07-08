# Handoff — boot env FIXED; desktop blocker = SIGCHLD/zombie-reap stall

## DESKTOP BLOCKER (isolated on a CLEAN host — codex paused)
Clean boot reaches ~10s guest: journal-flush **Finished** (the earlier timeout
was pure codex CONTENTION, not a bug), userdbd Started — then WEDGES. sysrq task
dump (scratchpad/wedge.log): **13 processes in `Z` zombie state, last syscall
`nr#231` = exit_group** — systemd's early fork-children exited and are NEVER
REAPED. `init`(pid1) parks in `epoll_wait`; CPU idle (`current=tid:0 state=R`).
systemd reaps via SIGCHLD → signalfd → epoll_wait → waitid.
CODE-PATH TRACED (all LOOKS correct — bug is a subtle runtime state issue):
- `syscalls/060_exit.rs` sys_exit_group→sys_exit: for a group-leader
  (tid==tgid) calls `sched::live::signal_child_exit(task)`.
- `sched/live/zombies.rs signal_child_exit`: push_child_event → set parent
  `sigpending |= SIGCHLD` → `wake_wait4_parent` → `wake_task_for_signal(parent)`
  → `try_to_wake_up` (Sleeping→Runnable CAS; NO-OP if parent not Sleeping).
- `fs/signalfd.rs poll()`: POLL_IN iff `sched::current().sigpending & mask`.
So SIGCHLD IS posted + a wake IS attempted, yet systemd stays parked. Suspects
(need a TRACE, not code-read): (a) `try_to_wake_up` CAS no-ops because systemd's
epoll_wait park state isn't `Sleeping`; (b) epoll_wait, once roused, doesn't
RE-POLL the signalfd; (c) signalfd `poll()` runs with `current()` != systemd so
it reads the wrong sigpending; (d) 2257f275's child_sigq_pop / pending-bit-clear
races the poll. NEXT: add klog trace at signal_child_exit (did CAS succeed?) +
signalfd poll (called? current tid? bit set?) + epoll rewake; OR a hosted
harness: task blocks epoll_wait on a SIGCHLD signalfd, another exits, assert the
epoll wakes + read returns SIGCHLD. Commit 2257f275 is the prime regression.
Repro: `OXIDE_SMP=1 ./tools/boot-smoke.sh x86 90` (unique SMOKE_KEEP_LOG); wedges
~10s and sysrq-dumps ~13 zombies.

# Handoff — boot env FIXED (qemu CID conflict)

## THE "BOOT BROKE ALL NIGHT" ROOT CAUSE — FIXED + MERGED (PR #2848)
NOT a host fault, NOT the kernel (an earlier handoff wrongly blamed SeaBIOS).
A parallel **Codex `--yolo` agent** in worktree
`/home/nd/oxide-wt/B656-vt-kd-ioctl-compliance` looped `make smoke`; its qemu held
the HOST-GLOBAL `vhost-vsock guest-cid=3`. Both the MCP and xtask launchers
HARDCODED cid=3 (+ gdb 1234, ssh 2222), so every OTHER boot on the box died at
launch: `vhost-vsock: unable to set guest cid: Address already in use` (aborts
before SeaBIOS — the GDB stub then showed a stale reset vector, misread as a
"SeaBIOS hang"). Worktrees isolate files, NOT the CID/port namespace.
- **FIX (merged to main):** per-launch vsock CID + gdb/ssh ports from repo path +
  build id + pid (`buildns::qemu_vsock_cid`/`qemu_host_port`); overrides
  OXIDE_QEMU_{VSOCK_CID,GDB_PORT,SSH_PORT}. Both arches. Multiple workers coexist now.
- `pkill -9 qemu-system` DOES work here (old lesson §7 is stale) — but kill the
  RESPAWN loop first (`pgrep -af 'make smoke|boot-smoke'`) or qemu respawns in secs.

## BOOTING — what works
- `./tools/boot-smoke.sh x86 <timeout>` (make/xtask path) BOOTS to systemd
  userspace. Use a UNIQUE `SMOKE_KEEP_LOG=<path>` — codex writes the SAME
  /tmp/oxide-boot-smoke-x86-*.log, so `ls -t` grabs the wrong log (check for
  `Leaving directory 'oxide-wt'` to spot codex's).
- qemu MCP path STALLS at SeaBIOS 0x82e7 even with cid free — separate MCP bug,
  not chased. Use boot-smoke.
- Two agents both booting ≈ halves KVM throughput → systemd service timeouts.
  For a clean desktop boot, PAUSE the codex agent.
- Don't do git checkouts while a boot-smoke build runs (corrupts the build).
  Don't run overlapping boots. My bash tool's 120s timeout kills a fg boot — always
  run boot-smoke with run_in_background and WAIT for the completion notification.

## DESKTOP BLOCKER (current frontier)
Boots reach systemd but stop at **`systemd-journal-flush.service: Failed with
result 'timeout'`** (Flush Journal to Persistent Storage) — same journald↔ext4
writeback issue as prior sessions. May be contention OR a real bug. IN FLIGHT:
boot-smoke of `int-desktop-verify` (ext4 stack + qemu fix) with
SMOKE_MARKER='Reached target graphical.target' (log scratchpad/final.log) to see
if the A1/A2 ext4 fixes get past it to gdm.

## READY (local branches; hosted-tested + both arches build; NOT pushed)
Stacked off main: **A1 B656 → A2 B657 → A4 B658 → A3 B659 → B3 B660**. Integration
branch `int-desktop-verify` = that stack + the merged qemu fix. See scratch/ext4fix.md.
- A1 mtime-on-write (frozen-1970), A2 s_state lifecycle, A4 extent-descent bound,
  A3 rmdir reclaim, B3 msync EIO. ext4 87 lib + ~90 integ + vfs 98 tests green.
- To land: rebase the stack onto main (has qemu fix now), boot-verify, push+PR A1→B3.

## NEXT
1. Read scratchpad/final.log: journal-flush pass? graphical.target reached?
2. journal-flush still fails → real ext4 writeback bug (unwritten-extent / journal
   file); use a hosted harness, not boot-per-hypothesis.
3. Then push the ext4 stack + resume gdm greeter (prior blocker: gdm session
   wrapper SIGTERM after ~45s hang — see [[greeter-blocker-logind-seat]]).

## FIRST COMMAND NEXT SESSION
`pgrep -af 'make smoke|boot-smoke' | grep oxide-wt   # codex still competing?`
