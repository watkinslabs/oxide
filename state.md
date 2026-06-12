# state — session hand-off

Branch: **main** @ `3c58187d`. Branch counters live in `metadata/index.md`
(AUTHORITATIVE — read+bump per branch). Dev loop:
`tools/boot-smoke-probe.sh x86 <probe>` under `OXIDE_QEMU_KVM=1` (~20s).
**GOTCHA: never `pkill -f qemu-system`** — it matches the bash-tool's own
cmdline and SIGTERMs the shell (exit 144). Use `pkill -9 -x qemu-system-x86_64`.

## Merged this run (linux2.md loop — "is this the Linux way", no fakes)

PID identity fully unified on the VPID (user pid == vtgid/vtid; internal tid is
kernel-only). All boot-verified on x86:
- **B117 #1806** SIGCHLD siginfo: real si_pid(child VPID)/si_status/si_code via
  per-parent child_sigq → SA_SIGINFO handlers correct (sigchld_probe PASS).
- **B118 #1805** pgid/sid in VPID space (with_vpid spawn re-seeds to vtgid; forks
  inherit via clone; kthreads keep internal tid) + /proc/loadavg last_pid via
  live_vpids (pid_identity_probe PASS: pgid=8 sid=7).
- **B119 #1807** real TCXONC output flow control (TCOOFF/TCOON park/wake; pty
  out_hold reuse; bad action EINVAL) — replaced `TCXONC=>0` (tcflow_probe PASS).
- **F438 #1808** real io_uring_register: REGISTER_BUFFERS/FILES/EVENTFD/PROBE +
  FILES_UPDATE + READ_FIXED/WRITE_FIXED + IOSQE_FIXED_FILE + eventfd-signal-on-CQE;
  unknown reg op => EINVAL. Replaced `427 {0}` (io_uring_reg_probe PASS).
  KNOWN GAP: reg op 7 REGISTER_EVENTFD_ASYNC falls to EINVAL (honest, not faked) —
  small follow-up to wire like op 4 + async flag.

## INCOMPLETE — 2 agents STOPPED mid-flight (uncommitted, work NOT lost)

Both branched off `e6d41d8f`; **nothing committed** (branch heads still at base).
Partial edits sit in their worktrees. Each was near-done but hit a structural snag.
Decision for next session: **redo cleanly** (recommended — cleaner than salvaging),
or inspect the worktree edits first. Bump index.md per branch on the redo.

1. **B120 tty-ioctl de-fake** (next B = 120) — worktree
   `.claude/worktrees/agent-adf6a97339ed5877c`. Goal: TIOCMSET/MGET/MBIS/MBIC
   (pty→ENOTTY; serial/VT→real modem bitmask in static_console/core) +
   TIOCSPTLCK/GPTLCK real pts lock (default locked, slave-open EIO while locked).
   Fakes still live in `016_ioctl.rs`: `TIOCMSET|TIOCMBIS|TIOCMBIC => 0` (~L431),
   `TIOCMGET` hardcoded mask (~L415), `TIOCSPTLCK => 0` (~L283).
   SNAG hit: agent ran cargo from shared checkout not its worktree (build looked
   stale). Probe: tty_ioctl_probe (uses ptmx/TIOCGPTN/TIOCSPTLCK/slave-open-EIO).

2. **F439 netlink multicast** (next F = 439) — worktree
   `.claude/worktrees/agent-a94cd55f2562038ec`. Goal: real bind() nl_groups +
   NETLINK_ADD/DROP_MEMBERSHIP + `rtnl_multicast()` broadcasting RTM_NEWLINK/
   NEWADDR/NEWROUTE to subscribed sockets. Fake still live:
   `syscalls/src/netlink_fd.rs:39 pub fn bind() -> i64 { 0 }` (ignores nl_pid +
   nl_groups; socket already HAS `groups: AtomicU32` at netlink/lib.rs:195, unused).
   SNAG hit: rtnetlink.rs grew to 1007 lines (>1000 cap) — split notify fns into a
   new `netlink/src/mcast.rs`, make the RTM_* builders `pub(crate)`. Probe:
   nlmcast_probe. NOTE wire RTMGRP_*→RTNLGRP_* mapping from uapi exactly.

Clean up if redoing fresh: `git worktree remove <path> --force` then
`git branch -D B120-tty-ioctl-defake F439-netlink-multicast`.

## First command next session

    git worktree list                 # confirm the 2 stale agent worktrees
    sed -n '280,285p;410,432p' crates/kernel/syscalls/src/016_ioctl.rs   # B120 fakes
    sed -n '35,40p' crates/kernel/syscalls/src/netlink_fd.rs             # F439 fake

## linux2.md remaining (validated real gaps, priority per linux2.md §7)
§2.6 full rtnetlink for iproute2/networkd (F439 starts this) · §2.8 ext4 write
caps at extent depth 2 (Linux=5; `extent_rw.rs` DepthUnsupported) · §2.9 stale
NotImplemented init() shims (iouring/net/tty crates) · §2.10 netfilter — LOCAL_IN
IS enforced (stack.rs:665 nf_hook bridge); gap = the other 4 hooks (LOCAL_OUT/
FORWARD/PRE/POSTROUTING) · §2.11 eBPF verifier/JIT · §2.12 tracefs real buffers ·
§2.13 fanotify real semantics · §3 X11/Wayland.

LESSON saved to memory: parallel impl-agents in worktrees must run cargo from the
worktree dir; and pre-warn them about the 1000-line file cap so they split early.
