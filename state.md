# Session hand-off

## Headline
**PR #1508 merged to main (97bb9e1e).** Both arches boot to `oxide login:`
with: dentry-keyed mount crossing, real openat dirfd resolution,
MS_REMOUNT ordering, real TSC calibration + live rdtsc/cntvct vDSO clock,
and netlink real-state infra (rtnl async DEFERRED — open fails
gracefully). main is clean. Two precisely-localized follow-ups below.

## Follow-up 1 — netlink rtnl async reply matching (re-enable lo)
DEFERRED in #1508: getsockopt(SO_PROTOCOL)→-ENOPROTOOPT so sd_netlink_open
fails → systemd skips rtnl → login. To re-enable: revert that gate
(netlink_fd.rs getsockopt) and fix the real bug.
Timing-PROVEN it is NOT clock/scheduler: SETLINK ack arrives 2 ms after
send (ms 3219→3221), consumed, but sd_netlink `process_reply(serial)`
finds no callback for the SETLINK reply while the two RTM_NEWADDR acks
(consecutive serials) DO match → loopback_setup blocks to its 5 s timeout.
Callback keyed by wire serial (sd-netlink.c call_async:579-583); our ack
echoes that serial — yet SETLINK doesn't match. Needs gdb-on-systemd (or
sd-netlink serial/rqueue_by_serial tracing); not kernel-side-inspectable.
Files: vendor/systemd/.../shared/loopback-setup.c + .../sd-netlink.c
(process_reply @332; process_running @424 runs process_timeout BEFORE
dispatch_rqueue).

## Follow-up 2 — PID1 "Looping too fast" (CPU spin, pre-existing on main)
systemd's sd-event epoll never blocks because ONE fd is perpetually
level-ready POLLIN. TRACED: it's a `SockKind::UnixMsgPair` (AF_UNIX
SEQPACKET socketpair), one fd, ino_lo=437744744, reports POLLIN ~every
scan. poll() = POLLIN when `pair.has_msg(end)` (recv-ring non-empty).
recv path DOES drain it (net::sock::recvfrom → UnixMsgPair @sock.rs:963 →
pair.recv pops the same ring has_msg checks). So cause is either (a)
continuous traffic refilling the ring, or (b) systemd never reads THAT fd
(epolls it for HUP/error, or the handler is one-shot/disabled). Needs
gdb-on-systemd / systemd socketpair-usage analysis to confirm which.
NB: sys_recvmsg (net.rs:622-625) special-cases UnixDgram + Unix-stream
but NOT UnixMsgPair — it falls through to the recvfrom loop (which does
drain via sock::recvfrom). Verify that path is what systemd uses.
Login is reached regardless — this is CPU-efficiency, not a blocker.

## Proven / ruled out this session
- Clock was NOT the loopback gate (calibration→4.2 GHz + live vDSO, still
  timed out). Both clock fixes kept — correct + fix real userspace clock
  staleness (the old vDSO snapshot lagged seconds under a busy boot).
- F369 netlink commit was the ONLY boot regressor (bisected); neutralized.
- machine-id fully works (openat-dirfd + MS_REMOUNT + dentry bind).

## First task next session
1. Pick follow-up 1 (netlink) or 2 (PID1 spin) — both need gdb-on-systemd.
   For gdb-on-systemd: the qemu MCP attaches gdb to the KERNEL elf; to
   debug systemd userspace, breakpoint the kernel syscall entry for the
   relevant fd and read systemd's memory, or add gdbserver to the rootfs.
2. Else continue the distro roadmap (vim, more programs) on a fresh branch.

## Harness notes
- KVM (~1min): `OXIDE_QEMU_KVM=1 make SMP=2 qemu-x86`. Default TCG ~10-15min.
  arm is TCG-only (no arm KVM on x86 host) and boots clean to login.
- Free :2222 first: `ss -ltnp|grep 2222 → kill -9 <pid>` (comm truncated to
  "qemu-system-x86"; pgrep -x misses it — kill the pid from ss).
- Run boots ALONE in background; spec-lint clean before commit; netlink
  crate has no klog dep (trace from kernel/src instead).
