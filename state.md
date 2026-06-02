# Session hand-off

## Headline
Branch **F370-sched-clock-accuracy** (off F369 off main). **Both arches
reach `oxide login:`** with real improvements active; netlink rtnl async
deferred honestly. Mergeable once x86-TCG smoke confirms (KVM + arm-TCG
already verified). x86 under KVM = login; aarch64 under TCG = clean login
("Startup finished … 14s").

## What landed this session (commits on F370, newest first)
- `7efe6e09` chore(netlink): defer rtnl async — getsockopt(SO_PROTOCOL)→
  -ENOPROTOOPT so sd_netlink_open fails gracefully → systemd skips rtnl →
  login (main's behaviour). Real-state netlink infra retained.
- `84491d88` feat(time): real TSC calibration (PIT ch2, measured 4.20 GHz
  under KVM) + LIVE rdtsc/cntvct vDSO clock (both arches) replacing the
  stale published snapshot. vvar: monotonic_ns field → tsc_khz.
- `c8ffe1b4` fix(netlink): MSG_PEEK in recvmsg (sd-netlink buffer sizing).
- `efa06dc2` fix(syscall): real openat dirfd resolution (was IGNORED
  kernel-wide) + MS_REMOUNT-before-MS_BIND.
- `01d1d8cd` refactor(vfs): mount crossing keyed by DENTRY IDENTITY, not
  path string (the user's "no strings" demand). 69 vfs hosted tests pass.
- `5449322f` feat(netlink): real mutable iface flags + unified socket recv.

## The netlink rtnl bug (DEFERRED, precisely localized — for follow-up)
Timing-PROVEN it is NOT clock/scheduler: SETLINK ack arrives 2 ms after
send (ms 3219→3221), is consumed, but sd_netlink's `process_reply(serial)`
finds no callback for the SETLINK reply while the two RTM_NEWADDR acks
(consecutive serials) DO match. So `loopback_setup` (and every sd_netlink
user, incl. the systemd manager rtnl) blocks to its 5 s timeout and the
boot wedges. Callback is keyed by the wire serial (sd-netlink.c
call_async:579-583) and our ack echoes that serial — yet SETLINK doesn't
match. Needs gdb-on-systemd (or sd-netlink serial/rqueue_by_serial
tracing) to root-cause; not resolvable by kernel-side inspection.
Files: vendor/systemd/systemd-259/src/shared/loopback-setup.c +
.../libsystemd/sd-netlink/sd-netlink.c (process_reply @332; process_running
@424 runs process_timeout BEFORE dispatch_rqueue).

## Proven / ruled out this session
- Clock was NOT the loopback gate (calibration→4.2GHz + live vDSO, still
  timed out). Both clock fixes kept — correct regardless (live vDSO fixes
  real userspace clock staleness: snapshot lagged seconds under busy boot).
- KVM gated behind `OXIDE_QEMU_KVM=1` (~1min); default TCG ~10-15min.
- main reaches login under KVM (skips rtnl). F369 netlink commit was the
  ONLY boot regressor (bisected) — now neutralized by the open-defer.
- machine-id fully works (openat-dirfd + MS_REMOUNT + dentry bind).

## First task next session
1. Confirm x86-TCG smoke (task by833ffs6 → /tmp/fx86tcg.txt) reached login.
   If yes: push F370 -u; gh pr create + merge --delete-branch (SKIP_SMOKE=1
   only after both-arch local login confirmed).
2. netlink rtnl follow-up: gdb-on-systemd at loopback_setup to see why
   process_reply drops the SETLINK serial; re-enable SO_PROTOCOL once fixed
   → lo comes up + all rtnl unblocks.
3. Pre-existing (NOT this branch): x86 KVM "Looping too fast. Throttling
   execution" (crash-looping unit) — main has it too; login still reached.

## Harness notes
- Free :2222 first: `ss -ltnp|grep 2222 → kill -9 <pid>` (comm truncated to
  "qemu-system-x86"; pgrep -x misses it — kill the pid from ss).
- Run boots ALONE in background; spec-lint clean; netlink crate has no klog.
