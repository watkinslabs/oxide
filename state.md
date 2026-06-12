# state — session hand-off

Branch: **main** (clean). All this session's work merged. 17 PRs (#1769–#1785).

## OVERNIGHT autonomous run — meta-finding
Validated huge swathes of linux2.md against code: the system is FAR more
complete than linux2.md's pessimistic framing. Already-real (linux2 was wrong):
IPC ns (shm/sem/msg/mq ns-keyed), mount ns (resolve_mount filters mount_ns),
pivot_root, perms/*at, route+addr control-plane (persistent tables), sched_setattr.
Many stale "v1/follow-up/global/hardcoded" comments fixed (#1782, #1784, #1786-area).
Genuine gaps FIXED this run: namespace fork-inheritance (#1776), shared UTS-ns
registry (#1778), sched_setscheduler aliased-to-get (#1779), net-ns rtnetlink
dumps (#1780), dynlink IRELATIVE/IFUNC (#1783), AT_HWCAP baseline arm (#1785).

## HIGH-VALUE NEXT (need daytime / live verification — too risky unattended)
1. **openssl-on-aarch64 constructor hang** (#1 linux2 §2.3 blocker). Uses the
   REAL ld-musl (NOT dynlink.c — F33 was a separate fix). arm libcrypto IS
   vendored + openssl_probe builds for arm → diagnosable. Hypotheses: arm
   signal-frame gap (OpenSSL armcap SIGILL+longjmp probe; see
   project_signal_frame_minimal) OR ld-musl reloc OR getauxval. Needs LIVE arm
   qemu diagnosis (gdb / serial trace where it hangs before main).
2. **Full arm rt_sigframe** (ucontext) — unblocks Go/SA_SIGINFO + maybe (1).
   HIGH value, HIGH risk (subtle signal ABI; wrong = breaks ALL arm signals).
   Verify with a SIGILL+longjmp probe on arm before trusting.
3. **io_uring user-mmap** — rings live in HHDM, not user-visible → io_uring
   unusable by liburing. Needs multi-page liburing layout + offset-cookie mmap.
4. **AT_HWCAP crypto-ext bits** (read ID_AA64ISAR0_EL1 for AES/SHA/CRC32) — F34
   did only the FP|ASIMD baseline (safe). Optional bits need careful ID decode.

## linux2.md progress this session

## Merged this session (vty-plan completion, 7 PRs)
- #1769 P17-09 vt: DA/DECID answerback, IRM insert mode, C1 8-bit controls,
  OSC/DCS ST-terminator fix. emulator.rs relocated to `emulator/mod.rs`.
- #1770 P17-10 vt: OSC 4/104/10/11 color control + per-VC palette. emulator
  split into `emulator/{mod,sgr,osc}.rs` (was at 1000-line cap).
- #1771 P17-11 vt: DECCKM `?1` cursor-key app mode (arrows → SS3 `ESC O x`) +
  bracketed paste `?2004` (PASTESEL wrap). Foreground mode read via IoC
  fn-pointer queries in `tty::live` (keyboard driver has only a `tty` dep).
- #1772 RC4a tty: SIGTTIN/SIGTTOU + TOSTOP job control. Pure decision
  `tty::jobctl::decide` (host-tested, mirrors Linux `tty_check_change`);
  `console::jobctl::check` gathers live ctx + gates console/serial r/w.
- #1773 B109 pty: SIGHUP+SIGCONT to slave fg pgrp on master last-close
  (`on_release` set `pending_sighup` but never delivered it).
- #1774 B110 tty: VT/KD ioctls on `/dev/console` act on active VT, `/dev/ttyN`
  on VT N (dead `ino_low==1` branch fixed).

## vty-plan status — see vty-plan.md "Completion status"
Emulator command set + job-control core + RC2 functional bug DONE. Remaining
(documented, deliberately deferred): mouse reporting (needs pointer pipeline —
emulator-only would be theater), Step B/RC5 cleanup (no behavior change),
RC4 auto-ctty/session-enforcement (login-path risk), and **RC1 serial
answerback — reassessed as NOT the Linux way (a serial line's terminal answers
queries, not the kernel); do NOT implement kernel-side serial answerback.**
docs/57 stays DRAFT until mouse lands.

## NOW WORKING: linux2.md loop
Per user: after the plan, loop linux2.md — validate each gap against code, then
implement the REAL Linux behavior (no hacks/theater). CORE RULE (memory
`feedback_linux_way_per_task_gate`): for EVERY task ask "is this the Linux
way?"; name the exact Linux mechanism it mirrors; correct before shipping.

linux2.md priority order (§6): 1 shared-lib runtime both arches (esp aarch64
TLS/IFUNC/versioning/dlopen) → 2 PID1/login/PAM/NSS → 3 namespaces+mount+rootfs
→ 4 net control-plane (rtnetlink) → 5 io_uring_register (returns 0 uncond) →
6 ext4 extent depth/scale → 7 X11/Wayland graphics stack.

## linux2.md progress (overnight run, continuing)
- #1778 F31: shared uts_namespace registry — true Linux shared-ns UTS (setns
  adopts hostname; members share one entry). Replaced F30 per-task copies.
- #1779 B111: real sched_setscheduler(144) — was ALIASED to getscheduler
  (chrt/RT services silently got old policy back). Now applies policy+prio.
- #1780 F32: net-ns-aware rtnetlink dumps (GETLINK/GETADDR/GETROUTE) + per-ns
  routes (RouteRow.ns) — containers' `ip` now sees only their netns, not host.
- VALIDATED ALREADY-REAL (linux2.md was pessimistic): IPC ns (shm/sem/msg/mq
  all ns-keyed), pivot_root (real, main-dispatch), perms/*at (real), route/addr
  control-plane (persistent ROUTE_TABLE/ADDR_TABLE, not hardcoded), sched_setattr
  (real RT requeue). Syscall dispatch coverage broad + honest (ENOSYS only for
  the 17 OBSOLETE + genuinely-unimpl; cred/timer/perms/xattr/keyring sub-dispatch).

## earlier linux2.md progress this session
- #1776 F30 (§2.4): clone/fork now INHERIT parent namespaces (was: every fork
  reset to root ns — namespaces non-functional across process creation; Linux
  `copy_namespaces`). UTS ns now isolates domainname too (was nodename only).
  Factored `s272_unshare::apply_new_namespaces(&Task,bits)` shared by
  unshare+clone.
- VALIDATED, NOT a stub: io_uring (§2.7) — `427_register` returns 0, BUT the
  whole subsystem lacks user-visible ring mmap (rings live in HHDM kernel mem),
  so register isn't the gating piece; the mmap foundation is. Don't implement
  register first — build on sand. io_uring `iouring` crate (§2.9) is a dead
  45-line NotImplemented skeleton; real impl is in `syscalls/io_uring.rs`.

## Next task (precise): shared UTS-namespace registry
F30 stored UTS host/domain PER-TASK (copy on fork) — gives isolation but NOT
true Linux shared-ns semantics: two tasks in one UTS ns must SHARE one
`uts_namespace` (sethostname by one visible to the other), and `setns(uts_fd)`
must restore that ns's hostname (today `308_setns` UTS only sets the membership
bit, leaves hostname stale — `nscg/proc_ns.rs:setns_apply`). Linux-correct fix:
a refcounted registry `id → {hostname, domainname}` in `nscg`; task carries a
`uts_ns` id (REPLACES the two per-task `String` fields → shrinks task.rs, which
is AT the 1000-line cap); unshare allocates+copies, sethostname/setdomainname
write the entry, uname reads it, setns points at it, fork inherits the id
(shares). Touches: task.rs, nscg/proc_ns, hostname module (global=id 0),
063_uname, 170/171, 272_unshare, 056_clone. One focused PR.

## Then continue linux2.md §6 priority
1 shared-lib runtime both arches (aarch64 TLS/IFUNC/versioning/dlopen) — biggest
→ 2 PID1/login/PAM/NSS → 3 mount propagation/pivot_root → 4 rtnetlink control
plane → 5 io_uring user-mmap then register → 6 ext4 extent depth → 7 graphics.
CORE RULE (memory `feedback_linux_way_per_task_gate`): every task, ask "is this
the Linux way?"; name the exact Linux mechanism; no approximations/theater.
`git -C /home/nd/oxide2 log --oneline -10 main` for context.
