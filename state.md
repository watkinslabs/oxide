# state — session hand-off

Branch: **main** (clean). All work merged. This session: ~22 PRs (#1769–#1789).

## What this session did
**vty-plan: substance complete** (emulator command set + job control). Merged:
- #1769 vt DA/DECID, IRM, C1 controls, OSC/DCS ST fix; #1770 OSC 4/104/10/11
  palette (emulator split into emulator/{mod,sgr,osc}.rs); #1771 DECCKM ?1 +
  bracketed paste ?2004; #1772 SIGTTIN/SIGTTOU/TOSTOP job control; #1773 pty
  SIGHUP+SIGCONT drain; #1774 VT/KD ioctl on /dev/console → active VT.
  REMAINING vty (deferred, documented in vty-plan.md): mouse reporting (needs a
  pointer pipeline — emulator-only = theater), Step B/RC5 cleanup (no-behavior),
  auto-ctty/session-enforcement (login-path risk), RC1 serial answerback
  (REASSESSED: NOT the Linux way — a serial line's terminal answers, not the
  kernel). docs/57 stays DRAFT until mouse lands.

**linux2.md: validated + real fixes.** META-FINDING: system is FAR more complete
than linux2.md's framing. Already-real (linux2 was wrong): IPC ns (shm/sem/msg/mq
ns-keyed), mount ns (resolve_mount filters mount_ns), pivot_root, perms/*at,
route+addr control-plane (persistent tables), sched_setattr. Genuine gaps FIXED:
- #1776 namespace fork-inheritance (clone copied NO ns state → every fork reset
  to root ns; now copy_namespaces) + UTS domainname isolation.
- #1778 shared uts_namespace registry (true shared-ns; setns adopts hostname).
- #1779 real sched_setscheduler(144) — was ALIASED to getscheduler (fake success).
- #1780 net-ns-aware rtnetlink dumps (GETLINK/GETADDR/GETROUTE) + per-ns routes.
- #1783 dynlink R_*_IRELATIVE (IFUNC) — was skipped (stub-interp path only).
- #1785 AT_HWCAP baseline (FP|ASIMD) on arm — was 0; #1791 + crypto/CRC bits
  from ID_AA64ISAR0_EL1 (host-tested decode → arm hw crypto, openssl verified).
- Stale-comment honesty fixes: #1782, #1784, #1789.

**#1 linux2 §2.3 blocker RESOLVED + verified** (#1787): openssl-on-aarch64
load-constructor hang NO LONGER REPRODUCES — /bin/openssl_probe runs EVP SHA-256
+ PASSes on BOTH arches (boot-smoke-probe). Was stale (fixed by earlier kernel
work). Attribution test REFUTED the F34/AT_HWCAP guess (arm AT_HWCAP→0 still
works). systemd + PAM login + openssl all run dynamically (real ld-musl) on arm.

## MORE RESOLVED this run
- **io_uring usable** (#1793, §2.7): mmap(io_uring_fd) maps the ring page →
  userspace shares the rings. /bin/io_uring_probe (raw NOP round-trip) PASSes
  on BOTH arches. (liburing's 3-region mmap layout = follow-up; single-page
  raw layout works now.)
- **AT_HWCAP complete** on arm (#1791): baseline + crypto-ext from ID_AA64ISAR0.

## HIGH-VALUE NEXT (need daytime / human-in-loop — too risky fully-unattended)
1. **rt_sigframe — RESOLVED/refuted** (#1795): sigframe_self_probe (SA_SIGINFO
   via SIGALRM, checks sig/siginfo/non-null-ucontext/resume) PASSes on BOTH
   arches → full Linux rt_sigframe. project_signal_frame_minimal was STALE.
2. **NEW BUG (high value): self-signal delivery via raise()/tkill broken.**
   sigframe_self_probe v1 used raise(SIGUSR1) and the handler NEVER ran (2s of
   nanosleep windows); SIGALRM (kernel-posted) works fine. musl raise()→
   SYS_tkill(own tid). Two issues: (a) `NR_TKILL => sys_kill` (dispatch.rs:370)
   — tkill is THREAD-targeted, sys_kill has pid/pgrp semantics (tkill(0)=pgrp
   etc. is wrong); should route like tgkill(234) minus the tgid check. (b)
   sys_kill self fast-path compares `pid == cur.tid` (INTERNAL tid) vs the
   user-supplied vtid (vpid≠internal-tid minefield, see
   pid_identity_and_at_syscalls) — if gettid returns vtid this misses + relies
   on lookup_in_ns. abort()/pthread_kill/raise all depend on this. Trace with a
   tkill probe + dtrace; fix the dispatch + identity together. DO NOT fix blind.
3. **ext4 extent depth** — capped at 2 (Linux: 5); generalize the walk.
   Hosted-testable over a deep-extent ext4 image; fs-risky.
3. **liburing 3-region mmap** (IORING_OFF_SQ_RING/CQ_RING/SQES offset cookies)
   so real liburing programs work, not just raw single-page users (#1793).
4. **Graphics stack** (§3): no xorg/mesa/weston in-tree — huge, userspace.

## Workflow notes
- Boot smoke both arches before push (kernel/userspace paths). boot-smoke-probe.sh
  <arch> <probe> logs in + runs /bin/<probe> + asserts "<probe>: PASS" — works on
  the systemd boot, both arches. rcS smokes (oxide-smokes.sh) need the rcS boot.
- CORE RULE (memory feedback_linux_way_per_task_gate): every task, ask "is this
  the Linux way?"; name the exact Linux mechanism; no hacks/theater; measure,
  don't claim (the openssl F34 attribution was tested + refuted, not assumed).

## First task next session
`git -C /home/nd/oxide2 log --oneline -12 main`. Pick from HIGH-VALUE NEXT —
the arm rt_sigframe (1) is highest-leverage but do it with a SIGILL+longjmp arm
probe as the verification gate.
