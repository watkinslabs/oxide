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

## HIGH-VALUE NEXT (need daytime / human-in-loop — too risky fully-unattended)
1. **Full arm rt_sigframe (ucontext)** — unblocks Go / SA_SIGINFO apps
   (project_signal_frame_minimal). HIGH value, HIGH risk (wrong = breaks ALL
   arm signals). Verify with a SIGILL+longjmp probe on arm BEFORE trusting.
2. **io_uring user-mmap** — rings live in HHDM, not user-visible → io_uring
   unusable by liburing. Needs multi-page liburing layout + offset-cookie mmap;
   no in-tree io_uring userspace test → hard to verify.
3. **ext4 extent depth** — capped at 2 (Linux: 5); generalize the extent walk.
   Hosted-testable over a deep-extent ext4 image; fs-risky.
4. **AT_HWCAP crypto-ext bits** (ID_AA64ISAR0_EL1 → AES/SHA/CRC32). Safe (reads
   actual ID reg). cpu_hwcap() hook now exists (#1785).
5. **Graphics stack** (§3): no xorg/mesa/weston in-tree — huge, userspace.

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
