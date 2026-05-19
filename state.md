# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 15s + arm smoke 20s green.
Boot now reaches `oxide login:` through REAL getty (no more
`/bin/sh -c 'exec /bin/login'` workaround).

## Session tally (PRs #1178–#1186)

| PR    | What |
|-------|------|
| B44   | user-mode #GP delivers SIGSEGV instead of halting kernel |
| F126  | TIOCGSID / TIOCNOTTY / TIOCM* — closes getty kernel-ioctl surface |
| B45   | full-GPR dump on unhandled trap (rbx/rbp/r12-r15 captured) |
| F128  | MADV_DONTNEED drops pages, preserves VMA (was destructively munmap+mmap) |
| B46   | execve resets caught signal handlers to SIG_DFL — fixes the busybox-init SIGCHLD-handler leak (0x4925f9) that was silently SIGSEGV-ing every fork+execve'd child in its waitpid path |
| F129  | execve also resets sigaltstack / robust futex list / pdeath_sig / itimer / posix timers / RT sigqueue (companion sweep to B46) |
| F130  | **`tick_yield` x86 idle uses `sti; hlt; cli`** — fixes `sys_nanosleep`/`usleep`/`clock_nanosleep` hanging forever when alone-on-CPU (SFMASK cleared IF on syscall entry, HLT with IF=0 only wakes on NMI/INIT/RESET per Intel SDM §8.10.1). Flips inittab from the `/bin/login`-direct workaround back to real `/sbin/getty`. Adds `/bin/usleep_smoke` probe. |

## What works end-to-end now

- **Real getty boot path** — `oxide Linux on /dev/ttyS0 / oxide login:` via `/sbin/getty -L 115200 ttyS0 vt100` through busybox getty's full TIOCSCTTY / TCSETS / usleep / tcflush / print-issue / prompt flow.
- **Kernel survives user-mode #GP / #UD / #DE** — single non-canonical-pointer deref no longer wedges every CPU.
- **`usleep` / `nanosleep` / `clock_nanosleep`** — work alone-on-CPU. CRITICAL fix; was silently parking countless programs.
- **execve preserves Linux signal-disposition + per-task-state semantics** — caught handlers reset, sigaltstack/robust_list/pdeath/itimer/posix-timers/rt-sigqueue cleared. No more handler-leak across exec boundaries.
- **`MADV_DONTNEED`** — drops pages, preserves VMA. GROWSDOWN flags, file backing, and COW-shared peers all survive.
- **Smoke output now visible** — `sem_smoke: PASS / msg_smoke: PASS / mq_smoke: PASS / mprotect_smoke: PASS / mmap_zero_smoke: PASS / usleep_smoke: PASS`. These were all silently SIGSEGV'ing before B46.

## Open next (priority order)

1. **dhcpcd `0x40935a` #GP** — survived B46 + F129 + F130. Real
   dhcpcd-specific bug: a function in dhcpcd is being called with
   `ifo` pointing to user stack 0x7ffffffa7040, where offset
   0x10120 contains a deterministic non-canonical value
   (0xe580024eb70f2376) that gets dereffed → #GP. Needs caller-
   chain inspection (gdb-attached qemu) to identify the calling
   site — the binary is stripped so addr2line is no help. dhcpcd
   auto-launch in rcS stays gated behind `/etc/oxide-dhcpcd-enable`
   marker (off by default).
2. **arm tickless idle** — F130's arm side spins (busy-loop)
   inside `tick_yield` instead of `wfi` because QEMU virt + DAIF.I=1
   hangs both plain wfi and daifclr+wfi+daifset. Wasteful but
   correct; full tickless-idle for arm wants the right
   daifclr/wfit/daifset pairing or a separate idle helper.
3. **K10 eBPF rest** — path-sensitive verifier (reg types, scalar
   bounds) → JIT; structural-only today.
4. **K13 DRM/KMS atomic modeset** — property tables + real
   atomic-commit.
5. **per-fd targeted epoll wakes** — global broadcast today; needs
   `Inode::wake_poll()` hook without dragging `sched` into `vfs`.
6. **file-backed mmap completeness** — phase 14 item; less-common
   combinations (MAP_SHARED with non-anon backing) need auditing.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- spec-lint clean before every commit + PR
- `debug-irq` cfg gates `[FAULT]` lines + GPR dump. Use
  `FEATURES=debug-irq make qemu-x86` to see them.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick from "Open next". Item 1 (dhcpcd 0x40935a) is now a
pure userspace investigation — needs gdb-attached qemu to walk
the call chain because the binary is stripped. Item 2 (arm
tickless idle) is a small kernel cleanup. Items 3–6 are larger.
