# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 14s + arm smoke 18s green.

## Session tally (PRs #1178–#1179)

| PR    | What |
|-------|------|
| B44   | user-mode #GP (and any non-#PF user trap) now delivers SIGSEGV via the live FaultFrame's CS-CPL check instead of halting the whole kernel; SIGSEGV-delivery block split into `user_as/signal.rs` per `08§7` |
| F126  | added TIOCGSID / TIOCNOTTY / TIOCMGET / TIOCMSET / TIOCMBIS / TIOCMBIC; new `tty::live::session(vt)` + `Pair::session_pid`; closes the kernel surface busybox getty was wedging on |

## What works end-to-end now

- **kernel survives user-mode #GP / #UD / #DE / #SS** — a single
  dhcpcd-class non-canonical-pointer dereference no longer wedges
  every CPU; the offending task gets SIGSEGV (signal 11 + 0x100)
  and `schedule()` proceeds. Kernel-mode trips still halt with the
  diagnostic dump.
- **getty ioctl surface complete** — TIOCGSID returns the per-VT
  (or pair) session id or ENOTTY; TIOCNOTTY clears the slot when
  the caller owns it; TIOCMGET reports DTR/RTS/CD/DSR/CTS/LE
  asserted; SET/BIS/BIC accept and no-op.
- **dhcpcd-enable hunt marker** — opt-in via `OXIDE_DHCPCD_ENABLE=1`
  in the xtask rootfs builder; auto-launch in rcS still gated
  behind `/etc/oxide-dhcpcd-enable` (off by default until the
  userspace heap-corruption root cause is fixed).

## Open next (priority order)

1. **dhcpcd `0x40935a` (was `0x4925f9`) hunt** — the user-mode #GP
   is at `mov (%rdi, %r12, 1), %rax` inside `free_options()`
   walking `ifo->environ[]`. Either `rdi` (the array pointer) or
   `r12` (the index) is non-canonical. Our FaultFrame doesn't save
   callee-saved GPRs (r12 in particular), so the diagnostic dump
   can't show what's actually bad. Next step: extend
   `oxide_fault_common` to push rbx/rbp/r12-r15 so the #GP log
   can dump r12 + the value at `*(rdi)`. Repro recipe in
   `tools/xtask/src/main.rs` (set `OXIDE_DHCPCD_ENABLE=1` + stage
   `/etc/oxide-dhcpcd-enable` in rootfs, then `make qemu-x86`).
2. **getty inittab wedge (still open after F126)** — F127 tried
   flipping the serial respawn line to `/sbin/getty -L 115200
   ttyS0 vt100` but smoke didn't reach login; further trace
   needed (likely an unhandled tcsetattr c_cflag bit or
   open-with-O_NONBLOCK-on-our-console path). Branch
   `F127-inittab-real-getty-deferred` parked locally.
3. **K10 eBPF rest** — path-sensitive verifier (reg types, scalar
   bounds) → JIT; structural-only today
4. **K13 DRM/KMS atomic modeset** — property tables + real
   atomic-commit
5. **DNS / TLS userspace** — depends on dhcpcd actually leasing
6. **per-fd targeted epoll wakes** — current model is global
   broadcast; needs `Inode::poll_wait()` hook without dragging
   `sched` into `vfs`

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- spec-lint clean before every commit + PR
- Per `debug-irq` cfg: `[FAULT]` and `[FAULT] sigsegv:` lines stay
  silent in production builds. Use `FEATURES=debug-irq make qemu-x86`
  to see them.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick from "Open next". Item 1 (dhcpcd hunt) is the only
thing blocking real DHCP — needs a register-dump extension to
`oxide_fault_common` first (push callee-saved r12/r13/r14/r15
+ rbx/rbp) so we can see what `mov (%rdi,%r12,1)` is reading
from. Otherwise the crash address is correct but the diagnostic
context is unusable.
