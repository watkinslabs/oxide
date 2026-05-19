# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 14s + arm smoke 18s green.

## Session tally (PRs #1178–#1182)

| PR    | What |
|-------|------|
| B44   | non-#PF user-mode trap (#GP / #UD / etc.) now delivers SIGSEGV via the live FaultFrame's CS-CPL check instead of halting the kernel; SIGSEGV block split into `user_as/signal.rs` |
| F126  | TIOCGSID / TIOCNOTTY / TIOCM[GET\|SET\|BIS\|BIC] added (closes the kernel ioctl surface busybox getty wedges on) |
| B45   | x86 fault stub pushes rbx/rbp/r12-r15 in addition to caller-saved; full GPR dump on unhandled #GP/#UD lets the diagnostic name the bad register |
| F128  | MADV_DONTNEED no longer destructively munmap+mmap — uses refcount-aware `evict_pages_in_range` so GROWSDOWN flags, file backing, and COW-shared peers all survive |

## What works end-to-end now

- **kernel survives user-mode #GP / #UD / #DE / #SS** — a single
  dhcpcd-class non-canonical-pointer dereference delivers SIGSEGV
  to the offending task; kernel keeps running.
- **getty kernel surface complete** — TIOCGSID returns the per-VT
  (or pair) session id or ENOTTY; TIOCNOTTY clears it; TIOCMGET
  reports DTR/RTS/CD/DSR/CTS/LE asserted; SET/BIS/BIC accept and
  no-op. (Inittab still uses the `/bin/login`-direct workaround
  because getty wedges later in its tcgetattr/init_tty_attrs path
  — F127 attempt parked locally on a deferred branch.)
- **full register state on fault** — `[FAULT]` block under
  `debug-irq` now logs every GPR. dhcpcd crash diagnosed as
  userspace bug: `free_options(ctx, ifo)` called with `ifo`
  pointing to user stack (0x7ffffffa7040), `ifo->environ` read
  returns garbage 0xe580024eb70f2376 (non-canonical) → #GP on
  the next deref.
- **MADV_DONTNEED preserves VMA metadata** — anonymous pages
  refault as zero, file-backed pages refault from disk, COW-shared
  frames stay alive in the peer AS.

## Open next (priority order)

1. **dhcpcd userspace heap-corruption** — fault now diagnosed as
   userspace, not a kernel bug. `free_options` is being called
   with an uninitialised stack-resident struct. Next step is to
   identify the dhcpcd callsite (the rip-0x40935a function's
   exact name + caller chain). Likely an init/teardown path
   triggered by our F125 (epoll waitqueue) progression past where
   dhcpcd previously wedged. Auto-launch in rcS stays gated
   behind `/etc/oxide-dhcpcd-enable`.
2. **getty wedge past tcgetattr** — F126 closed the ioctl
   surface; F127 attempt (parked) showed getty still doesn't
   reach the login prompt under our /dev/ttyS0 console alias.
   Next step is debug-syscall trace to see which post-ioctl
   call wedges.
3. **K10 eBPF rest** — path-sensitive verifier (reg types,
   scalar bounds) → JIT; structural-only today.
4. **K13 DRM/KMS atomic modeset** — property tables + real
   atomic-commit.
5. **per-fd targeted epoll wakes** — current model is global
   broadcast; needs `Inode::wake_poll()` hook without dragging
   `sched` into `vfs`.
6. **file-backed mmap completeness** — phase 14 item; current
   path covers basic cases; less-common combinations (MAP_SHARED
   with non-anon backing) needs auditing.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch — `gh pr merge --merge` handles
  integration server-side
- Never delete branches (`git branch -d/-D`) — preserve all
- spec-lint clean before every commit + PR
- `debug-irq` cfg gates `[FAULT]` + `[FAULT] sigsegv:` + GPR dump.
  Use `FEATURES=debug-irq make qemu-x86` to see them.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick from "Open next". Item 1 (dhcpcd userspace) needs a
caller-chain trace via either gdb-attached qemu or a kernel-side
ELF backtracer keyed off the current task's frame chain — not a
kernel-completeness blocker, but the last piece before real DHCP.
