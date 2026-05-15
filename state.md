# state — hand-off

Branch: main (clean). spec-lint clean, 1044 tests pass, both arches build.
**Shell works end-to-end** (login → bash → pwd/cd/ls/ls foo all functional).
Host CPU stays near-idle when guest is at prompt. target/ slim (~1.9G).

## Major milestones this session

1. **PMM poison panic at login fixed** (PR #1100, B27) — bisected through 78
   PRs to commit 452e810 (F49 vvar-shared-frame); the new VmaBacking::KernelFrame
   demand-page handler installed the kernel-owned vvar PA in user PT without
   bumping the per-page refcount. AS-drop's per-leaf dec_and_maybe_free freed
   the vvar frame, the timer-tick publisher poisoned the now-free page, the
   next alloc panicked. Fix: inc_ref callback plumbed through
   handle_page_fault_cow_rmap.

2. **Shell working end-to-end** (B28..B34, R02, F80..F81) — added cwd-resolve
   to every stat-family / chmod-family / access / readlink / chdir / utime
   syscall; openat falls back to ext4::rootfs::lookup_inode_any for non-mount
   paths; ext4 readdir walks all dir blocks (was: block 0 only); ext4
   Inode::readlink real (fast inline + slow data-block); seven duplicated
   cwd-resolve sites extracted into syscalls::pathresolve::resolve_cwd.

3. **Idle no longer burns host CPU** (PR #1102, B29) — `halt_forever`'s
   tight `hlt` loop never picked up a freshly-runnable task (e.g. shell
   woken by UART RX). Now does `schedule(); hlt;` in a loop. `tick_yield`
   (called by every polling syscall) was busy-spinning when the polling task
   was the sole runnable thing; now does `schedule(); hlt;` so each iteration
   waits for an IRQ.

4. **target/ 30G → 1.9G** (PR #1112, C73) — `profile.dev` had
   `debug = "full"` baking per-type DWARF into every hosted-test rlib +
   incremental cache. Switched to `line-tables-only` (still gets panic
   backtraces). 16× size reduction.

## All PRs this session

| PR | Branch | Summary |
|----|--------|---------|
| #1065..#1099 | F59..F79 + D11..D22 + B25/B26 | flag-honor sweep + audit refresh |
| #1100 | B27 | vvar: inc_ref on KernelFrame demand-page (PMM poison fix) |
| #1101 | B28 | stat family: cwd resolve |
| #1102 | B29 | idle + tick_yield park via hlt/wfi |
| #1103 | F80 | ext4 readlink (fast + slow symlink) |
| #1104 | B30 | access/readlink: cwd resolve + real readlink fall-through |
| #1105 | B31 | chdir: cwd resolve + ext4 dir fallback |
| #1106 | B32 | perms (chmod/chown family): cwd resolve + ext4 fallback |
| #1107 | B33 | utime: cwd resolve + ext4 fallback |
| #1108 | B34 | openat: ext4 fallback for directories |
| #1109 | F81 | ext4 readdir walks all dir blocks |
| #1110 | R02 | extract shared cwd path resolver |
| #1111 | D23 | doc(state) checkpoint |
| #1112 | C73 | profile.dev line-tables-only (target 30G → 1.9G) |

## Open next (priority order)

1. **mknodat/symlinkat write-side** — needs ext4 mknod + symlink-create
   helpers (F80 only added read-side). Wires real device-node creation
   and symlink creation from userspace.
2. **ext4 extent depth > 2** — current support is 1-2 levels; deeper trees
   (large files / fragmented dirs) silently fail.
3. **O_TMPFILE** — needed by modern systemd and many shell idioms.
4. **futex_waitv** — currently silent-0; modern glibc multi-futex wait.
5. **TLS endgame** — FS_BASE / TPIDR_EL0 setup at execve, per-task TLS
   block allocation (currently relies on arch_prctl post-exec).
6. **#NM-driven lazy FPU save/restore** on context switch (perf, not
   correctness).
7. **K10 eBPF verifier + JIT** (multi-PR, large).
8. **K13 DRM/KMS atomic + per-evdev registry** (large).
9. **virtio-net live driver** (types in, not driving an iface yet).
10. **netlink + nftables** = network management substrate.
11. **DHCP / DNS / TLS** = userspace work.

## Discipline notes carried over

- [[feedback_lint_gate_command]] — gate `cargo run -p xtask -- spec-lint`
  with `grep -q "^spec-lint: clean$"` BEFORE `git checkout -b`, not after.
- Branch per change; never delete merged branches; no Co-Authored-By
  trailers; PR-time CI is the only soak gate.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
make qemu-x86    # should reach `oxide login:` cleanly, host CPU idle
```

Pick from "Open next" or attack any new bug surfaced by interactive use
of the shell.
