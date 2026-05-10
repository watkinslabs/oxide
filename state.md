# State 2026-05-10 (session 3)

## Branch

`F156-mm-linux-conformance` — PR #920 against `main`. HEAD = `1bde732`.

## What's working end-to-end (x86_64)

- `cargo run -p xtask -- qemu --arch x86_64` → `oxide login: root` → `~ #` shell prompt with cwd = `/root`.
- Shebang chain in execve runs `/etc/init.d/rcS` via `/bin/sh`.
- `access`/`stat`/`statx`/`chdir` resolve ext4 paths (was devfs-only).
- `/etc/login.defs` + `/root/.profile` → busybox login sets PATH so `ls`, `cat`, … work at first prompt.
- Single getty on tty1 (was tty1+tty2 fighting for the muxed serial).

## arm64 status — partial progress, fork now fires

`cargo run -p xtask -- qemu --arch aarch64` reaches `init-arm: spawned`,
busybox init reads `/etc/inittab` (`sys_read` returns 173 bytes), parses,
calls `sys_clone` (returns child pid 0x1000). After fork the syscall
trace stops — child likely faults during execve(`/etc/init.d/rcS`) or
the scheduler doesn't pick up the new task. Last syscall observed:
`pid=0xC0DE0002 nr=56 (clone) flags=0x11 a0=0x11`.

## Last-session fixes (HEAD..c4a5ff2)

- `1bde732` — **ungate NR_READ on arm**. The dispatch arm was
  `#[cfg(target_arch = "x86_64")]`, so every arm userspace read fell
  through to the legacy `dispatch::sys_read` stub returning
  `Err(Ebadf)` unconditionally. Init's `/etc/inittab` read now succeeds
  and the fork cascade proceeds. Plus warning sweep (intel_syntax
  redundant directives + unused imports).
- `e34d60d` — ext4 fallback in `sys_access`/`sys_stat`/`sys_statx`,
  `/etc/login.defs`, `/root/.profile`, drop tty2 from inittab.
- `e0ad8d3` — execve shebang chain (Linux fs/binfmt_script.c shape,
  `BINPRM_MAX_RECURSION=4`), `sys_chdir` ext4 fallback, `xtask qemu`
  defaults to `--features debug-all`.

## Open / next session

1. **arm64 post-clone silence** — find why the child task after
   `sys_clone` doesn't surface in the syscall trace. Check whether
   the cloned task is enqueued on the runqueue, whether
   `spawn_user_thread_with_vpid`'s arm path has a parity gap with
   x86, and whether the child's first syscall is actually entering
   `oxide_syscall_dispatch`. Add klog at child task's first scheduler
   pickup to confirm progress vs scheduler stall.
2. **Other arm-only dispatcher gates** — `NR_READ` was the obvious
   one; audit `kernel/src/syscall_glue.rs` for any remaining
   `#[cfg(target_arch = "x86_64")]` arms that should apply to both
   arches (only `NR_ARCH_PRCTL` is legitimately x86-only).
3. **Build warnings** — down from ~50 to ~38 distinct ones. Remaining
   are mostly cfg-gated unused imports in hal-aarch64/hal-x86_64
   under `#[cfg(target_os = "oxide-kernel")]` — fixes need to keep
   the imports under the same cfg as their use, not blanket remove.
4. **klog UART character drops under heavy syscall trace** — single
   bytes lost from contiguous `[INFO]/[SYS]` output when debug-all
   floods. Per-CPU spinlock or atomic ringbuf around klog::write_raw
   would fix it.

## First task next session

```
cargo run -p xtask -- qemu --arch aarch64
# observe: init forks at sys_clone (nr=56), trace goes silent.
# add klog in sched::spawn_user_thread_with_vpid + first scheduler
# pickup of cloned task to see whether the runqueue is processing it.
```
