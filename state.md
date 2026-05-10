# State 2026-05-10 (session 2)

## Branch

`F156-mm-linux-conformance` — PR #920 against `main`. ~30 commits, all pushed (HEAD = `e34d60d`).

## What's working end-to-end (x86_64)

- `cargo run -p xtask -- qemu --arch x86_64` → boot to `oxide login: root` → `~ #` shell prompt with cwd = `/root` (chdir to ext4 paths now resolves).
- Shebang chain in execve: busybox init → `#!/bin/sh /etc/init.d/rcS` resolves and runs.
- `access(/etc/init.d/rcS, R_OK)` succeeds (was the silent killer of "can't open … No error information").
- `stat`/`lstat`/`statx` resolve ext4 dirs + symlinks (was devfs-only).
- `/etc/login.defs` + `/root/.profile` ship — busybox login sets PATH so `ls`, `cat`, … work from first prompt.
- Single getty on tty1 (was double-attached on tty1+tty2 fighting for the muxed serial).
- Hosted tests: 1015+ pass, 0 fail. Both arches build, spec-lint clean.

## Last-session fixes (this session, on top of 2026-05-10 morning state)

- `e34d60d` — ext4 fallback in `sys_access`/`sys_stat`/`sys_statx` + `/etc/login.defs` + `/root/.profile` + drop `tty2` from inittab.
- `e0ad8d3` — execve shebang chain (Linux `fs/binfmt_script.c` shape, `BINPRM_MAX_RECURSION`=4) + `sys_chdir` ext4 fallback + `xtask qemu` defaults to `--features debug-all`.

## Open / next session

1. **aarch64 boot to login parity** — *blocker*. busybox init spawns (`init-arm: spawned`), opens fd 3 successfully, then `sys_read(fd=3)` returns `-EBADF` (rv=fffffffffffffff7). Init then enters sigsuspend/wait4/nanosleep idle loop with no clone/execve of rcS or getty. Root cause likely a procfs or pseudo-fs inode whose `read` returns Ebadf — busybox init reads `/proc/cmdline` or similar early. Needs targeted klog in `kernel_sys_read` to identify the failing fd's path/inode type. The new `lookup_inode_any` helper on x86 may also be at play; verify arm openat path.
2. **`xtask rootfs --arch aarch64` is stale** — kernel/blobs/rootfs-aarch64.img dated `9-May-2026 21:25` while x86 is `10-May-2026`. The MCP qemu start path doesn't run rootfs build. Ensure `cmd_qemu` builds rootfs for the chosen arch (it does call `cmd_rootfs(rest)` per `image_qemu.rs:57`, but check if MCP server bypasses that).
3. **Cosmetic but useful:** klog character drops under heavy syscall trace. Multiple writers to UART racing → `n` and other bytes dropped from contiguous output. Consider buffering the `[SYS]/[INFO]` lines with a per-CPU spinlock or atomic ringbuf so only complete lines hit the UART.
4. **Tty hosts the same console twice** — fixed at the rootfs level by dropping tty2 from inittab; if we ever want multi-tty, need to bind tty2 to a separate console device or virtual console.

## First task next session

```
cargo run -p xtask -- qemu --arch aarch64
# observe: init-arm spawns, opens fd 3, reads return -EBADF, idle loop
# instrument: klog in kernel_sys_read for fd whose file.read() returns Ebadf
# print path/file_type so we see which inode is the culprit
```

If x86 needs re-verification: `cargo run -p xtask -- qemu --arch x86_64`, login as root, run `/bin/ls` (full path), then `. /etc/profile`, then `ls` — should all work.
