# state — hand-off

Branch: F196-vendor-dropbear (in flight → PR pending).
Workspace: spec-lint clean, vfs tests 43/43, x86 smoke 16s, arm
smoke 20s.

## Endgame this session: working SSH login

Cross-built static-musl dropbear 2024.86 (vendor/dropbear/), wired
into rootfs at /sbin/dropbearmulti with /sbin/dropbear +
/sbin/dropbearkey hardlinks. rcS generates ed25519 host key,
brings eth0 up (10.0.2.15/24), backgrounds `dropbear -R -p
0.0.0.0:22`. QEMU forwards host TCP 2222 → guest 22.

## What this PR lands

1. **vendor/dropbear/build.sh + tools/fetch-dropbear.sh** — same
   pattern as dhcpcd / busybox. Static-musl x86_64 + aarch64.
2. **rootfs integration** — xtask drops the multibin + symlinks +
   mkdir /etc/dropbear; rcS starts dropbear when /sbin/dropbear
   exists.
3. **aarch64 FEAT_RNG probe (hwrng.rs)** — cortex-a72 is ARMv8.0,
   no MRS RNDR. Pre-fix, dropbearkey wedged for 6+ min on arm.
   Probe ID_AA64ISAR0_EL1[63:60] once; only emit MRS RNDR when
   the feature is implemented. Else `hw_random_u64` returns None
   and caller drops to LCG. Mirrors Linux's
   arch_get_random_seed_long false path on non-FEAT_RNG CPUs.
4. **vfs::Dentry::absolute_path()** — walks parent chain → bytes
   joined by `/`. 4 hosted tests (root, single, nested, deep).
5. **proclink::task_fd_path drive-by** — was returning basename
   only; now uses Dentry::absolute_path so `/proc/<pid>/fd/N`
   readlinks resolve to real absolute paths.
6. **execve refactor + sys_execveat AT_EMPTY_PATH** — pre-fix
   the execveat shim discarded dirfd+flags and forwarded an
   empty path to sys_execve, so fexecve(3) (libc maps to
   `execveat(fd, "", AT_EMPTY_PATH)`) always returned ENOENT.
   Now: sys_execve reads user path → execve_inner; sys_execveat
   resolves fd via fdt.get + Dentry::absolute_path → calls the
   same execve_inner with the resolved bytes. Path storage
   switched from `[u8;64] + usize` to `Vec<u8>` end-to-end;
   resolve_shebang_chain signature updated to match.

## Verified end-to-end

- ssh -p 2222 alice@127.0.0.1 → TCP 3WHS completes; dropbear logs
  "Child connection from 10.0.2.2:..."; fexecve succeeds (was
  ENOENT pre-F196). Banner write still fails (next bug, below).
- spec-lint clean; vfs 43/43, smoke x86 16s + arm 20s.
- No SSH session yet (session-fd EBADF, see open).

## Open — next bug to chase

**`Exit before auth: Error writing: Bad file descriptor`**
After dropbear's child fexecves itself, it tries to write the
SSH banner to its session socket and gets EBADF. Likely
suspects:

- dup2 not surviving fexecve cleanly (the session fd is moved
  to a specific slot pre-exec).
- O_CLOEXEC on the fd dropbear expects to keep open after exec.
- Our close_on_exec sweep dropping a non-cloexec fd.

Repro: vendor/dropbear/dropbearmulti-x86_64 is in rootfs; boot,
`ssh -p 2222 alice@127.0.0.1`. Watch `[36] Jan 01 ...
Child connection / Exit before auth ...` on the serial.

## Out-of-scope (deferred for later PRs)

- TCP_INFO field completeness past tcpi_total_retrans (F188).
- SCM_RIGHTS over SOCK_STREAM (F189 covers SOCK_DGRAM only).
- AF_NETLINK ROUTE / sock_diag completeness (D45 gap analysis #1).
- Outbound IPv6 NDP NS-on-cache-miss (F180c follow-on).
