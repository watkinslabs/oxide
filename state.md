# state — hand-off

Branch: main (clean). spec-lint clean, 1044 tests pass, both arches build.
Shell reaches a working prompt: login → bash, `pwd`/`cd`/`ls`/`ls /`/`ls .`
all functional after F80..R02. Host CPU no longer pegs (B29 idle+poll hlt).

## Critical fixes landed this segment

| PR | Branch | Summary |
|----|--------|---------|
| #1100 | B27 | vvar: inc_ref on KernelFrame demand-page (PMM poison panic) |
| #1101 | B28 | stat-family: resolve relative paths against cwd |
| #1102 | B29 | idle + tick_yield park via hlt/wfi (stop 100% host CPU) |
| #1103 | F80 | ext4 readlink (fast + slow symlink) |
| #1104 | B30 | access/readlink cwd resolve + real readlink fall-through |
| #1105 | B31 | chdir cwd resolve + ext4 dir fallback |
| #1106 | B32 | perms cwd resolve + ext4 fallback |
| #1107 | B33 | utime cwd resolve + ext4 fallback |
| #1108 | B34 | openat ext4 fallback (dirs/non-regular inodes) |
| #1109 | F81 | ext4 readdir walks ALL directory blocks (was: block 0 only) |
| #1110 | R02 | extract shared cwd path resolver (7 callsites → 1) |

## Earlier this run (kept for reference)

| range | summary |
|-------|---------|
| #1065..#1099 | F59..F79 syscall flag-honor sweep + audit refresh |
| #1100..#1110 | this segment — shell-bringup fixes |

## Open next

- mknodat/symlinkat: need ext4 mknod + symlink helpers (write-side)
- ext4 extent depth > 2 (currently 1-2 only)
- O_TMPFILE
- #NM-driven lazy FPU save/restore
- TLS endgame (FS_BASE/TPIDR_EL0 at execve, per-task TLS block)
- futex_waitv real multi-futex wait
- K10 eBPF verifier + JIT
- K13 DRM/KMS atomic + per-evdev registry
- virtio-net live driver
- netlink + nftables
- DHCP / DNS / TLS = userspace

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
