# state — hand-off

Branch: main (clean). K1..K10 substrate landed; K14 vDSO complete;
K9 ptrace complete (INTERRUPT+LISTEN real); K10 landlock enforce on
openat/unlinkat/mkdirat/rmdir/link/linkat/rename*/truncate/ftruncate.

## Most recent landed (continuation segment)

| PR | Branch | Summary |
|----|--------|---------|
| #1065 | F59 | landlock TRUNCATE check on sys_truncate/ftruncate |
| #1066 | F60 | wait4 WUNTRACED/WCONTINUED real (take_child_stop_event) |
| #1067 | F61 | record originating stop signal at SIGSTOP/TSTP/TTIN/TTOU/SIGTRAP |
| #1068 | F62 | setsockopt: per-socket SockOpts storage for SOL_SOCKET + TCP_NODELAY |
| #1069 | F63 | PTRACE_INTERRUPT (synthetic SIGSTOP + stop_pending) + LISTEN real |
| #1070 | F64 | sys_mincore real per-page residency via arch MMU translate |

## Still open (pick from here)

- mknodat / symlinkat: need ext4 mknod + symlink helpers (bigger)
- #NM-driven lazy FPU save/restore on context switch (perf)
- SO_SNDBUF/SO_RCVBUF semantic enforcement on data path
- TLS endgame: FS_BASE/TPIDR_EL0 at execve, per-task TLS block
- K10 eBPF verifier + JIT (multi-PR)
- K13 DRM/KMS atomic modesetting + evdev per-device registry

## First task next session

Pick any item above. State: spec-lint clean, 1044 tests pass, both
arches build.

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
