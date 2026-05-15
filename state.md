# state — hand-off

Branch: main (clean). Continuing autonomous K-rollout work; all merges
through PRs per discipline. spec-lint clean, 1044 tests pass.

## Most recent landed (continuation)

| PR | Branch | Summary |
|----|--------|---------|
| #1065 | F59 | landlock TRUNCATE check on truncate/ftruncate |
| #1066 | F60 | wait4 WUNTRACED/WCONTINUED real (take_child_stop_event) |
| #1067 | F61 | record originating stop signal at SIGSTOP/TSTP/TTIN/TTOU/SIGTRAP |
| #1068 | F62 | setsockopt: per-socket SockOpts storage for SOL_SOCKET + TCP_NODELAY |
| #1069 | F63 | PTRACE_INTERRUPT + LISTEN real |
| #1070 | F64 | sys_mincore real per-page residency via MMU translate |
| #1072 | F65 | fcntl F_GETOWN/F_SETOWN real via per-File owner cell |
| #1073 | F66 | priority: PRIO_PGRP + PRIO_USER walking |
| #1074 | B25 | hotfix: extract priority syscalls (proc.rs over cap) |
| #1075 | F67 | recvfrom: block + SO_RCVTIMEO + MSG_DONTWAIT + O_NONBLOCK |
| #1076 | F68 | accept: block + SO_RCVTIMEO + O_NONBLOCK |

## Open next

- sendto/sendmsg: SO_SNDTIMEO + nonblock parity with recvfrom
- mknodat/symlinkat: need ext4 mknod + symlink helpers
- #NM-driven lazy FPU save/restore on context switch
- TLS endgame: FS_BASE/TPIDR_EL0 at execve, per-task TLS block
- K10 eBPF verifier + JIT (multi-PR)
- K13 DRM/KMS atomic modesetting + evdev per-device registry
- audit refresh: docs/kernel-audit.md is stale (clone3, rt_sig*,
  ICANON, prlimit64 all real now)

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
