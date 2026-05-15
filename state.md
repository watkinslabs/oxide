# state — hand-off

Branch: main (clean). spec-lint clean, 1044 tests pass, both arches build.

## Most recent landed (one long autonomous run)

| PR | Branch | Summary |
|----|--------|---------|
| #1065 | F59 | landlock TRUNCATE on truncate/ftruncate |
| #1066 | F60 | wait4 WUNTRACED/WCONTINUED real |
| #1067 | F61 | record originating stop signal at SIGSTOP/TSTP/TTIN/TTOU/SIGTRAP |
| #1068 | F62 | setsockopt per-socket SockOpts storage |
| #1069 | F63 | PTRACE_INTERRUPT + LISTEN real |
| #1070 | F64 | mincore real per-page residency via MMU translate |
| #1072 | F65 | fcntl F_GETOWN/F_SETOWN |
| #1073 | F66 | priority: PRIO_PGRP + PRIO_USER walks |
| #1074 | B25 | hotfix proc.rs split |
| #1075 | F67 | recvfrom block + SO_RCVTIMEO |
| #1076 | F68 | accept block + SO_RCVTIMEO |
| #1078 | F69 | socket SOCK_CLOEXEC + SOCK_NONBLOCK |
| #1079 | F70 | accept4 flags |
| #1083 | F71 | sched_rr_get_interval real |
| #1088 | F72 | sendto block + SO_SNDTIMEO |
| #1090 | F73 | eventfd2 honour EFD_CLOEXEC/EFD_NONBLOCK |
| #1091 | F74 | timerfd/signalfd/inotify_init1 CLOEXEC+NONBLOCK |
| #1077/1080..1087/1089 | D11..D20 | state + audit doc refreshes |

## Audit (docs/kernel-audit.md) state

Bulk-sweep complete: rt_sig family, sigaltstack, clone3, mincore,
robust_list, rseq, mmap MAP_SHARED + file-backed + mremap + madvise,
memfd_create, pkey_*, fcntl F_GETFL/SETFL/SETLK/GETOWN, chroot, xattr,
inotify, eventfd/signalfd/timerfd, pidfd, io_uring, sendfile/splice/
copy_file_range, setsockopt round-trip, recvfrom/accept/sendto
blocking, SOCK_CLOEXEC/NONBLOCK on socket/accept4/eventfd2/timerfd/
signalfd/inotify, getpgid/setsid, /dev/console termios full, mount/
umount, openat2/faccessat2/preadv2/pwritev2/epoll_pwait2 aliases,
userfaultfd, close_range, sendmmsg/recvmmsg, /proc full surface,
SysV IPC + POSIX MQ + keyring, threading (CLONE_VM/THREAD).

K9 ptrace closes (INTERRUPT/LISTEN + GETFPREGS/SETFPREGS + wait4
WUNTRACED). K10 landlock substrate closes (path-syscall coverage
incl. truncate/ftruncate); eBPF verifier + JIT + seccomp_unotify
are the remaining K10. K14 vDSO closes.

## Open next

- mknodat/symlinkat: need ext4 mknod + symlink helpers
- #NM-driven lazy FPU save/restore
- TLS endgame: FS_BASE/TPIDR_EL0 at execve + per-task TLS block
- futex_waitv real multi-futex wait substrate
- ext4: dir>4KiB, extent depth>2, symlink read, O_TMPFILE
- K10 eBPF verifier + JIT (multi-PR)
- K13 DRM/KMS atomic + per-evdev registry
- DHCP client + DNS resolver + TLS = userspace work
- virtio-net live driver
- netlink + nftables = network management substrate

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
