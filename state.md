# state — hand-off

Branch: main (clean). spec-lint clean, 1044 tests pass, both arches build.

## Most recent landed

| PR | Branch | Summary |
|----|--------|---------|
| #1065 | F59 | landlock TRUNCATE on truncate/ftruncate |
| #1066 | F60 | wait4 WUNTRACED/WCONTINUED real |
| #1067 | F61 | record originating stop signal |
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
| #1077/1080/1081/1082/1084 | D12..D16 | state + audit doc sweeps |

## Audit (docs/kernel-audit.md) refresh

D13/D14/D15/D16 marked ✅: rt_sig family, sigaltstack, clone3, mincore,
robust_list, rseq, mmap MAP_SHARED + file-backed + mremap + madvise,
memfd_create, pkey_*, fcntl F_GETFL/SETFL/SETLK/GETOWN, chroot, xattr,
inotify, eventfd/signalfd/timerfd, pidfd, io_uring, sendfile/splice/
copy_file_range, setsockopt round-trip, recvfrom/accept blocking,
SOCK_CLOEXEC/NONBLOCK, getpgid/setsid, /dev/console termios family
(ECHO/ICRNL/ONLCR/ISIG/VEOF/...), TIOCSCTTY, mount/umount, openat2/
faccessat2/preadv2/pwritev2/epoll_pwait2 aliases, userfaultfd,
close_range, sendmmsg/recvmmsg.

## Open next

- sendto/sendmsg: SO_SNDTIMEO + nonblock parity with F67/F68
- mknodat/symlinkat: needs ext4 mknod + symlink helpers
- #NM-driven lazy FPU save/restore
- TLS endgame: FS_BASE/TPIDR_EL0 at execve, per-task TLS block
- futex_waitv real multi-futex wait
- pthread_create / CLONE_THREAD real same-AS thread
- K10 eBPF verifier + JIT (multi-PR)
- K13 DRM/KMS atomic + per-evdev registry
- DHCP client + DNS resolver + TLS = userspace work

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
