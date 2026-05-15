# Kernel stub audit

DRAFT (living). Dep:`00`,`15`.

Purpose: complete inventory of stubbed / half-implemented / missing
syscalls and kernel features so we can do a directed completeness
sweep instead of patching one ENOSYS at a time when a real-libc
program (bash, busybox, util-linux) chokes on it. Filename has no
numeric prefix because it's a working-doc index, not a versioned
spec.

Source: `kernel/src/syscall_glue*.rs`, `kernel/src/dev_*.rs`,
`kernel/src/syscall_compat.rs`. 136 syscall handlers across ~6700
LOC scanned for `Errno::Enosys`, `// v1`, `// stub`, `// minimal`,
`// rides a follow-up`, `accept-and-no-op`, "future PR".

**2026-05-08 refresh:** session-38 sweep + subsequent PRs landed
PR-B, PR-C, PR-D, PR-E, PR-F, PR-H wholesale. The only remaining
sweep gap was PR-G mmap completeness (MAP_SHARED, MAP_FIXED, addr
hint, file-backed mmap).

**2026-05-09 refresh:** F89 closed PR-G's MAP_FIXED via the munmap-
then-insert pattern; MAP_SHARED + addr hint had landed in F60. All
sweep PRs A..I are now closed. File-backed mmap is the only
remaining sub-item, gated on VFS+pagecache wiring.

**2026-05-09 rollin pass (F89..F97):** nine PRs landed closing
audit items wholesale.
  * F89 closes audit PR-G (MAP_FIXED real via munmap-then-insert).
  * F90 lands xattr family real per-inode overlay.
  * F92 cap-gates setuid/setgid family + capbset (replaces is_root() lies).
  * F93 cap-aware kill/tgkill/pidfd_send_signal (CAP_KILL + uid match).
  * F94 real inotify watch storage + IN_MODIFY firing via vfs::File hook.
  * F95 real chroot via per-task root prefix in devfs::lookup.
  * F96 fanotify_mark forwarded to inotify substrate.
  * F97 real UTS namespace (per-task hostname via CLONE_NEWUTS).

**2026-05-15 refresh (F59..F70 + B25):** 11 PRs landed closing
prior 🟥/🟡 entries:
  * F59 landlock TRUNCATE on sys_truncate/ftruncate.
  * F60 wait4 WUNTRACED + WCONTINUED real (take_child_stop_event).
  * F61 originating stop signal recorded at SIGSTOP/TSTP/TTIN/TTOU/SIGTRAP.
  * F62 setsockopt/getsockopt: per-socket SockOpts cells for SOL_SOCKET
    ints (REUSEADDR/REUSEPORT/KEEPALIVE/BROADCAST/SND/RCVBUF/PRIORITY/
    MARK/LINGER/SND/RCVTIMEO) + TCP_NODELAY.
  * F63 PTRACE_INTERRUPT (synthetic SIGSTOP + stop_pending) + LISTEN real.
  * F64 mincore real per-page residency via arch MMU translate.
  * F65 fcntl F_GETOWN/F_SETOWN: per-File owner cell.
  * F66 priority: PRIO_PGRP + PRIO_USER walks (was PROCESS-only).
  * B25 hotfix: extract priority syscalls (proc.rs 1010>1000 cap).
  * F67 recvfrom: block + SO_RCVTIMEO + MSG_DONTWAIT + O_NONBLOCK.
  * F68 accept: block + SO_RCVTIMEO + O_NONBLOCK.
  * F69 socket(2): honour SOCK_CLOEXEC + SOCK_NONBLOCK at creation.
  * F70 accept4 flags arg honoured (SOCK_CLOEXEC / SOCK_NONBLOCK).

Stale 🟥 entries now ✅ (per-subsystem table needs in-place sweep):
  rt_sigsuspend / rt_sigtimedwait / rt_sigqueueinfo / rt_tgsigqueueinfo
  (signal.rs), sigaltstack, clone3, mincore, robust_list (F65 era),
  rseq, ICANON (live::tty), F_GETOWN/F_SETOWN. PRIO_PGRP/PRIO_USER,
  SO_REUSEADDR/REUSEPORT/etc.

**2026-05-14 refresh (B14..B24):** ARM completeness sweep — `faccessat` ABI mapping fix (B15), `statx` mask STATX_BASIC_STATS + stx_blocks (B16), `statx`/`newfstatat` ARM ABI routing (B17, B21 real `sys_newfstatat`), ARM EL0 IRQ delivery (B14), ext4 `Ext4FileInode` lazy reads (B21), ARM signal-dispatch: mask delivered signal + `rt_sigreturn_arm` SP offset 40→32 + SIG_FRAME_BYTES 40→48 for AAPCS64 alignment (B22). No new syscall surface added; existing surface now correct on aarch64. Makefile `FEATURES=` extras fix (B24). See `## Rollout plan 2026-05-14` at file end for prioritized open work.

**2026-05-09 syscall stub-sweep (F63..F84):** at user direction, a
wholesale pass across `syscall_compat.rs` + `syscall_glue.rs` removed
~20 silent-0 / synthetic-success lies and replaced them with real
storage-backed impls or honest ENOSYS. PRs #783..#804 landed:
clone3 parity, real Creds (uid/gid/groups/caps), real robust_list,
real syslog/dmesg, real setdomainname, real fallocate, real
pidfd_getfd, real POSIX timers, real prctl (NO_NEW_PRIVS, KEEPCAPS,
PDEATHSIG, SUBREAPER, CAPBSET), real utimensat/utimes/utime via
inode_times overlay, real flock with vfs::File Drop hook, real
process_vm_readv/writev, real keyring (single global ring), real
mq_notify + mq_getsetattr, real personality, real get_mempolicy,
real chmod/chown family with mode + uid/gid overlay, honest ENOSYS
for futex_waitv / fanotify_mark / landlock_add_rule /
landlock_restrict_self / fsconfig / move_mount / mount_setattr.
The kernel's syscall surface is now substantially less mendacious —
remaining silent-0 entries (NR_VHANGUP, NR_READAHEAD, NR_FADVISE64,
NR_SYNC_FILE_RANGE, NR_SYNCFS, NR_MLOCK2, NR_CACHESTAT, NR_PKEY_*,
NR_PROCESS_MADVISE, NR_PROCESS_MRELEASE, NR_KCMP, NUMA family) are
honest no-ops on the current substrate (no swap, no MPU/MPK, single UMA
node, no pagecache).

## Status legend

| code | meaning |
|---|---|
| ✅  | real impl, complete enough for distro programs |
| 🟡  | partial — works for the common path but missing edge cases |
| 🟥  | stub (returns 0 / ENOSYS / no-op) |
| ❌  | missing — no impl at all |

## TL;DR — what blocks bash + login + util-linux right now

All sweep PRs A..I are closed as of F89 (2026-05-09). MAP_SHARED
+ addr hint landed in F60; MAP_FIXED via munmap-then-insert in F89.
File-backed mmap is the last sub-item; gated on VFS+pagecache
wiring (`17§5`).

PR-B (termios + line discipline on /dev/console), PR-C (job
control), PR-D (signal completeness), PR-E (real threading),
PR-F (`/proc` completion), PR-H (modern fd-creating syscalls)
are **done** — see the per-subsystem table below for the file
references.

## Subsystem table

### 1. TTY + line discipline + termios

| feature | state | notes |
|---|---|---|
| pty pair termios | ✅ | `crates/tty/src/pty.rs` — c_iflag/c_oflag/c_lflag with ICANON/ECHO/ISIG/ICRNL/ONLCR. Used by `/dev/ptmx`. |
| /dev/console termios | ✅ | live tty termios via crates/tty/src/live.rs. |
| ICANON (line buffering) | ✅ | `crates/tty/src/live.rs` cooked-mode line buffer with VERASE/VKILL/VEOF. |
| ECHO toggle | ✅ | live tty cooked-mode honours c_lflag ECHO. |
| ICRNL on input | ✅ | per-fd c_iflag honoured. |
| ONLCR on output | ✅ | per-fd c_oflag ONLCR honoured. |
| ISIG (Ctrl-C → SIGINT) | ✅ | VINTR/VQUIT/VSUSP signal generation per c_cc. |
| VEOF/VERASE/VKILL/VINTR | ✅ | c_cc array applied in cooked-mode line buffer. |
| TIOCGWINSZ / TIOCSWINSZ | ✅ | per-tty winsize storage. |
| TIOCSCTTY (control terminal) | ✅ | per-Task ctty_dev field; setsid implicit-detach. |

### 2. Job control + process groups

| feature | state | notes |
|---|---|---|
| getpgid/setpgid/getpgrp | ✅ | Task.pgid field; setpgid + getpgrp wired. |
| setsid (session leader) | ✅ | Task.sid + setsid syscall. |
| getsid | ✅ | |
| Foreground process group on tty | ✅ | TIOCGPGRP/TIOCSPGRP on pty + console. |
| tcsetpgrp / tcgetpgrp | 🟡 | Works for pty fds via TIOCGPGRP/TIOCSPGRP arms (`syscall_glue_ioctl.rs:128`). Missing for console. |
| `cmd &` background jobs | 🟡 | Works in toy sh (P5-12) but no real pgid → bash's `fg`/`bg` won't work. |

### 3. Signals

| feature | state | notes |
|---|---|---|
| rt_sigaction | ✅ | `syscall_glue_proc.rs:142` — per-task sigactions table; sa_handler/sa_flags/sa_restorer/sa_mask. |
| rt_sigprocmask | ✅ | `syscall_glue_proc.rs:191` |
| rt_sigreturn | ✅ | `sig_dispatch.rs` — restores frame after handler. |
| rt_sigsuspend | ✅ | `signal.rs:739`. |
| rt_sigtimedwait | ✅ | `signal.rs:770`. |
| rt_sigqueueinfo / rt_tgsigqueueinfo | ✅ | `signal.rs:855/870` real siginfo enqueue. |
| sigaltstack | ✅ | `signal.rs:684` real per-task stack. |
| signal frame for fault (SIGSEGV/SIGBUS) | ✅ | F30 added 10-signal core dump path. |
| Real-time signals (32+) | ✅ | F35 per-RT-sig VecDeque queue. |
| restart_syscall (-EINTR loop) | 🟡 | `syscall_compat.rs:43` returns EINTR; not real restart. |
| Default actions (Term/Core/Ign/Stop/Cont) | ✅ | F61 records originating stop signal for wait4 WUNTRACED. |
| wait4 WUNTRACED / WCONTINUED | ✅ | F60 take_child_stop_event. |
| PTRACE_INTERRUPT / LISTEN | ✅ | F63. |

### 4. Threading + clone

| feature | state | notes |
|---|---|---|
| fork (clone with no flags) | ✅ | `syscall_glue.rs:228` — copies AS w/ COW-ish via demand fault. |
| clone with CLONE_VM/CLONE_THREAD | ✅ | `clone.rs:57` Arc-shared AS; CLONE_THREAD inherits tgid. |
| clone3 | ✅ | `proc.rs:82` real struct clone_args parse + dispatch. |
| pthread_create | ✅ | musl flag set (VM|FS|FILES|SIGHAND|THREAD|SETTLS) all wired; SETTLS via arch_prctl post-clone. |
| set_thread_area | n/a | i386-only; x86_64 uses arch_prctl(ARCH_SET_FS) — real. |
| gettid | ✅ | Returns kernel tid. tgid separate (CLONE_THREAD-aware). |
| set_tid_address | ✅ | `syscall_glue_proc.rs:34` stores in `clear_child_tid`. CLONE_CHILD_CLEARTID wakeup-on-exit not done. |
| futex FUTEX_WAIT/WAKE | ✅ | `kernel/src/futex.rs` (P3a). |
| futex_waitv | 🟡 | ENOSYS forces glibc to fall back to per-futex FUTEX_WAIT loop. Real multi-futex wait substrate pending. |
| robust_list | ✅ | Real set/get_robust_list against per-Task slot. |
| rseq (restartable sequences) | ✅ | Real `sys_rseq` + rseq_writeback per F86. |

### 5. Memory management

| feature | state | notes |
|---|---|---|
| mmap MAP_PRIVATE \| MAP_ANONYMOUS | ✅ | Demand-paged. |
| mmap MAP_SHARED | ✅ | F60 era — VmaBacking::File backing. |
| mmap MAP_FIXED | ✅ | F89 munmap-then-insert. |
| mmap file-backed (MAP_PRIVATE) | ✅ | K6 file-backed mmap via PageCache (F26). |
| mprotect per-PTE | ✅ | `pmm::user_as::mprotect_pages` walks live PTs + TLB flush. |
| mremap | ✅ | `proc.rs:538` MAYMOVE+FIXED via AddressSpace::mremap. |
| madvise | ✅ | `proc.rs:153` DONTNEED/FREE/REMOVE drop+refault. |
| mlock / mlockall | ✅ | No-swap substrate → accept-and-no-op semantically correct. |
| mincore | ✅ | F64 per-page residency via arch MMU translate. |
| memfd_create / memfd_secret | ✅ | `anonfd.rs:36`. |
| brk | ✅ | |
| pkey_alloc/pkey_free/pkey_mprotect | ✅ | `misc.rs:59` bitmap + delegate to mprotect. |

### 6. Filesystem + VFS

| feature | state | notes |
|---|---|---|
| openat / open | ✅ | Recently fixed `.`/`..` resolution (B08). |
| close | ✅ | |
| read / write | ✅ | |
| pread64 / pwrite64 | ✅ | |
| readv / writev | ✅ | |
| preadv / pwritev | ✅ | (P9-17) |
| preadv2 / pwritev2 | ✅ | aliased to preadv/pwritev (PR-H). |
| sendfile | ✅ | `sched::xfer::sys_sendfile` staging-buffer loop. |
| splice / tee / vmsplice | ✅ | `sched::xfer::sys_splice/tee/vmsplice`. |
| copy_file_range | ✅ | `sched::xfer::sys_copy_file_range`. |
| dup / dup2 / dup3 | 🟡 | dup/dup2 work; dup3 unclear (`syscall_glue_fs.rs:152`). |
| pipe / pipe2 | 🟡 | `dev_pipe.rs` minimal — non-blocking on empty/full (Eagain). Real blocking with WaitQueue rides P3-01b. |
| fcntl F_GETFD/F_SETFD | 🟡 | FD_CLOEXEC tracked. |
| fcntl F_GETFL/F_SETFL | ✅ | O_APPEND + O_NONBLOCK toggles tracked. |
| fcntl F_DUPFD | ✅ | F_DUPFD + F_DUPFD_CLOEXEC. |
| fcntl F_SETLK / F_GETLK | ✅ | F28 POSIX + OFD record locks via fs::posix_lock. |
| fcntl F_GETOWN / F_SETOWN | ✅ | F65 per-File owner cell. |
| fcntl F_GETPIPE_SZ / F_SETPIPE_SZ | 🟡 | Returns 4096; no real resize. |
| getdents64 | ✅ | (overlay fix recent) |
| stat / fstat / lstat / fstatat | ✅ | |
| statx | 🟡 | check — modern programs prefer this. |
| access / faccessat | 🟡 | |
| faccessat2 | ✅ | aliased to faccessat (PR-M). |
| openat2 | ✅ | aliased to openat (PR-M); RESOLVE_BENEATH advisory. |
| chmod/fchmod/fchmodat | 🟡 | |
| chown/fchown/fchownat | 🟡 | |
| utimes / utimensat | 🟡 | `futimesat` accept-and-no-op. |
| chdir / fchdir | ✅ | per-task cwd |
| getcwd | ✅ | |
| chroot | ✅ | F95 per-task root prefix in devfs::lookup. |
| mount / umount | ✅ | F110 tmpfs mount backend. |
| pivot_root | 🟥 | ENOSYS. |
| ext4 RO read | ✅ | |
| ext4 RW + JBD2 | 🟡 | (P7b) — works for small files. |
| ext4 dir > 4 KiB | 🟥 | `kernel/src/dev_ext4.rs:140` only first dir block read. |
| ext4 extent depth >2 | 🟥 | Depth 1-2 read+write (P9-07). Depth 3+ missing. |
| ext4 hard links | 🟡 | (P9-24) |
| ext4 symlinks | 🟥 | Maybe missing. |
| xattr (get/set/list/remove) | ✅ | F90 per-inode xattr overlay. |
| inotify / fanotify | ✅ | F94 inotify real watch+IN_MODIFY; F96 fanotify_mark→inotify. |
| O_TMPFILE | 🟥 | Unclear. |
| /tmp tmpfs | ✅ | (P3-pipe) |
| /proc | 🟡 | Partial (see /proc table below). |
| /sys | 🟡 | (P9-13/P9-31) — net subset. |
| /dev | ✅ | (B07 multi-VT) |

### 7. Modern fd-creating syscalls

| feature | state | notes |
|---|---|---|
| eventfd / eventfd2 | ✅ | `anonfd.rs:14` real counting eventfd. |
| signalfd / signalfd4 | ✅ | `signalfd.rs:56`. |
| timerfd_create / settime / gettime | ✅ | `timerfd.rs:103/128/181`. |
| epoll_create / epoll_ctl / epoll_wait | ✅ | `dev_epoll.rs` (P9-21 poll readiness) |
| epoll_pwait | 🟡 | |
| epoll_pwait2 | ✅ | aliased to epoll_pwait. |
| inotify_init / inotify_add_watch | 🟡 | dev_inotify exists. |
| pidfd_open | ✅ | dev/pidfd. |
| pidfd_send_signal | ✅ | F93 cap-aware kill/tgkill/pidfd_send_signal. |
| pidfd_getfd | ✅ | F63..F84 sweep landed real pidfd_getfd. |
| close_range | ✅ | real range-close in fd_table. |
| userfaultfd | ✅ | `fs::userfaultfd::sys_userfaultfd` + UFFDIO ioctls (P28a). |
| io_uring (setup/enter/register) | ✅ | `kernel/src/io_uring.rs` real setup+enter (register stub). |
| memfd_create | ✅ | `anonfd.rs:36`. |

### 8. Network

| feature | state | notes |
|---|---|---|
| AF_INET UDP | ✅ | |
| AF_INET TCP (listen/accept/connect) | ✅ | (P8-08..P8-10) |
| AF_UNIX SOCK_STREAM (socketpair) | ✅ | (P8-11) |
| AF_UNIX path-bound (bind/listen) | ✅ | (P8-15) |
| AF_INET6 | 🟡 | Types in (P8-17) but not socket-layer wired. |
| ICMP echo (loopback) | ✅ | |
| ARP | 🟡 | (P8-18) types only — no real driver to drive. |
| NDP | 🟡 | (P8-20) types only. |
| Real NIC driver (virtio-net) | 🟥 | Types in (P12-02), not live. |
| DHCP client | 🟥 | Missing entirely. |
| DNS resolver | 🟥 | musl has client; no /etc/resolv.conf consumed. |
| TLS | 🟥 | No openssl/rustls integration. |
| sendmmsg / recvmmsg | ✅ | PR-G wrapper around sendto/recvfrom. |
| netlink (route/genl) | 🟥 | Missing. |
| iptables / nftables | 🟥 | No netfilter. |
| getsockopt / setsockopt | ✅ | F62 per-socket SockOpts cells + TCP_NODELAY. |
| recvfrom / accept blocking | ✅ | F67/F68 SO_RCVTIMEO + MSG_DONTWAIT + O_NONBLOCK. |
| socket SOCK_CLOEXEC / SOCK_NONBLOCK | ✅ | F69 + F70 accept4 flags. |

### 9. /proc completion

| path | state | notes |
|---|---|---|
| /proc/self/maps | 🟡 | Verify — bash + glibc read. |
| /proc/self/status | 🟡 | |
| /proc/self/cmdline | 🟡 | |
| /proc/self/exe (symlink) | 🟥 | |
| /proc/self/environ | 🟥 | |
| /proc/self/fd/* | 🟥 | |
| /proc/self/mountinfo | 🟥 | |
| /proc/self/stat | 🟡 | |
| /proc/cpuinfo | 🟡 | |
| /proc/meminfo | 🟡 | |
| /proc/uptime | 🟡 | |
| /proc/loadavg | 🟡 | |
| /proc/version | 🟡 | "Linux version 5.15.0-oxide" present (verified) |
| /proc/<pid>/* for live tasks | 🟡 | |
| /proc/sys/kernel/* | 🟡 | hostname, ostype, osrelease |
| /proc/net/{dev,tcp,udp,route,arp} | 🟡 | (P9-02/P9-31) |
| /proc/modules | ✅ | (P10-06) |
| /proc/mounts | 🟡 | (P9-14) — hardcoded 5-line string |
| /proc/filesystems | 🟥 | |
| /proc/devices | 🟥 | |
| /proc/partitions | 🟥 | |
| /proc/cgroups | 🟥 | |

### 10. IPC

| feature | state | notes |
|---|---|---|
| SysV shm/sem/msg | 🟥 | ENOSYS family. |
| POSIX MQ | 🟥 | ENOSYS family. |
| keyring | 🟥 | ENOSYS family. |
| futex | ✅ | (PR-B before sweep) |
| eventfd | 🟡 | |
| Unix-socket SCM_RIGHTS fd-passing | 🟡 | Verify — Wayland + dbus require. |
| Unix-socket SCM_CREDS | 🟥 | Deferred (P9-18 comment). |

### 11. Process management

| feature | state | notes |
|---|---|---|
| getpid / getppid | ✅ | |
| getuid / geteuid / getgid / getegid | ✅ | |
| setuid family | 🟥 | accept-and-no-op (`syscall_compat.rs:27`). |
| getgroups / setgroups | 🟥 | accept-and-no-op. |
| capget / capset | 🟥 | accept-and-no-op. |
| prctl | 🟡 | Some entries; PR_SET_NAME / PR_SET_PDEATHSIG unclear. |
| arch_prctl ARCH_SET_FS | ✅ | (essential for musl pthreads TLS) |
| arch_prctl ARCH_GET_FS | 🟥 | `syscall_glue.rs:585` returns 0. |
| getrlimit / setrlimit | 🟡 | per-task slot honored; not enforced anywhere. |
| prlimit64 | 🟡 | Stub (returns 0). |
| sysinfo | 🟡 | Minimal — uptime + zeros (`syscall_glue_proc.rs:493`). |
| sched_getaffinity | 🟡 | "single-bit mask covering CPU 0" |
| sched_setaffinity | 🟥 | Probably no-op. |
| clock_nanosleep | 🟡 | "ignores clk_id + flags" (`syscall_glue_proc.rs:743`). |
| nanosleep | 🟡 | |
| getitimer / setitimer | 🟡 | ITIMER_REAL only. |

### 12. Privileged ops (intentional refuse)

| feature | state | notes |
|---|---|---|
| reboot | 🟥 | EPERM (kernel-only path) |
| mount/umount/chroot | 🟥 | EPERM |
| init_module/finit_module/delete_module | 🟥 | EPERM (kernel modules disabled in current userspace) |
| kexec_load | 🟥 | EPERM |
| iopl/ioperm | 🟥 | EPERM |
| adjtimex / clock_adjtime | 🟥 | EPERM |
| swapon/swapoff | 🟥 | ENOSYS |

### 13. Modern Linux extras (mostly ENOSYS)

| feature | state | notes |
|---|---|---|
| seccomp | 🟥 | ENOSYS |
| bpf | 🟥 | ENOSYS |
| perf_event_open | 🟥 | ENOSYS |
| landlock | 🟥 | ENOSYS family |
| unshare / setns | 🟥 | ENOSYS — namespaces missing entirely |
| pivot_root | 🟥 | ENOSYS |
| name_to_handle_at / open_by_handle_at | 🟥 | ENOSYS |
| io_uring | 🟥 | ENOSYS |
| process_vm_readv / writev | 🟥 | ENOSYS |
| kcmp | 🟥 | ENOSYS |

## Sweep order — done vs open

| PR | Subsystem | Status | Reference |
|----|-----------|--------|-----------|
| A  | this audit | ✅ | this file |
| B  | termios + line discipline on /dev/console | ✅ done | `kernel/src/tty.rs:240-450`, `crates/tty/src/pty.rs`, `kernel/src/syscall_glue_ioctl.rs:14-200` |
| C  | Job control (setpgid/getpgid/setsid/getsid/getpgrp + tcsetpgrp) | ✅ done | `kernel/src/syscall_glue_proc.rs:570-650` |
| D  | Signal completeness (rt_sigsuspend / sigaltstack / rt_sigtimedwait / rt_sigqueueinfo) | ✅ done | `kernel/src/syscall_glue_signal.rs:407-561` |
| E  | Real threading (clone CLONE_VM\|CLONE_THREAD, clone3, gettid distinct) | ✅ done | `kernel/src/syscall_glue_clone.rs`, `kernel/src/syscall_glue_proc.rs:25-118` |
| F  | /proc completion (`/proc/self/{maps,status,cmdline,exe,fd,environ,stat}`, `/proc/{cpuinfo,meminfo,uptime,loadavg}`) | ✅ done | `kernel/src/procfs.rs`, `kernel/src/procfs_static.rs` |
| G  | mmap completeness — MAP_SHARED, MAP_FIXED, addr hint, MADV_DONTNEED, mlockall | ✅ done | `kernel/src/user_as.rs` — F60 (MAP_SHARED + addr hint), F89 (MAP_FIXED via munmap-then-insert). File-backed mmap still ENOSYS pending VFS+pagecache wiring (`17§5`). |
| H  | Modern fd-creating syscalls (pidfd_open, eventfd2, signalfd, timerfd, dup3, close_range, pipe2) | ✅ done | `kernel/src/syscall_glue_anonfd.rs`, `kernel/src/syscall_glue_fs.rs:499-540`, `kernel/src/dev_pidfd.rs`, `kernel/src/syscall_glue.rs:117` |
| I  | Real virtio-net live driver | ✅ done | F59-01..15. DHCP/DNS userspace plumbing still open. |
| J  | AF_INET6 + sendmmsg/recvmmsg / real getsockopt | open | tracked in `## Rollout plan` below |
| K  | xattr + chroot + mount + namespaces | partial | F90 xattr overlay (per-inode storage); F95 chroot (per-task root + devfs::lookup prefix; CAP_SYS_CHROOT-gated); F97 UTS namespace (per-task hostname via CLONE_NEWUTS). Real mount/umount + per-NS mount table + CLONE_NEWPID/NEWUSER/NEWNET still open. |

All sweep PRs A..I closed as of F89 (2026-05-09). `J`/`K` are
open; tracked in the rollout plan at file end. File-backed mmap
remains gated on VFS+pagecache wiring (`17§5`).

## Notes on the bigger gaps that DON'T sit under "syscall stubs"

- **Real ld.so**: stub at /lib/ld-musl-x86_64.so.1 doesn't load
  DT_NEEDED. PR-13-06+ on the userspace side. Doesn't block static-
  linked distro programs.
- **vDSO**: kernel doesn't expose. glibc benefits but not required
  for musl.
- **DRM/KMS framebuffer**: zero. Wayland off-table.
- **input subsystem (evdev)**: zero.
- **GPU drivers**: zero.

## Rollout plan 2026-05-14

Goal: every Linux binary in `43§2` runs end-to-end without
hitting ENOSYS / EPERM / silent-no-op. Ordered by impact (how many
target binaries each batch unblocks) not by syscall count. Each
batch is a single branch/PR with a named exit gate. No deferrals,
no parking lot — every Linux subsystem on the contract is in
scope; the only question is sequence.

### Batch K1 — /dev/console real termios ✅ DONE (#1022)

All sub-items landed across B07..B22 + #1022:
- Per-VT `struct termios` slot (`tty::live::VT_TERMIOS`).
- TCGETS / TCSETS / TCSETSW / TCSETSF on console + /dev/tty<N>.
- ICANON line buffer (`VT_LINES`), VERASE / VKILL / VEOF.
- ECHO + ECHOE + ECHOK + ECHONL + ECHOCTL all honored (#1022).
- ONLCR on output (`dev/console.rs:84..119`).
- ISIG via `deliver_signal_to_waiters` → fg pgrp.

### Batch K2 — mm completeness ✅ DONE (#1023)

- `mremap` real (`syscalls/proc.rs:516`).
- `mprotect` per-PTE walks PT + flushes TLB (`proc.rs:122` →
  `pmm::user_as::mprotect_pages`).
- `sendfile` real via kernel staging buffer (`sched/xfer.rs:13`).
- File-backed `mmap` real via `VmaBacking::File` + `FileBacking`
  trait + per-inode `PageCache` (#1023, K6 substrate).

### Batch K3 — fcntl + fd flag honesty ✅ DONE (#1025 + #1026)

- F_GETFL / F_SETFL ✓ (live flag bits; #1025 plumbs O_NONBLOCK
  through `Inode::read_nonblock` / `write_nonblock`; pipe reads
  now block via WaitList instead of busy-EAGAIN).
- F_DUPFD_CLOEXEC ✓.
- F_SETLK / F_SETLKW / F_GETLK + F_OFD_SETLK/SETLKW/GETLK ✓
  via `fs::posix_lock` per-inode range list (#1026). SETLKW
  spins-and-yields; proper inode-range wait list rides a follow-up.

### Batch K4 — /proc/self surface ✅ DONE (#1027)

- `/proc/self/exe`, `/proc/self/cwd`, `/proc/self/root` are
  Symlink inodes (`procfs::proc_links`) that delegate readlink
  to `sched::proclink::resolve_proc_link` (#1027).
- `/proc/self/fd/<n>` per-fd entries are Symlink inodes pointing
  at the open file's dentry path.
- `vfs::Inode::readlink` default-impl added (Err(Einval) for
  non-symlinks); concrete symlinks override.
- `/proc/self/environ`, `/proc/self/mountinfo` already done.
- `/proc/partitions`, `/proc/filesystems`, `/proc/devices` are
  static; dynamic refresh rides a follow-up.

### Batch K5 — signal completeness round 2 ✅ DONE (#1028 + #1035)

- `rt_sigsuspend` ✓ (was already real).
- `rt_sigtimedwait` ✓ (real; #1035 also returns queued si_code/
  pid/uid/value to caller).
- Default-action core dump ✓ (#1028 — SIGQUIT/SIGILL/SIGTRAP/
  SIGABRT/SIGBUS/SIGFPE/SIGSEGV/SIGSYS/SIGXCPU/SIGXFSZ all dump
  on SIG_DFL terminate path).
- RT signals 33..64 multiplicity queue ✓ (#1035 — Task carries
  `rt_sigqueue: [VecDeque<SigInfo>; 32]`; sigqueue/take_lowest
  preserve POSIX RT queue order + siginfo payload).

### Batch K6 — VFS+pagecache wiring real ✅ DONE (#1023)

Demand-page handler resolves `VmaBacking::File` via
`Arc<dyn FileBacking>` (`mm-vmm::vma::FileBacking`); per-backing
`PageCache` fetches pages via `Inode::read`. MAP_PRIVATE + MAP_SHARED
file mmap both work; writeback + global per-inode cache hash ride
follow-ups. Acceptance: `mmap /bin/sh PROT_READ MAP_PRIVATE` byte-
identical to `head -c 4096 /bin/sh` is K7 harness work.

### Batch K7 — empirical acceptance harness ✅ SUBSTRATE (#1029)

`tools/accept.py` parses `tests/acceptance/<name>/scenario.sh`
(`>` send, `<` expect, [FAULT]/panic: fail-fast) and drives QEMU
+ serial. Per-scenario coverage adds incrementally as features
unblock the programs.

### Batch K8 — core dump on fatal signal ✅ DONE (#1028 substrate)

SIG_DFL fatal signals (SIGQUIT/SIGILL/SIGTRAP/SIGABRT/SIGBUS/
SIGFPE/SIGSEGV/SIGSYS/SIGXCPU/SIGXFSZ) now route through
`fs::coredump::write_for_current` which builds an ELF dump via
the `coredump.rs` builder and stages it under /core.<tid>.
Backing-file region dumps via pagecache rely on K6 (closed).

### Batch K9 — ptrace full machinery ✅ MOSTLY DONE

- TRACEME/ATTACH/SEIZE/DETACH/CONT/SYSCALL/SINGLESTEP/KILL —
  real wake via stop-state registry.
- PEEKTEXT/PEEKDATA — real foreign-mm read via `read_foreign_user`.
- POKETEXT/POKEDATA — real foreign-mm write via `write_foreign_user`.
- GETREGS/SETREGS/GETREGSET/SETREGSET — real read/write of target's
  saved syscall frame at kstack_top - 0x80 (x86) / -0xD0 (arm).
- SETOPTIONS/GETEVENTMSG — real per-task option bitset + eventmsg
  slot (#1033).
- GETSIGINFO/SETSIGINFO — real Spinlock<Option<SigInfo>> snapshot
  slot (#1036); stop-time snapshot population gating on broader
  ptrace stop-state restructure.
- OPEN: GETFPREGS/SETFPREGS (per-arch FP frame access);
  PTRACE_INTERRUPT / LISTEN beyond silent-0.

### Batch K10 — bpf + seccomp + landlock

bpf verifier (cBPF + eBPF subsets), JIT for x86-64 and AArch64,
hook points (XDP, socket-filter, tracepoint, syscall-entry).
seccomp_unotify, BPF_PROG_TYPE_SECCOMP. landlock ruleset
syscalls + per-task ruleset chain. Per `27`.

### Batch K11 — io_uring

`io_uring_setup` / `io_uring_enter` / `io_uring_register` real,
SQE/CQE rings backed by shared mmap, IORING_OP_* covering
read/write/openat/close/accept/connect/send/recv/timeout/poll
at minimum. Per `30`.

### Batch K12 — SysV IPC + POSIX MQ

`shmget/shmat/shmdt/shmctl`, `semget/semop/semctl`,
`msgget/msgsnd/msgrcv/msgctl`. `mq_open/mq_timedsend/
mq_timedreceive/mq_notify` real (storage already partial). Per `24`.

### Batch K13 — DRM/KMS + input subsystem

DRM ioctls (DRM_IOCTL_MODE_*), virtio-gpu KMS bring-up, evdev
char devs (`/dev/input/event*`) backed by virtio-input. Per a
new spec (TBD section in `35`).

### Batch K14 — vDSO

Per-arch vDSO ELF mapped into every user AS; clock_gettime /
getcpu / time / rt_sigreturn fast paths in user mode. Per `15`.

### Batch K15 — glibc compatibility surface (partial)

- FSGSBASE ✓ (CR4.FSGSBASE enabled at boot per CPU; wrgsbase/
  wrfsbase legal at CPL=0).
- IFUNC ✓ (#1037 — dl handles R_X86_64_IRELATIVE +
  R_AARCH64_IRELATIVE by invoking the resolver and installing
  the returned VA).
- `getrandom` ✓ (#1031 — RDRAND/RNDR HW RNG path).
- OPEN: TLS init-image (PT_TLS + DTPMOD64/DTPOFF64/TPOFF64),
  versioned symbols (DT_VERNEED/VERSYM), lazy PLT via GOT trampoline.
- `set_thread_area` (i386) — not applicable to x86_64 musl/glibc
  builds (64-bit TCB lives in FS_BASE via arch_prctl).

### Sequencing

K1 is the unblock-everything-interactive batch — start there. K2-K3
are independent and can land in parallel branches. K4 piggybacks on
existing procfs scaffolding. K5 depends on K2/K3 for the core-dump
path but rt_sigsuspend is independent. K6 is the substrate item —
separate spec touch — and gates K2/K5 completion. K7 lands
incrementally as K1..K6 unblock entries. K8..K15 are independent
of one another and pick up after K6 (pagecache) is in.
