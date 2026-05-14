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
| /dev/console termios | 🟥 | `kernel/src/syscall_glue_ioctl.rs:90` TCGETS returns zero-filled buf for non-pty char devs. No real termios state. |
| ICANON (line buffering) | 🟥 | `/dev/console` reads byte-by-byte, no line accumulation. Bash needs raw, login + sh need cooked. |
| ECHO toggle | 🟥 | `kernel/src/tty.rs:178` echoes unconditionally. login's password-prompt phase echoes too. |
| ICRNL on input | 🟡 | `tty.rs:194` hardcoded CR→NL. Should be opt-in via per-fd c_iflag. |
| ONLCR on output | 🟥 | `tty.rs:188` echoes "\r\n" for CR/NL on input echo only. Userspace `write(1, "\n")` does NOT get ONLCR translation. |
| ISIG (Ctrl-C → SIGINT) | 🟥 | No translation of 0x03/0x1c/0x1a → signal. **This is why "Ctrl-C does nothing on a hung app".** |
| VEOF/VERASE/VKILL/VINTR | 🟥 | No c_cc array applied to /dev/console input. |
| TIOCGWINSZ | 🟡 | `syscall_glue_ioctl.rs:44` returns 80×24 hardcoded. |
| TIOCSWINSZ | 🟥 | Probably accept-and-no-op. |
| TIOCSCTTY (control terminal) | 🟥 | No "controlling tty" concept. |

### 2. Job control + process groups

| feature | state | notes |
|---|---|---|
| getpgid/setpgid/getpgrp | 🟥 | Likely stub — `Task` has no pgid field. |
| setsid (session leader) | 🟥 | No session concept. |
| getsid | 🟥 | |
| Foreground process group on tty | 🟥 | TIOCGPGRP/TIOCSPGRP work for pty (per docs/28 P3-pty), missing for /dev/console. |
| tcsetpgrp / tcgetpgrp | 🟡 | Works for pty fds via TIOCGPGRP/TIOCSPGRP arms (`syscall_glue_ioctl.rs:128`). Missing for console. |
| `cmd &` background jobs | 🟡 | Works in toy sh (P5-12) but no real pgid → bash's `fg`/`bg` won't work. |

### 3. Signals

| feature | state | notes |
|---|---|---|
| rt_sigaction | ✅ | `syscall_glue_proc.rs:142` — per-task sigactions table; sa_handler/sa_flags/sa_restorer/sa_mask. |
| rt_sigprocmask | ✅ | `syscall_glue_proc.rs:191` |
| rt_sigreturn | ✅ | `sig_dispatch.rs` — restores frame after handler. |
| rt_sigsuspend | 🟥 | Likely missing — bash uses for SIGCHLD wait. |
| rt_sigtimedwait | 🟥 | `syscall_compat.rs` ENOSYS. |
| rt_sigqueueinfo / rt_tgsigqueueinfo | 🟥 | ENOSYS. |
| sigaltstack | 🟥 | Probably stub. |
| signal frame for fault (SIGSEGV/SIGBUS) | 🟡 | Some delivery; full siginfo_t fill incomplete. |
| Real-time signals (32+) | 🟡 | sigpending uses single u64 → only 64 sigs total. |
| restart_syscall (-EINTR loop) | 🟡 | `syscall_compat.rs:43` returns EINTR; not real restart. |
| Default actions (Term/Core/Ign/Stop/Cont) | 🟡 | Term + Ign + Stop/Cont present (sched_stop.rs); no core dump. |

### 4. Threading + clone

| feature | state | notes |
|---|---|---|
| fork (clone with no flags) | ✅ | `syscall_glue.rs:228` — copies AS w/ COW-ish via demand fault. |
| clone with CLONE_VM/CLONE_THREAD | 🟥 | Falls through to fork — **not a real thread**. Multi-thread same-AS missing. |
| clone3 | 🟥 | `syscall_glue_proc.rs:60` ENOSYS. |
| pthread_create | 🟥 | musl pthreads issue clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SETTLS) — not handled. |
| set_thread_area | 🟥 | x86_64 uses arch_prctl(ARCH_SET_FS) which works, but `set_thread_area` (i386 path) absent. |
| gettid | 🟡 | Returns tid — works for single-thread (tid == tgid). Wrong once threading lands. |
| set_tid_address | ✅ | `syscall_glue_proc.rs:34` stores in `clear_child_tid`. CLONE_CHILD_CLEARTID wakeup-on-exit not done. |
| futex FUTEX_WAIT/WAKE | ✅ | `kernel/src/futex.rs` (P3a). |
| futex_waitv | 🟥 | accept-as-no-op. |
| robust_list | 🟥 | `set_robust_list` returns 0 silently. `get_robust_list` ENOSYS. |
| rseq (restartable sequences) | 🟥 | ENOSYS — modern glibc/musl uses for fast pthread getpid. |

### 5. Memory management

| feature | state | notes |
|---|---|---|
| mmap MAP_PRIVATE \| MAP_ANONYMOUS | ✅ | Demand-paged. |
| mmap MAP_SHARED | 🟥 | Likely treated as PRIVATE. Wayland + dbus + tmpfiles mmap need this. |
| mmap MAP_FIXED | ✅ | |
| mmap file-backed (MAP_PRIVATE) | 🟡 | KernelBytes path works for ELF; arbitrary file mmap unclear. |
| mprotect per-PTE | 🟥 | `syscall_glue_proc.rs:62` updates VMA prot, doesn't walk PTEs. |
| mremap | 🟥 | `syscall_glue_proc.rs:520` returns ENOMEM unconditionally. |
| madvise | 🟥 | accept-and-no-op. MADV_DONTNEED zero-fill missing. |
| mlock / mlockall | 🟥 | accept-and-no-op. |
| mincore | 🟥 | ENOSYS. |
| memfd_create / memfd_secret | 🟥 | ENOSYS. systemd + Wayland use heavily. |
| brk | ✅ | |
| pkey_alloc/pkey_free/pkey_mprotect | 🟥 | ENOSYS. |

### 6. Filesystem + VFS

| feature | state | notes |
|---|---|---|
| openat / open | ✅ | Recently fixed `.`/`..` resolution (B08). |
| close | ✅ | |
| read / write | ✅ | |
| pread64 / pwrite64 | ✅ | |
| readv / writev | ✅ | |
| preadv / pwritev | ✅ | (P9-17) |
| preadv2 / pwritev2 | 🟥 | ENOSYS. |
| sendfile | 🟥 | ENOSYS — nginx + cp use heavily. |
| splice / tee / vmsplice | 🟥 | ENOSYS. |
| copy_file_range | 🟥 | ENOSYS. |
| dup / dup2 / dup3 | 🟡 | dup/dup2 work; dup3 unclear (`syscall_glue_fs.rs:152`). |
| pipe / pipe2 | 🟡 | `dev_pipe.rs` minimal — non-blocking on empty/full (Eagain). Real blocking with WaitQueue rides P3-01b. |
| fcntl F_GETFD/F_SETFD | 🟡 | FD_CLOEXEC tracked. |
| fcntl F_GETFL/F_SETFL | 🟥 | O_NONBLOCK toggle probably no-op. |
| fcntl F_DUPFD | 🟡 | |
| fcntl F_SETLK / F_GETLK | 🟥 | No advisory locking. |
| getdents64 | ✅ | (overlay fix recent) |
| stat / fstat / lstat / fstatat | ✅ | |
| statx | 🟡 | check — modern programs prefer this. |
| access / faccessat | 🟡 | |
| faccessat2 | 🟥 | ENOSYS. |
| openat2 | 🟥 | ENOSYS. systemd uses for RESOLVE_BENEATH. |
| chmod/fchmod/fchmodat | 🟡 | |
| chown/fchown/fchownat | 🟡 | |
| utimes / utimensat | 🟡 | `futimesat` accept-and-no-op. |
| chdir / fchdir | ✅ | per-task cwd |
| getcwd | ✅ | |
| chroot | 🟥 | EPERM (privileged refuse). |
| mount / umount | 🟥 | EPERM. |
| pivot_root | 🟥 | ENOSYS. |
| ext4 RO read | ✅ | |
| ext4 RW + JBD2 | 🟡 | (P7b) — works for small files. |
| ext4 dir > 4 KiB | 🟥 | `kernel/src/dev_ext4.rs:140` only first dir block read. |
| ext4 extent depth >2 | 🟥 | Depth 1-2 read+write (P9-07). Depth 3+ missing. |
| ext4 hard links | 🟡 | (P9-24) |
| ext4 symlinks | 🟥 | Maybe missing. |
| xattr (get/set/list/remove) | 🟥 | ENOSYS family. systemd uses. |
| inotify / fanotify | 🟡 | dev_inotify.rs exists; fanotify ENOSYS. |
| O_TMPFILE | 🟥 | Unclear. |
| /tmp tmpfs | ✅ | (P3-pipe) |
| /proc | 🟡 | Partial (see /proc table below). |
| /sys | 🟡 | (P9-13/P9-31) — net subset. |
| /dev | ✅ | (B07 multi-VT) |

### 7. Modern fd-creating syscalls

| feature | state | notes |
|---|---|---|
| eventfd / eventfd2 | 🟡 | Probably wired — verify. |
| signalfd / signalfd4 | 🟡 | `dev_signalfd.rs` exists. |
| timerfd_create / settime / gettime | 🟡 | `dev_timerfd.rs` exists. |
| epoll_create / epoll_ctl / epoll_wait | ✅ | `dev_epoll.rs` (P9-21 poll readiness) |
| epoll_pwait | 🟡 | |
| epoll_pwait2 | 🟥 | ENOSYS. |
| inotify_init / inotify_add_watch | 🟡 | dev_inotify exists. |
| pidfd_open | 🟥 | Unclear. |
| pidfd_send_signal | 🟡 | dev_pidfd.rs exists. |
| pidfd_getfd | 🟥 | ENOSYS. |
| close_range | 🟥 | Unclear — probably stub. |
| userfaultfd | 🟥 | ENOSYS. |
| io_uring (setup/enter/register) | 🟥 | ENOSYS. |
| memfd_create | 🟥 | ENOSYS. |

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
| sendmmsg / recvmmsg | 🟥 | ENOSYS. |
| netlink (route/genl) | 🟥 | Missing. |
| iptables / nftables | 🟥 | No netfilter. |
| getsockopt / setsockopt | 🟡 | Silent-accept; SO_REUSEADDR honored. |

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

### Batch K1 — /dev/console real termios (gates: bash, login cooked-mode, password echo)

Affected: every interactive program that reads from `/dev/console`
without going through a PTY pair. Currently the console fakes a
zero-filled `struct termios` (`syscall_glue_ioctl.rs:90`), ignores
TCSETS, hardcodes ECHO and CR→NL on input, never emits ONLCR on
write, and has no ISIG path.

- Per-device `struct termios` slot in the console driver.
- Honor TCGETS / TCSETS / TCSETSW / TCSETSF on the console fd.
- Wire ICANON line-accumulation buffer (commit on `\n` or VEOF).
- Wire ECHO toggle (and ECHONL, ECHOE, ECHOK).
- Wire ONLCR on `write(fd, "\n", …)` — output side, not just echo.
- Wire ISIG: VINTR/VQUIT/VSUSP → signal delivery to fg pgrp on the
  controlling tty (already wired for PTY pair; reuse path).
- Test: `stty -echo` then `read pw` shows no echo; Ctrl-C aborts a
  `sleep 30`; `printf "a\nb\n"` produces `a\r\nb\r\n` on a serial
  console with ONLCR set (default).

### Batch K2 — mm completeness for non-toy programs (gates: realloc-heavy + JIT + cp/sendfile)

- `mremap` real: MREMAP_MAYMOVE shrink + grow with copy; MREMAP_FIXED
  via munmap-then-insert pattern (mirror F89's MAP_FIXED handling).
- `mprotect` per-PTE: walk the range and flip W/X bits in the live
  page tables; TLB shootdown per-CPU (already plumbed for SMP-coop).
- `sendfile` real: copy via pagecache (read-then-write under VFS),
  not ENOSYS. cp, nginx, scp, busybox httpd all use it.
- File-backed `mmap` real: KernelBytes path already wires ELF; extend
  to any vfs::File via demand-fault → pagecache (depends on K6).
- Test: `mprotect_smoke` extended to grow + shrink + page split;
  `cp -a /bin /tmp/bin` byte-identical via sendfile path.

### Batch K3 — fcntl + fd flag honesty (gates: server programs + non-blocking I/O)

- `fcntl F_SETFL` toggling O_NONBLOCK takes effect on subsequent
  read/write on pipes, sockets, ptys, ttys (currently no-op).
- `fcntl F_GETFL` returns the live flag set (currently stale).
- `fcntl F_DUPFD_CLOEXEC` (the modern variant).
- `fcntl F_SETLK / F_GETLK / F_OFD_*` advisory locks via per-inode
  range list (musl's `flock_chk` + tar/dpkg use these).
- Test: socat / busybox httpd accepts a connection in non-blocking
  mode and EAGAIN's correctly.

### Batch K4 — /proc/self surface (gates: ldd, gdb stubs, glibc init)

- `/proc/self/exe` symlink → resolve current task's binary path.
- `/proc/self/fd/<n>` symlinks → resolve open vfs::File path.
- `/proc/self/environ` from saved exec envp.
- `/proc/self/mountinfo` from per-NS mount table.
- `/proc/partitions` from registered block devs.
- `/proc/filesystems` from registered fs types.
- `/proc/devices` from registered char/block major numbers.
- Test: `ls -l /proc/self/exe` resolves; `readlink /proc/self/fd/0`
  returns `/dev/console` or `/dev/pts/N`.

### Batch K5 — signal completeness round 2 (gates: bash signal traps, pkill, daemons)

- `rt_sigsuspend` real (was ENOSYS) — atomic block-mask-and-wait.
- `rt_sigtimedwait` real — bash uses for SIGCHLD timeouts.
- Default-action coverage: SIGSTOP/SIGCONT already; add core dump
  for SIGSEGV/SIGABRT/SIGFPE/SIGILL/SIGBUS once K6 lands.
- Real-time signals 32..64 — extend per-task sigpending from u64
  to a 64-entry queue.
- Test: `bash -c 'trap : USR1; kill -USR1 $$; echo ok'` prints `ok`.

### Batch K6 — VFS+pagecache wiring real (gates: file-backed mmap, core dumps, sendfile)

Substrate for K2 (file-backed mmap) and K5 (core dump SIGSEGV→ELF).
Already partial (block layer + page cache + ext4 RW done per
`00§3.1`); missing is the read-side page-fault handler that maps a
file's pagecache page into the faulting task's AS.

- Hook page fault → vfs::File backing → pagecache lookup → install
  the page in the task's AS as read-only-shared (writable on COW).
- TLB shootdown on page eviction.
- Test: `mmap /bin/sh PROT_READ MAP_PRIVATE` of size 4 KiB returns a
  va that reads the binary's first page byte-identical to
  `head -c 4096 /bin/sh`.

### Batch K7 — empirical acceptance harness (gates: release tag)

Per `43§5`: build a harness that drives `tests/acceptance/<bin>/
scenario.sh` under QEMU on both arches, asserts expected `<` lines
in the serial stream, fails on `[FAULT]` / `panic:` substrings.
Land the busybox scenario first; add per-applet scenarios as
batches K1..K6 unblock them. Exit gate: every entry in `43§2`
passes on both arches.

### Batch K8 — core dump on fatal signal

SIGSEGV / SIGABRT / SIGFPE / SIGILL / SIGBUS → ELF coredump
written to fs per `27`. Depends on K6 (pagecache for backing-file
reads) and K5 (default-action wiring).

### Batch K9 — ptrace full machinery

`PTRACE_ATTACH/SEIZE/DETACH/CONT/SYSCALL/SINGLESTEP/GETREGS/
SETREGS/PEEKTEXT/POKETEXT/PEEKDATA/POKEDATA/GETSIGINFO/SETOPTIONS`
real, integrating with the scheduler's stop-state machine and
the signal delivery path. Per-arch register slab (x86-64 user
regs + AArch64 user regs).

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

### Batch K15 — glibc compatibility surface

`set_thread_area` (i386 path), FSGSBASE instructions enabled in
the user CR4 mask, IFUNC resolver wiring in the ELF loader.

### Sequencing

K1 is the unblock-everything-interactive batch — start there. K2-K3
are independent and can land in parallel branches. K4 piggybacks on
existing procfs scaffolding. K5 depends on K2/K3 for the core-dump
path but rt_sigsuspend is independent. K6 is the substrate item —
separate spec touch — and gates K2/K5 completion. K7 lands
incrementally as K1..K6 unblock entries. K8..K15 are independent
of one another and pick up after K6 (pagecache) is in.
