# 15 Syscall ABI

FROZEN 2026-05-02. Dep:`01`,`03`,`06`,`08`,`09`.

## Revision 2026-05-02 (R03)

- Changed: added §6.7 "UAPI surface boundary" enumerating the public-to-userspace contract.
- Why: §2 lists syscall numbers + §6 lists ABI structs but never says "this and only this is what userspace sees" — leaving the musl fork (`29§4`, `29a§3`) with no precise contract to consume. Linux uses `include/uapi/linux/` for this; we had no analogue.
- Affected code: future `xtask uapi-export` (`07§3.4`); future `crates/uapi/` (kernel-side single-source-of-truth) and `userspace/uapi/` (export tree the musl fork reads).
- Test contract change: §9 unchanged; the static-assert that currently lives implicitly in `userspace-abi` becomes the export step's correctness criterion.

Linux-compatible ABI; numbers exactly Linux x86_64. aarch64 reuses x86_64 numbering (deviates from Linux aarch64 numbering — same userspace stub both arches differing only in trap instr).

Rule: **every Linux x86_64 syscall number has a documented disposition. No gaps, no surprises.**

## 1 Calling convention

### 1.1 x86_64
Trap=`syscall`. Nr in `rax`. Args `rdi,rsi,rdx,r10,r8,r9` (`r10` not `rcx` because syscall clobbers `rcx`). Return `rax` (`-errno` for errors). Clobbers: `rcx`(saved RIP), `r11`(saved RFLAGS).

### 1.2 aarch64
Trap=`svc #0`. Nr in `x8`. Args `x0..x5`. Return `x0`. Clobbers: none beyond PCS save/restore.

### 1.3 Return rule
Success: `0..=0x7fff_ffff_ffff_f000` (top 4KiB reserved). `0xffff_ffff_ffff_f001..=...ffff` = `-errno`. libc check `rv > -4096UL` sound.

### 1.4 Ptr validation
User ptr args wrapped in `UserPtr<T>` at dispatch:
1. Range check `ptr+size ≤ USER_VA_END`.
2. PT check via `copy_from_user`/`copy_to_user`; faults gracefully → `EFAULT`.
3. No raw `*mut u8` from userspace past dispatch.

## 2 Full table

Legend:
- **V1**: implemented v1, on must-run-binary path.
- **V2**: v1 point release; v1.0 returns `ENOSYS`; number reserved.
- **V2**: deferred to v2.
- **STUB**: number reserved, always returns `ENOSYS` (we will never implement, but the number is ABI).
- **NEVER**: same as STUB but explicitly because the syscall is legacy. Linux still exposes some of these; we never will.

Where a syscall has a "modern replacement," we point to it.

| Nr | Name | Status | Notes |
|---|---|---|---|
| 0 | read | V1 | |
| 1 | write | V1 | |
| 2 | open | V2 | Prefer `openat`/`openat2`; libc wraps. |
| 3 | close | V1 | |
| 4 | stat | NEVER | Use `statx`. Linux still has it; we don't. |
| 5 | fstat | V1 | Kept for fd-only metadata, libc compat. |
| 6 | lstat | NEVER | Use `statx` with `AT_SYMLINK_NOFOLLOW`. |
| 7 | poll | V2 | Prefer `ppoll`. |
| 8 | lseek | V1 | |
| 9 | mmap | V1 | |
| 10 | mprotect | V1 | |
| 11 | munmap | V1 | |
| 12 | brk | V1 | Thin shim for libc heap; not preferred. |
| 13 | rt_sigaction | V1 | |
| 14 | rt_sigprocmask | V1 | |
| 15 | rt_sigreturn | V1 | Internal; called from userspace signal trampoline. |
| 16 | ioctl | V1 | Per-driver opcode dispatch. |
| 17 | pread64 | V1 | |
| 18 | pwrite64 | V1 | |
| 19 | readv | V1 | |
| 20 | writev | V1 | |
| 21 | access | V2 | Prefer `faccessat2`. |
| 22 | pipe | V2 | Prefer `pipe2`. |
| 23 | select | NEVER | Use `epoll`/`ppoll`. |
| 24 | sched_yield | V1 | |
| 25 | mremap | V1 | |
| 26 | msync | V1 | |
| 27 | mincore | V1 | |
| 28 | madvise | V1 | Modern flags only (`MADV_FREE`, `MADV_COLD`, `MADV_PAGEOUT`, etc.). |
| 29 | shmget | NEVER | SysV shm dropped. Use `memfd_create` + `mmap`. |
| 30 | shmat | NEVER | SysV shm dropped. |
| 31 | shmctl | NEVER | SysV shm dropped. |
| 32 | dup | V1 | |
| 33 | dup2 | V2 | Prefer `dup3`. |
| 34 | pause | V1 | |
| 35 | nanosleep | V1 | |
| 36 | getitimer | V2 | Use `timerfd_*`. |
| 37 | alarm | V2 | Use `timerfd_*`. |
| 38 | setitimer | V2 | Use `timerfd_*`. |
| 39 | getpid | V1 | vDSO-served. |
| 40 | sendfile | V1 | |
| 41 | socket | V1 | |
| 42 | connect | V1 | |
| 43 | accept | V2 | Prefer `accept4`. |
| 44 | sendto | V1 | |
| 45 | recvfrom | V1 | |
| 46 | sendmsg | V1 | |
| 47 | recvmsg | V1 | |
| 48 | shutdown | V1 | |
| 49 | bind | V1 | |
| 50 | listen | V1 | |
| 51 | getsockname | V1 | |
| 52 | getpeername | V1 | |
| 53 | socketpair | V1 | |
| 54 | setsockopt | V1 | Modern options only; legacy options return `ENOPROTOOPT`. |
| 55 | getsockopt | V1 | |
| 56 | clone | V2 | Prefer `clone3`; libc wraps. |
| 57 | fork | V2 | Implemented as `clone3` with the right flags; libc wraps. |
| 58 | vfork | NEVER | Replaced by `posix_spawn` userspace pattern. |
| 59 | execve | V1 | |
| 60 | exit | V1 | |
| 61 | wait4 | V2 | Prefer `waitid`. |
| 62 | kill | V1 | |
| 63 | uname | V1 | Returns a fixed modern-looking string. |
| 64 | semget | NEVER | SysV IPC dropped. |
| 65 | semop | NEVER | |
| 66 | semctl | NEVER | |
| 67 | shmdt | NEVER | |
| 68 | msgget | NEVER | |
| 69 | msgsnd | NEVER | |
| 70 | msgrcv | NEVER | |
| 71 | msgctl | NEVER | |
| 72 | fcntl | V1 | Modern subset: `F_GETFD/F_SETFD`, `F_GETFL/F_SETFL`, `F_DUPFD_CLOEXEC`, `F_SETLK/F_GETLK/F_OFD_*`, `F_SETOWN`, `F_SETPIPE_SZ`. |
| 73 | flock | V1 | |
| 74 | fsync | V1 | |
| 75 | fdatasync | V1 | |
| 76 | truncate | V1 | |
| 77 | ftruncate | V1 | |
| 78 | getdents | NEVER | Use `getdents64`. |
| 79 | getcwd | V1 | |
| 80 | chdir | V1 | |
| 81 | fchdir | V1 | |
| 82 | rename | V2 | Prefer `renameat2`. |
| 83 | mkdir | V2 | Prefer `mkdirat`. |
| 84 | rmdir | V2 | Prefer `unlinkat(AT_REMOVEDIR)`. |
| 85 | creat | NEVER | Use `openat`. |
| 86 | link | V2 | Prefer `linkat`. |
| 87 | unlink | V2 | Prefer `unlinkat`. |
| 88 | symlink | V2 | Prefer `symlinkat`. |
| 89 | readlink | V2 | Prefer `readlinkat`. |
| 90 | chmod | V2 | Prefer `fchmodat2`. |
| 91 | fchmod | V1 | |
| 92 | chown | V2 | Prefer `fchownat`. |
| 93 | fchown | V1 | |
| 94 | lchown | V2 | Prefer `fchownat(AT_SYMLINK_NOFOLLOW)`. |
| 95 | umask | V1 | |
| 96 | gettimeofday | V2 | vDSO-served when present; syscall path mostly for fallback. Prefer `clock_gettime`. |
| 97 | getrlimit | V1 | |
| 98 | getrusage | V1 | |
| 99 | sysinfo | V1 | |
| 100 | times | V1 | |
| 101 | ptrace | V1 | gdb/strace subset only. No legacy `PTRACE_PEEKUSR` for non-current arch reg sets. |
| 102 | getuid | V1 | |
| 103 | syslog | V1 | Reads `/dev/kmsg` ring; subset of actions. |
| 104 | getgid | V1 | |
| 105 | setuid | V1 | |
| 106 | setgid | V1 | |
| 107 | geteuid | V1 | |
| 108 | getegid | V1 | |
| 109 | setpgid | V1 | |
| 110 | getppid | V1 | |
| 111 | getpgrp | V1 | |
| 112 | setsid | V1 | |
| 113 | setreuid | V1 | |
| 114 | setregid | V1 | |
| 115 | getgroups | V1 | |
| 116 | setgroups | V1 | |
| 117 | setresuid | V1 | |
| 118 | getresuid | V1 | |
| 119 | setresgid | V1 | |
| 120 | getresgid | V1 | |
| 121 | getpgid | V1 | |
| 122 | setfsuid | V1 | |
| 123 | setfsgid | V1 | |
| 124 | getsid | V1 | |
| 125 | capget | V1 | v3 only; v1/v2 header magic returns `EINVAL`. |
| 126 | capset | V1 | v3 only. |
| 127 | rt_sigpending | V1 | |
| 128 | rt_sigtimedwait | V1 | |
| 129 | rt_sigqueueinfo | V1 | |
| 130 | rt_sigsuspend | V1 | |
| 131 | sigaltstack | V1 | |
| 132 | utime | V2 | Prefer `utimensat`. |
| 133 | mknod | V2 | Prefer `mknodat`. |
| 134 | uselib | NEVER | Legacy a.out shared-lib loading. |
| 135 | personality | V1 | Only `PER_LINUX` and `ADDR_NO_RANDOMIZE` honored. |
| 136 | ustat | NEVER | Use `statfs`/`fstatfs`. |
| 137 | statfs | V1 | |
| 138 | fstatfs | V1 | |
| 139 | sysfs | NEVER | Use `/proc/filesystems`. |
| 140 | getpriority | V1 | |
| 141 | setpriority | V1 | |
| 142 | sched_setparam | V1 | |
| 143 | sched_getparam | V1 | |
| 144 | sched_setscheduler | V1 | |
| 145 | sched_getscheduler | V1 | |
| 146 | sched_get_priority_max | V1 | |
| 147 | sched_get_priority_min | V1 | |
| 148 | sched_rr_get_interval | V1 | |
| 149 | mlock | V1 | |
| 150 | munlock | V1 | |
| 151 | mlockall | V1 | |
| 152 | munlockall | V1 | |
| 153 | vhangup | V1 | |
| 154 | modify_ldt | NEVER | No segmented memory tricks. |
| 155 | pivot_root | V1 | Required for containers. |
| 156 | _sysctl | NEVER | Removed in modern Linux (5.5). Use `/proc/sys/`. |
| 157 | prctl | V1 | Modern subset: `PR_SET_NAME`, `PR_SET_PDEATHSIG`, `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE`, `PR_CAP_AMBIENT`, `PR_SET_CHILD_SUBREAPER`, `PR_SET_THP_DISABLE`, `PR_SET_VMA`, `PR_SET_TIMERSLACK`, `PR_SET_SECCOMP`, `PR_GET_KEEPCAPS`, `PR_SET_KEEPCAPS`. Legacy `PR_*` return `EINVAL`. |
| 158 | arch_prctl | V1 | `ARCH_SET_FS`, `ARCH_GET_FS`, `ARCH_SET_GS`, `ARCH_GET_GS`. Used by libc TLS init. |
| 159 | adjtimex | V2 | Subset for NTP daemons. |
| 160 | setrlimit | V1 | |
| 161 | chroot | V1 | |
| 162 | sync | V1 | |
| 163 | acct | V2 | Process accounting; not a v1 priority. |
| 164 | settimeofday | V2 | Prefer `clock_settime`. |
| 165 | mount | V2 | Implemented as compat shim over the new mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`). |
| 166 | umount2 | V1 | |
| 167 | swapon | NEVER | No swap in v1. |
| 168 | swapoff | NEVER | |
| 169 | reboot | V1 | UEFI Runtime Services / platform reset. |
| 170 | sethostname | V1 | |
| 171 | setdomainname | V1 | |
| 172 | iopl | NEVER | No raw port I/O for userspace. |
| 173 | ioperm | NEVER | |
| 174 | create_module | NEVER | Legacy module loading. |
| 175 | init_module | NEVER | Use `finit_module`. |
| 176 | delete_module | V1 | |
| 177 | get_kernel_syms | NEVER | Use `/proc/kallsyms` (gated). |
| 178 | query_module | NEVER | Removed in Linux 2.6. |
| 179 | quotactl | V2 | Use `quotactl_fd` if needed in v2. |
| 180 | nfsservctl | NEVER | Removed in Linux 3.1. |
| 181 | getpmsg | NEVER | STREAMS, never implemented in mainline Linux. |
| 182 | putpmsg | NEVER | |
| 183 | afs_syscall | NEVER | |
| 184 | tuxcall | NEVER | |
| 185 | security | NEVER | |
| 186 | gettid | V1 | |
| 187 | readahead | V1 | |
| 188 | setxattr | V1 | |
| 189 | lsetxattr | V1 | |
| 190 | fsetxattr | V1 | |
| 191 | getxattr | V1 | |
| 192 | lgetxattr | V1 | |
| 193 | fgetxattr | V1 | |
| 194 | listxattr | V1 | |
| 195 | llistxattr | V1 | |
| 196 | flistxattr | V1 | |
| 197 | removexattr | V1 | |
| 198 | lremovexattr | V1 | |
| 199 | fremovexattr | V1 | |
| 200 | tkill | V2 | Prefer `tgkill`. |
| 201 | time | NEVER | Use `clock_gettime(CLOCK_REALTIME)`. |
| 202 | futex | V1 | Classic futex required for libc compat. New code should use `futex_waitv` / `futex_wake`. |
| 203 | sched_setaffinity | V1 | |
| 204 | sched_getaffinity | V1 | |
| 205 | set_thread_area | NEVER | x86_32 legacy. |
| 206 | io_setup | NEVER | POSIX AIO. Use `io_uring`. |
| 207 | io_destroy | NEVER | |
| 208 | io_getevents | NEVER | |
| 209 | io_submit | NEVER | |
| 210 | io_cancel | NEVER | |
| 211 | get_thread_area | NEVER | x86_32 legacy. |
| 212 | lookup_dcookie | NEVER | oprofile legacy. |
| 213 | epoll_create | V2 | Prefer `epoll_create1`. |
| 214 | epoll_ctl_old | NEVER | |
| 215 | epoll_wait_old | NEVER | |
| 216 | remap_file_pages | V2 | Deprecated; nontrivial to implement; not on must-run-binary path. |
| 217 | getdents64 | V1 | |
| 218 | set_tid_address | V1 | |
| 219 | restart_syscall | V1 | Internal; signal restart. |
| 220 | semtimedop | NEVER | SysV IPC dropped. |
| 221 | fadvise64 | V1 | |
| 222 | timer_create | V1 | POSIX timers. |
| 223 | timer_settime | V1 | |
| 224 | timer_gettime | V1 | |
| 225 | timer_getoverrun | V1 | |
| 226 | timer_delete | V1 | |
| 227 | clock_settime | V1 | |
| 228 | clock_gettime | V1 | vDSO-served. |
| 229 | clock_getres | V1 | vDSO-served. |
| 230 | clock_nanosleep | V1 | |
| 231 | exit_group | V1 | |
| 232 | epoll_wait | V2 | Prefer `epoll_pwait2`. |
| 233 | epoll_ctl | V1 | |
| 234 | tgkill | V1 | |
| 235 | utimes | V2 | Prefer `utimensat`. |
| 236 | vserver | NEVER | |
| 237 | mbind | V2 | NUMA memory policy. |
| 238 | set_mempolicy | V2 | |
| 239 | get_mempolicy | V2 | |
| 240 | mq_open | V2 | POSIX mqueue. Not v1. |
| 241 | mq_unlink | V2 | |
| 242 | mq_timedsend | V2 | |
| 243 | mq_timedreceive | V2 | |
| 244 | mq_notify | V2 | |
| 245 | mq_getsetattr | V2 | |
| 246 | kexec_load | V2 | |
| 247 | waitid | V1 | |
| 248 | add_key | V2 | Kernel keyring. |
| 249 | request_key | V2 | |
| 250 | keyctl | V2 | |
| 251 | ioprio_set | V2 | |
| 252 | ioprio_get | V2 | |
| 253 | inotify_init | V2 | Prefer `inotify_init1`. |
| 254 | inotify_add_watch | V1 | |
| 255 | inotify_rm_watch | V1 | |
| 256 | migrate_pages | V2 | NUMA. |
| 257 | openat | V1 | |
| 258 | mkdirat | V1 | |
| 259 | mknodat | V1 | |
| 260 | fchownat | V1 | |
| 261 | futimesat | NEVER | Use `utimensat`. |
| 262 | newfstatat | V1 | (a.k.a. `fstatat`) |
| 263 | unlinkat | V1 | |
| 264 | renameat | V2 | Prefer `renameat2`. |
| 265 | linkat | V1 | |
| 266 | symlinkat | V1 | |
| 267 | readlinkat | V1 | |
| 268 | fchmodat | V2 | Prefer `fchmodat2`. |
| 269 | faccessat | V2 | Prefer `faccessat2`. |
| 270 | pselect6 | NEVER | Use `ppoll`/`epoll`. |
| 271 | ppoll | V1 | |
| 272 | unshare | V1 | |
| 273 | set_robust_list | V1 | |
| 274 | get_robust_list | V1 | |
| 275 | splice | V1 | |
| 276 | tee | V1 | |
| 277 | sync_file_range | V1 | |
| 278 | vmsplice | V2 | |
| 279 | move_pages | V2 | NUMA. |
| 280 | utimensat | V1 | |
| 281 | epoll_pwait | V1 | |
| 282 | signalfd | V2 | Prefer `signalfd4`. |
| 283 | timerfd_create | V1 | |
| 284 | eventfd | V2 | Prefer `eventfd2`. |
| 285 | fallocate | V1 | |
| 286 | timerfd_settime | V1 | |
| 287 | timerfd_gettime | V1 | |
| 288 | accept4 | V1 | |
| 289 | signalfd4 | V1 | |
| 290 | eventfd2 | V1 | |
| 291 | epoll_create1 | V1 | |
| 292 | dup3 | V1 | |
| 293 | pipe2 | V1 | |
| 294 | inotify_init1 | V1 | |
| 295 | preadv | V1 | |
| 296 | pwritev | V1 | |
| 297 | rt_tgsigqueueinfo | V1 | |
| 298 | perf_event_open | V2 | Hardware PMU access for `perf`. Subset in v2. |
| 299 | recvmmsg | V1 | |
| 300 | fanotify_init | V2 | |
| 301 | fanotify_mark | V2 | |
| 302 | prlimit64 | V1 | |
| 303 | name_to_handle_at | V2 | NFS-style file handles. |
| 304 | open_by_handle_at | V2 | |
| 305 | clock_adjtime | V2 | |
| 306 | syncfs | V1 | |
| 307 | sendmmsg | V1 | |
| 308 | setns | V1 | |
| 309 | getcpu | V1 | vDSO-served. |
| 310 | process_vm_readv | V1 | |
| 311 | process_vm_writev | V1 | |
| 312 | kcmp | V2 | Used by CRIU; v2. |
| 313 | finit_module | V1 | Modular kernel: load `.ko` from fd, signature-checked. |
| 314 | sched_setattr | V1 | |
| 315 | sched_getattr | V1 | |
| 316 | renameat2 | V1 | Adds `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`. |
| 317 | seccomp | V1 | `SECCOMP_SET_MODE_STRICT` and `SECCOMP_SET_MODE_FILTER`. Filter requires the BPF verifier (V2). v1.0 ships with strict mode only; filter mode returns `ENOSYS` until BPF lands. |
| 318 | getrandom | V1 | |
| 319 | memfd_create | V1 | |
| 320 | kexec_file_load | V2 | |
| 321 | bpf | V2 | BPF deferred to v2; a substantial subsystem. |
| 322 | execveat | V1 | |
| 323 | userfaultfd | V1 | Required by Go runtime, CRIU. |
| 324 | membarrier | V1 | |
| 325 | mlock2 | V1 | |
| 326 | copy_file_range | V1 | |
| 327 | preadv2 | V1 | |
| 328 | pwritev2 | V1 | |
| 329 | pkey_mprotect | V2 | Memory protection keys. |
| 330 | pkey_alloc | V2 | |
| 331 | pkey_free | V2 | |
| 332 | statx | V1 | Modern stat. |
| 333 | io_pgetevents | NEVER | POSIX AIO. |
| 334 | rseq | V1 | Restartable sequences; required by glibc/musl. |
| 424 | pidfd_send_signal | V1 | |
| 425 | io_uring_setup | V2 | v2 phase 23; v1.0 stubs. |
| 426 | io_uring_enter | V2 | |
| 427 | io_uring_register | V2 | |
| 428 | open_tree | V1 | New mount API. |
| 429 | move_mount | V1 | New mount API. |
| 430 | fsopen | V1 | New mount API. |
| 431 | fsconfig | V1 | New mount API. |
| 432 | fsmount | V1 | New mount API. |
| 433 | fspick | V1 | New mount API. |
| 434 | pidfd_open | V1 | |
| 435 | clone3 | V1 | The modern clone. Primary process/thread create syscall. |
| 436 | close_range | V1 | |
| 437 | openat2 | V1 | With `RESOLVE_*` flags for safe path resolution. |
| 438 | pidfd_getfd | V1 | |
| 439 | faccessat2 | V1 | |
| 440 | process_madvise | V2 | Required by some modern OOM-killer userspace. |
| 441 | epoll_pwait2 | V1 | |
| 442 | mount_setattr | V1 | New mount API. |
| 443 | quotactl_fd | V2 | |
| 444 | landlock_create_ruleset | V2 | Landlock; the v1 sandboxing primitive. v1.0 may stub. |
| 445 | landlock_add_rule | V2 | |
| 446 | landlock_restrict_self | V2 | |
| 447 | memfd_secret | V1 | |
| 448 | process_mrelease | V2 | |
| 449 | futex_waitv | V1 | Modern futex; vector wait. |
| 450 | set_mempolicy_home_node | V2 | NUMA. |
| 451 | cachestat | V1 | Page-cache visibility. |
| 452 | fchmodat2 | V1 | |
| 453 | map_shadow_stack | V2 | CET shadow-stack. |
| 454 | futex_wake | V1 | |
| 455 | futex_wait | V1 | |
| 456 | futex_requeue | V1 | |
| 457 | statmount | V1 | |
| 458 | listmount | V1 | |
| 459 | lsm_get_self_attr | V2 | LSM stacking is v2. |
| 460 | lsm_set_self_attr | V2 | |
| 461 | lsm_list_modules | V2 | |

Numbers 335..423 = gaps (Linux x86_64 arch-specific / aarch64-only ranges). Treated **STUB** (`ENOSYS`); reserved.

## 3 Oxide-private extensions

No new syscall numbers invented. Oxide-specific functionality via: `prctl` sub-codes (`PR_OXIDE_*` namespaced in unused range); `ioctl` on `/dev/oxide-ctl`; sysfs/configfs interface. Keeps ABI Linux-compatible; additions can't collide with future Linux additions.

## 4 Dispatch (`crates/syscall/src/lib.rs`)

```rust
pub struct SyscallArgs { pub a0:u64, pub a1:u64, pub a2:u64, pub a3:u64, pub a4:u64, pub a5:u64 }
pub type SyscallFn = fn(&SyscallArgs) -> KR<u64>;

pub static SYSCALL_TABLE: [SyscallFn; 462] = {
  let mut t = [sys_enosys as SyscallFn; 462];
  t[0] = sys_read; t[1] = sys_write; /* ... */
  t
};

pub fn dispatch(nr:u32, args:&SyscallArgs) -> i64 {
  let f = SYSCALL_TABLE.get(nr as usize).copied().unwrap_or(sys_enosys);
  match f(args) { Ok(v) => v as i64, Err(e) => -(e as i64) }
}
```

Static-array lookup O(1). Numbers > table size → `ENOSYS`. Each `sys_*` takes typed args (constructed from `SyscallArgs` via `UserPtr::new` bound-check) returns `KR<u64>`.

### 4.1 Arch trampoline

`hal-x86_64::syscall_entry` / `hal-aarch64::syscall_entry`:
1. Save user regs to per-CPU kernel stack (or task's saved-context area).
2. KPTI: swap to kernel PT root.
3. Load kernel `gs_base`/`tpidr_el1`.
4. Call `dispatch(nr, &args)`.
5. Reverse: user CR3/TTBR0, restore regs, return.

Per-arch trampoline ≤200 lines `.S`; reviewed line-by-line. See `20`,`21`.

## 5 ABI-shaped types (in `userspace-abi` crate)

`iovec`,`timespec`(time_t=i64),`timeval`,`sockaddr*` (`_in`,`_in6`,`_un`),`stat` (legacy; `fstat` only),`statx`+`statx_timestamp`,`epoll_event`+`epoll_data`,`sigaction`+`siginfo_t`+`ucontext_t`+`mcontext_t` (per-arch),`rusage`,`rlimit64`,`dirent64`,`cmsghdr`+`msghdr`+`mmsghdr`,`clone_args` (clone3),`open_how` (openat2),`io_uring_*` (v2).

Each `#[repr(C)]` + `static_assertions::assert_eq_size!` vs Linux struct layout per arch.

## 6 ABI bit-flag tables

These are the bit-flag constants passed in syscall registers. They are the **syscall surface only** — internal kernel types (e.g., `OpenIntent`, `VmaProt`) are constructed from them at dispatch and used everywhere thereafter. Numeric values match Linux x86_64 exactly.

### 6.1 `open`/`openat`/`openat2` flags

```rust
pub mod open_flags {
    pub const O_RDONLY    : u32 = 0o0;
    pub const O_WRONLY    : u32 = 0o1;
    pub const O_RDWR      : u32 = 0o2;
    pub const O_ACCMODE   : u32 = 0o3;
    pub const O_CREAT     : u32 = 0o100;
    pub const O_EXCL      : u32 = 0o200;
    pub const O_NOCTTY    : u32 = 0o400;
    pub const O_TRUNC     : u32 = 0o1000;
    pub const O_APPEND    : u32 = 0o2000;
    pub const O_NONBLOCK  : u32 = 0o4000;
    pub const O_DSYNC     : u32 = 0o10000;
    pub const O_DIRECT    : u32 = 0o40000;
    pub const O_LARGEFILE : u32 = 0o100000;
    pub const O_DIRECTORY : u32 = 0o200000;
    pub const O_NOFOLLOW  : u32 = 0o400000;
    pub const O_NOATIME   : u32 = 0o1000000;
    pub const O_CLOEXEC   : u32 = 0o2000000;
    pub const O_PATH      : u32 = 0o10000000;
    pub const O_TMPFILE   : u32 = 0o20000000 | O_DIRECTORY;
    pub const __O_SYNC    : u32 = 0o4000000;
    pub const O_SYNC      : u32 = __O_SYNC | O_DSYNC;
}

/// `openat2` extension. Used as the `resolve` field of `struct open_how`.
pub mod resolve_flags {
    pub const RESOLVE_NO_XDEV       : u64 = 0x01;
    pub const RESOLVE_NO_MAGICLINKS : u64 = 0x02;
    pub const RESOLVE_NO_SYMLINKS   : u64 = 0x04;
    pub const RESOLVE_BENEATH       : u64 = 0x08;
    pub const RESOLVE_IN_ROOT       : u64 = 0x10;
    pub const RESOLVE_CACHED        : u64 = 0x20;
}
```

### 6.2 `mmap`/`mprotect` flags

```rust
pub mod mmap_flags {
    pub const PROT_NONE  : u32 = 0;
    pub const PROT_READ  : u32 = 1;
    pub const PROT_WRITE : u32 = 2;
    pub const PROT_EXEC  : u32 = 4;
    pub const PROT_GROWSDOWN : u32 = 0x01000000;
    pub const PROT_GROWSUP   : u32 = 0x02000000;

    pub const MAP_SHARED            : u32 = 0x01;
    pub const MAP_PRIVATE           : u32 = 0x02;
    pub const MAP_SHARED_VALIDATE   : u32 = 0x03;
    pub const MAP_FIXED             : u32 = 0x10;
    pub const MAP_FIXED_NOREPLACE   : u32 = 0x100000;
    pub const MAP_ANONYMOUS         : u32 = 0x20;
    pub const MAP_GROWSDOWN         : u32 = 0x100;
    pub const MAP_NORESERVE         : u32 = 0x4000;
    pub const MAP_POPULATE          : u32 = 0x8000;
    pub const MAP_NONBLOCK          : u32 = 0x10000;
    pub const MAP_STACK             : u32 = 0x20000;
    pub const MAP_HUGETLB           : u32 = 0x40000;
    pub const MAP_SYNC              : u32 = 0x80000;
    pub const MAP_HUGE_2MB          : u32 = 21 << 26;
    pub const MAP_HUGE_1GB          : u32 = 30 << 26;
}
```

### 6.3 `madvise` advice values

```rust
pub mod madv {
    pub const MADV_NORMAL      : i32 = 0;
    pub const MADV_RANDOM      : i32 = 1;
    pub const MADV_SEQUENTIAL  : i32 = 2;
    pub const MADV_WILLNEED    : i32 = 3;
    pub const MADV_DONTNEED    : i32 = 4;
    pub const MADV_FREE        : i32 = 8;
    pub const MADV_REMOVE      : i32 = 9;
    pub const MADV_DONTFORK    : i32 = 10;
    pub const MADV_DOFORK      : i32 = 11;
    pub const MADV_HWPOISON    : i32 = 100;
    pub const MADV_MERGEABLE   : i32 = 12;
    pub const MADV_UNMERGEABLE : i32 = 13;
    pub const MADV_HUGEPAGE    : i32 = 14;
    pub const MADV_NOHUGEPAGE  : i32 = 15;
    pub const MADV_DONTDUMP    : i32 = 16;
    pub const MADV_DODUMP      : i32 = 17;
    pub const MADV_WIPEONFORK  : i32 = 18;
    pub const MADV_KEEPONFORK  : i32 = 19;
    pub const MADV_COLD        : i32 = 20;
    pub const MADV_PAGEOUT     : i32 = 21;
    pub const MADV_POPULATE_READ  : i32 = 22;
    pub const MADV_POPULATE_WRITE : i32 = 23;
    pub const MADV_DONTNEED_LOCKED: i32 = 24;
    pub const MADV_COLLAPSE    : i32 = 25;
}
```

### 6.4 File mode bits (`mode_t`)

```rust
/// File mode bits. Unix-standard: type (top 4 bits) + perms (low 12).
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct FileMode(pub u32);

pub mod mode {
    pub const S_IFMT   : u32 = 0o170000;
    pub const S_IFSOCK : u32 = 0o140000;
    pub const S_IFLNK  : u32 = 0o120000;
    pub const S_IFREG  : u32 = 0o100000;
    pub const S_IFBLK  : u32 = 0o060000;
    pub const S_IFDIR  : u32 = 0o040000;
    pub const S_IFCHR  : u32 = 0o020000;
    pub const S_IFIFO  : u32 = 0o010000;
    pub const S_ISUID  : u32 = 0o004000;
    pub const S_ISGID  : u32 = 0o002000;
    pub const S_ISVTX  : u32 = 0o001000;
    pub const S_IRWXU  : u32 = 0o000700;
    pub const S_IRUSR  : u32 = 0o000400;
    pub const S_IWUSR  : u32 = 0o000200;
    pub const S_IXUSR  : u32 = 0o000100;
    pub const S_IRWXG  : u32 = 0o000070;
    pub const S_IRGRP  : u32 = 0o000040;
    pub const S_IWGRP  : u32 = 0o000020;
    pub const S_IXGRP  : u32 = 0o000010;
    pub const S_IRWXO  : u32 = 0o000007;
    pub const S_IROTH  : u32 = 0o000004;
    pub const S_IWOTH  : u32 = 0o000002;
    pub const S_IXOTH  : u32 = 0o000001;
}
```

### 6.5 `clone3` flags

```rust
pub mod clone {
    pub const CLONE_NEWTIME      : u64 = 0x00000080;
    pub const CLONE_VM           : u64 = 0x00000100;
    pub const CLONE_FS           : u64 = 0x00000200;
    pub const CLONE_FILES        : u64 = 0x00000400;
    pub const CLONE_SIGHAND      : u64 = 0x00000800;
    pub const CLONE_PIDFD        : u64 = 0x00001000;
    pub const CLONE_PTRACE       : u64 = 0x00002000;
    pub const CLONE_VFORK        : u64 = 0x00004000;
    pub const CLONE_PARENT       : u64 = 0x00008000;
    pub const CLONE_THREAD       : u64 = 0x00010000;
    pub const CLONE_NEWNS        : u64 = 0x00020000;
    pub const CLONE_SYSVSEM      : u64 = 0x00040000;     // STUB; SysV IPC dropped
    pub const CLONE_SETTLS       : u64 = 0x00080000;
    pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
    pub const CLONE_CHILD_CLEARTID:u64 = 0x00200000;
    pub const CLONE_DETACHED     : u64 = 0x00400000;     // legacy, ignored
    pub const CLONE_UNTRACED     : u64 = 0x00800000;
    pub const CLONE_CHILD_SETTID : u64 = 0x01000000;
    pub const CLONE_NEWCGROUP    : u64 = 0x02000000;
    pub const CLONE_NEWUTS       : u64 = 0x04000000;
    pub const CLONE_NEWIPC       : u64 = 0x08000000;
    pub const CLONE_NEWUSER      : u64 = 0x10000000;
    pub const CLONE_NEWPID       : u64 = 0x20000000;
    pub const CLONE_NEWNET       : u64 = 0x40000000;
    pub const CLONE_IO           : u64 = 0x80000000;

    // clone3-only:
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;
    pub const CLONE_INTO_CGROUP  : u64 = 0x200000000;
}
```

### 6.6 `fcntl` commands

```rust
pub mod fcntl {
    pub const F_DUPFD          : i32 = 0;
    pub const F_GETFD          : i32 = 1;
    pub const F_SETFD          : i32 = 2;
    pub const F_GETFL          : i32 = 3;
    pub const F_SETFL          : i32 = 4;
    pub const F_GETLK          : i32 = 5;
    pub const F_SETLK          : i32 = 6;
    pub const F_SETLKW         : i32 = 7;
    pub const F_SETOWN         : i32 = 8;
    pub const F_GETOWN         : i32 = 9;
    pub const F_SETSIG         : i32 = 10;
    pub const F_GETSIG         : i32 = 11;
    pub const F_SETOWN_EX      : i32 = 15;
    pub const F_GETOWN_EX      : i32 = 16;
    pub const F_GETOWNER_UIDS  : i32 = 17;
    pub const F_OFD_GETLK      : i32 = 36;
    pub const F_OFD_SETLK      : i32 = 37;
    pub const F_OFD_SETLKW     : i32 = 38;
    pub const F_DUPFD_CLOEXEC  : i32 = 1024 + 6;
    pub const F_SETPIPE_SZ     : i32 = 1024 + 7;
    pub const F_GETPIPE_SZ     : i32 = 1024 + 8;
    pub const F_ADD_SEALS      : i32 = 1024 + 9;
    pub const F_GET_SEALS      : i32 = 1024 + 10;
    pub const F_GET_RW_HINT    : i32 = 1024 + 11;
    pub const F_SET_RW_HINT    : i32 = 1024 + 12;
    pub const F_GET_FILE_RW_HINT: i32 = 1024 + 13;
    pub const F_SET_FILE_RW_HINT: i32 = 1024 + 14;
}
```

### 6.7 Remaining flag tables

The following exist in this section but are listed by reference, not duplicated here when they fit naturally inside their subsystem spec:

| Domain | Living in |
|---|---|
| Socket types/options (`SOCK_*`, `SO_*`, `IPPROTO_*`) | `25-net.md` §X (ABI surface) |
| Signal flags (`SA_*`, `SS_*`) | `24-ipc.md` §X (signal subsystem) |
| Mount flags (`MS_*`, `MOUNT_ATTR_*`) | `16-vfs.md` §X |
| Seccomp constants | `27-security.md` |
| Cgroup constants | `26-namespaces-cgroups.md` |
| `epoll` events (`EPOLLIN`, …) | `24-ipc.md` |
| `prctl` codes | `27-security.md` (most) and `25-net.md` (a few) |
| Module flags (`MODULE_INIT_*`) | `18-modules.md` |
| `io_uring` opcodes | `30-io-uring.md` |

Each subsystem spec mirrors this rule: if the constant is *only* read at one syscall's boundary and never used internally, it lives in the subsystem spec, not here. If a constant is used by ≥2 syscall handlers across subsystems, it lives in this file.

The ones in §6.1–§6.6 above qualify because they are referenced by multiple syscall handlers across subsystem boundaries.

### 6.7 UAPI surface boundary

UAPI = the union of types and numbers userspace can rely on:

| Source | Content |
|---|---|
| `15§1` | calling convention per arch |
| `15§2` | syscall numbers + dispositions |
| `15§6` | ABI struct layouts |
| `15§8` | vDSO entry symbols + signatures |
| `01§6` | errno table |
| `01§7` | signal numbers |

Everything else is **kernel-internal** per `01§10`: subsystem `Error`/`KResult`, lock primitives, slab caches, scheduler state, internal trait sigs. Userspace must never depend on those.

Mechanical export: `xtask uapi-export` walks the listed sections + their cross-referenced types and emits `userspace/uapi/oxide/*.h` + `*.rs`. The musl fork (`29§4`, `29a§3`) reads from there. Build-chain step 2 per `07§3.4`.

In-tree single source of truth = `crates/uapi/` (kernel side); `userspace/uapi/` is its generated export tree. Kernel code that touches UAPI imports `crates/uapi/`; userspace consumers see the exported tree only.

Static-assert per arch (already in §9 test contract): every ABI struct in `userspace-abi` matches Linux layout. The export step is the production form of that assertion.

---

## 7 Errno mapping

Every `sys_*` returns `KR<u64>`. `Errno` per `01§6` = sole error type. Dispatch converts to `-errno` on egress. No "kernel-internal error type" mapped at boundary; internal code uses `KR<T>` end-to-end; Errno chosen at failure site is what user sees.

## 8 vDSO

Small RX ELF blob mapped into every user AS. Exports:
- `__vdso_clock_gettime(clk_id, *ts)`
- `__vdso_clock_getres(clk_id, *res)`
- `__vdso_gettimeofday(*tv, *tz)`
- `__vdso_time(*t)` (legacy; provided so it doesn't trap)
- `__vdso_getcpu(*cpu, *node)`

Per-arch impls in `crates/vdso-x86_64/`,`crates/vdso-aarch64/`. Time data in per-CPU page; kernel updates from timer ISR; vDSO reads lockless via seqlock (`06§3.4`). Layout: `23§9`.

## 9 Test contract (frozen)

- `SYSCALL_TABLE` populated 0..=461; gaps = `sys_enosys`.
- Fuzz: every nr 0..2048 with random args; no panic; nr>461 → `-ENOSYS(38)`.
- Static-assert: every ABI struct in `userspace-abi` matches Linux layout (size+align+field offsets) per arch via `static_assertions`.
- Property `UserPtr<T>::read/write` vs oracle: random ptrs (user/kernel/unmapped), random sizes; `EFAULT` ⇔ unmapped OR kernel-side.
- Trampoline review: `hal-*::syscall_entry` cited line-by-line vs SysV (x86) / AAPCS (arm) ABI docs; review notes committed.
- Boot+run: static-musl binary calls `getpid`, `write(1,"hi\n",3)`, `exit(0)`. Serial = `hi\n`, exit 0.

## 10 Cross-spec

Touched by every subsystem spec (user-facing surface):
`16` (read/write/open/close/...), `13` (sched_*, clone3, exit), `11` (mmap/mprotect/munmap/mremap), `17` (pread/pwrite/fsync), `25` (socket/...), `23` (clock_*, vDSO), `27` (seccomp/landlock_*/capset), `26` (unshare/setns/clone3 ns flags), `30` v2 (io_uring_*), `18` (finit_module/delete_module).

## 11 Changelog

(none)

