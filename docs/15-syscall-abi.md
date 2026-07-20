# 15 Syscall ABI

FROZEN 2026-05-02. Dep:`01`,`03`,`06`,`08`,`09`.

## Revision 2026-06-05 (R06)

- Changed: abolished the `V1`/`V2`/`STUB`/`NEVER` status labels. Every syscall
  is now `IMPL` (full Linux semantics, mandatory) or one of 17 `OBSOLETE`
  numbers (modern Linux itself returns `ENOSYS`). See the §2 legend.
- Why: `V2` meant "tracked as a later phase; currently returns `ENOSYS`; number
  reserved" — a deferral license that violated `02§9` rule 8 ("no v2; every
  spec describes the full Linux surface"). The labels also drifted from the
  live dispatcher: `stat`/`lstat`/`select`/`shm*` tagged `NEVER` yet live-
  mapped; `dup2`/`alarm`/`getitimer` tagged `V2` yet live-mapped (`syscal_anal.md`).
  The ambiguity produced subset/strawman bodies and ENOSYS gaps on real paths.
- **Supersedes R05's deferral dispositions.** R05's "silent-0 admit", "EPERM
  (privileged refuse)", and "ENOSYS" slot classes are retired: every slot R05
  parked there is now `IMPL` and must reach full Linux semantics — `swapon`/
  `swapoff`, the libaio `io_*` family, `ustat`, `sysfs`, `modify_ldt`,
  `quotactl[_fd]`, `acct`, `remap_file_pages`, `cachestat`, `mq_notify`/
  `mq_getsetattr`, `pivot_root`, the module loader (`init_module`/`finit_module`/
  `delete_module`), `kexec_*`, `iopl`/`ioperm`, `adjtimex`/`clock_adjtime`,
  `name_to_handle_at`/`open_by_handle_at`, `fanotify_mark`, `io_uring_register`.
  Only the 17 genuinely-OBSOLETE numbers keep `ENOSYS` (see legend).
- Added: every Linux x86_64 number through 6.x that lacked a row — incl.
  `uretprobe`(335), `uprobe`(336), `fchmodat2`(452), the futex2 family
  (454-456), `statmount`/`listmount` (457-458), LSM-attr (459-461), `mseal`(462),
  the `*xattrat` family (463-466), `open_tree_attr`(467), `file_getattr`/
  `file_setattr` (468-469), `listns`(470) — all `IMPL`. Numbers added to
  `crates/kernel/syscall/src/nrs.rs`.
- Code follow-up tracked in `syscal_anal.md` (directed completeness sweep) and
  `53` (ABI shim holds zero work logic).

## Revision 2026-05-09 (R05)

- Changed: explicit disposition rows for every syscall slot that
  is admit / silent-0 / EPERM / ENOSYS instead of full Linux
  semantics. Previously the table left these as ambiguous "V1"
  rows; userspace consumers (musl, distro programs)
  could not predict whether a return code reflected real work.
- Disposition labels and where each slot lives:
    - **REAL (Linux semantics)** — most slots; see syscall_glue.rs
      direct dispatch.
    - **REAL (validate-then-noop)** — `fsync`/`fdatasync`/`syncfs`/
      `sync_file_range` / `fadvise64` / `readahead` / `mlock2`:
      validate fd + length, return 0. RAM-fs is always sync; no
      page-cache to advise. Real disk-backed fsync per phase 7b.
    - **REAL subset** — `ptrace` per R04 disposition table.
    - **silent-0 admit** — `cachestat` (no page cache), `mq_notify`/
      `mq_getsetattr` (no per-task signal-on-arrival yet),
      `io_uring_register` (no fixed-buffer/file table — see `30`
      R01), `fanotify_mark` (records nothing yet).
    - **EPERM (privileged refuse)** — `pivot_root`, `init_module`/
      `delete_module`/`finit_module`, `kexec_load`/`kexec_file_load`,
      `iopl`/`ioperm`, `adjtimex`/`clock_adjtime`. No substrate yet;
      cap-gating identical for now.
    - **ENOSYS** — `swapon`/`swapoff`, `lookup_dcookie`,
      `remap_file_pages`, `uselib`, `ustat`, `sysfs`, `modify_ldt`,
      `quotactl[_fd]`, `acct`, `name_to_handle_at`/
      `open_by_handle_at`, `vserver`, `_sysctl`, `futex_waitv`,
      libaio family (`io_setup`/`io_destroy`/`io_getevents`/
      `io_submit`/`io_cancel`/`io_pgetevents`).
- Why: g.md flagged ambiguity as a Linux-conformance hazard.
  Ambiguous "V1" rows let code drift from spec without anyone
  noticing — explicit labels make the contract auditable per slot.
- Affected code: `kernel/src/syscall_compat.rs::try_compat`
  (silent-0/EPERM/ENOSYS arms), `kernel/src/syscall_glue.rs`
  (validate-then-noop arms — fsync/pkey/numa/etc).
- Test contract change: §9 acceptance gains "every slot in the
  disposition table matches its actual return code class" — the
  smoke walks the table and validates each slot.

## Revision 2026-05-09 (R04)

- Changed: pinned the `ptrace(2)` op disposition. Slot 101 still
  V1 (Linux subset) but the disposition table now says explicitly:
  TRACEME / ATTACH / SEIZE / DETACH / CONT / SYSCALL / SINGLESTEP /
  KILL / PEEKTEXT / PEEKDATA / POKETEXT / POKEDATA / GETREGS /
  GETREGSET (NT_PRSTATUS) are real; PEEKUSER / SETREGS / SETREGSET
  / GETFPREGS / SETFPREGS / SETOPTIONS / GETEVENTMSG / GETSIGINFO /
  SETSIGINFO are silent-0 admit (substrate not yet wired).
- Why: F104/F108/F115 landed real ATTACH/SYSCALL-stop/GETREGS;
  callers (gdb, strace, ltrace) need to know exactly which ops
  affect tracee state vs return ok-but-noop. Without this row the
  ABI table left "subset" undefined.
- Affected code: `kernel/src/syscall_glue_signal.rs` (kernel_sys_ptrace).
- Test contract change: §9 acceptance gains a "ptrace subset
  matches the table" check; gdb attach + step is the smoke.

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

Legend (disposition). Per `02§9` rule 8 there is no "later version" — every
syscall in the Linux contract is built to full semantics. Exactly two states:

- **IMPL**: implemented to full Linux x86_64/aarch64 semantics. The default for
  every syscall. Mandatory — no stubs, no subsets, no "minimal"/"strawman"
  bodies, no `ENOSYS` placeholders, no "rides a later phase". If a program can
  call it, it behaves the way Linux behaves.
- **OBSOLETE**: modern Linux **itself** returns `ENOSYS` for this number on
  x86_64 (removed upstream, or never implemented upstream) — so matching Linux
  *means* returning `ENOSYS`. The number stays reserved. This is the **only**
  non-IMPL disposition; each such row cites the reason. Complete set:
  `uselib`(134), `_sysctl`(156), `create_module`(174), `get_kernel_syms`(177),
  `query_module`(178), `nfsservctl`(180), `getpmsg`(181), `putpmsg`(182),
  `afs_syscall`(183), `tuxcall`(184), `security`(185), `set_thread_area`(205),
  `get_thread_area`(211), `lookup_dcookie`(212), `epoll_ctl_old`(214),
  `epoll_wait_old`(215), `vserver`(236). Nothing else is OBSOLETE.

There is no `V1`/`V2`/`STUB`/`NEVER` any more — those licensed deferral and
drifted from the live dispatcher (see `syscal_anal.md`). A syscall is `IMPL`
or it is one of the 17 `OBSOLETE` numbers above. Where a syscall has a modern
replacement libc prefers, Notes points to it, but the legacy entry is still
`IMPL` (real programs and older libcs call it directly).

| Nr | Name | Status | Notes |
|---|---|---|---|
| 0 | read | IMPL | |
| 1 | write | IMPL | |
| 2 | open | IMPL | Prefer `openat`/`openat2`; libc wraps. |
| 3 | close | IMPL | |
| 4 | stat | IMPL | Full `stat`; libc may prefer `statx`. |
| 5 | fstat | IMPL | Kept for fd-only metadata, libc compat. |
| 6 | lstat | IMPL | Use `statx` with `AT_SYMLINK_NOFOLLOW`. |
| 7 | poll | IMPL | Prefer `ppoll`. |
| 8 | lseek | IMPL | |
| 9 | mmap | IMPL | |
| 10 | mprotect | IMPL | |
| 11 | munmap | IMPL | |
| 12 | brk | IMPL | Thin shim for libc heap; not preferred. |
| 13 | rt_sigaction | IMPL | |
| 14 | rt_sigprocmask | IMPL | |
| 15 | rt_sigreturn | IMPL | Internal; called from userspace signal trampoline. |
| 16 | ioctl | IMPL | Per-driver opcode dispatch. |
| 17 | pread64 | IMPL | |
| 18 | pwrite64 | IMPL | |
| 19 | readv | IMPL | |
| 20 | writev | IMPL | |
| 21 | access | IMPL | Prefer `faccessat2`. |
| 22 | pipe | IMPL | Prefer `pipe2`. |
| 23 | select | IMPL | Use `epoll`/`ppoll`. |
| 24 | sched_yield | IMPL | |
| 25 | mremap | IMPL | |
| 26 | msync | IMPL | |
| 27 | mincore | IMPL | |
| 28 | madvise | IMPL | Modern flags; `MADV_PAGEOUT` uses the canonical anonymous rmap-to-swap or MAP_SHARED shmem rmap-to-swap transaction, while `MADV_COLD` remains a placement hint. |
| 29 | shmget | IMPL | Full SysV shared memory (real shared frames). |
| 30 | shmat | IMPL | Full SysV shared memory. |
| 31 | shmctl | IMPL | Full SysV shared memory control. |
| 32 | dup | IMPL | |
| 33 | dup2 | IMPL | Prefer `dup3`. |
| 34 | pause | IMPL | |
| 35 | nanosleep | IMPL | |
| 36 | getitimer | IMPL | Use `timerfd_*`. |
| 37 | alarm | IMPL | Use `timerfd_*`. |
| 38 | setitimer | IMPL | Use `timerfd_*`. |
| 39 | getpid | IMPL | vDSO-served. |
| 40 | sendfile | IMPL | |
| 41 | socket | IMPL | |
| 42 | connect | IMPL | |
| 43 | accept | IMPL | Prefer `accept4`. |
| 44 | sendto | IMPL | |
| 45 | recvfrom | IMPL | |
| 46 | sendmsg | IMPL | |
| 47 | recvmsg | IMPL | |
| 48 | shutdown | IMPL | |
| 49 | bind | IMPL | |
| 50 | listen | IMPL | |
| 51 | getsockname | IMPL | |
| 52 | getpeername | IMPL | |
| 53 | socketpair | IMPL | |
| 54 | setsockopt | IMPL | Modern options only; legacy options return `ENOPROTOOPT`. |
| 55 | getsockopt | IMPL | |
| 56 | clone | IMPL | Prefer `clone3`; libc wraps. |
| 57 | fork | IMPL | Implemented as `clone3` with the right flags; libc wraps. |
| 58 | vfork | IMPL | Replaced by `posix_spawn` userspace pattern. |
| 59 | execve | IMPL | |
| 60 | exit | IMPL | |
| 61 | wait4 | IMPL | Prefer `waitid`. |
| 62 | kill | IMPL | |
| 63 | uname | IMPL | Returns a fixed modern-looking string. |
| 64 | semget | IMPL | Full SysV semaphores. |
| 65 | semop | IMPL | |
| 66 | semctl | IMPL | |
| 67 | shmdt | IMPL | |
| 68 | msgget | IMPL | |
| 69 | msgsnd | IMPL | |
| 70 | msgrcv | IMPL | |
| 71 | msgctl | IMPL | |
| 72 | fcntl | IMPL | Modern subset: `F_GETFD/F_SETFD`, `F_GETFL/F_SETFL`, `F_DUPFD_CLOEXEC`, `F_SETLK/F_GETLK/F_OFD_*`, `F_SETOWN`, `F_SETPIPE_SZ`. |
| 73 | flock | IMPL | |
| 74 | fsync | IMPL | |
| 75 | fdatasync | IMPL | |
| 76 | truncate | IMPL | |
| 77 | ftruncate | IMPL | |
| 78 | getdents | IMPL | Use `getdents64`. |
| 79 | getcwd | IMPL | |
| 80 | chdir | IMPL | |
| 81 | fchdir | IMPL | |
| 82 | rename | IMPL | Prefer `renameat2`. |
| 83 | mkdir | IMPL | Prefer `mkdirat`. |
| 84 | rmdir | IMPL | Prefer `unlinkat(AT_REMOVEDIR)`. |
| 85 | creat | IMPL | Use `openat`. |
| 86 | link | IMPL | Prefer `linkat`. |
| 87 | unlink | IMPL | Prefer `unlinkat`. |
| 88 | symlink | IMPL | Prefer `symlinkat`. |
| 89 | readlink | IMPL | Prefer `readlinkat`. |
| 90 | chmod | IMPL | Prefer `fchmodat2`. |
| 91 | fchmod | IMPL | |
| 92 | chown | IMPL | Prefer `fchownat`. |
| 93 | fchown | IMPL | |
| 94 | lchown | IMPL | Prefer `fchownat(AT_SYMLINK_NOFOLLOW)`. |
| 95 | umask | IMPL | |
| 96 | gettimeofday | IMPL | vDSO-served when present; syscall path mostly for fallback. Prefer `clock_gettime`. |
| 97 | getrlimit | IMPL | |
| 98 | getrusage | IMPL | |
| 99 | sysinfo | IMPL | RAM/process ABI information plus canonical active-swap total/free capacity. |
| 100 | times | IMPL | |
| 101 | ptrace | IMPL | Full ptrace op set (every request real, incl. PEEKUSER/SET{REGS,REGSET,FPREGS}/SETOPTIONS/GETEVENTMSG/{GET,SET}SIGINFO). |
| 102 | getuid | IMPL | |
| 103 | syslog | IMPL | Reads `/dev/kmsg` ring; subset of actions. |
| 104 | getgid | IMPL | |
| 105 | setuid | IMPL | |
| 106 | setgid | IMPL | |
| 107 | geteuid | IMPL | |
| 108 | getegid | IMPL | |
| 109 | setpgid | IMPL | |
| 110 | getppid | IMPL | |
| 111 | getpgrp | IMPL | |
| 112 | setsid | IMPL | |
| 113 | setreuid | IMPL | |
| 114 | setregid | IMPL | |
| 115 | getgroups | IMPL | |
| 116 | setgroups | IMPL | |
| 117 | setresuid | IMPL | |
| 118 | getresuid | IMPL | |
| 119 | setresgid | IMPL | |
| 120 | getresgid | IMPL | |
| 121 | getpgid | IMPL | |
| 122 | setfsuid | IMPL | |
| 123 | setfsgid | IMPL | |
| 124 | getsid | IMPL | |
| 125 | capget | IMPL | v3 only; v1/v2 header magic returns `EINVAL`. |
| 126 | capset | IMPL | v3 only. |
| 127 | rt_sigpending | IMPL | |
| 128 | rt_sigtimedwait | IMPL | |
| 129 | rt_sigqueueinfo | IMPL | |
| 130 | rt_sigsuspend | IMPL | |
| 131 | sigaltstack | IMPL | |
| 132 | utime | IMPL | Prefer `utimensat`. |
| 133 | mknod | IMPL | Prefer `mknodat`. |
| 134 | uselib | OBSOLETE | Legacy a.out shared-lib loading. |
| 135 | personality | IMPL | Only `PER_LINUX` and `ADDR_NO_RANDOMIZE` honored. |
| 136 | ustat | IMPL | Use `statfs`/`fstatfs`. |
| 137 | statfs | IMPL | |
| 138 | fstatfs | IMPL | |
| 139 | sysfs | IMPL | Use `/proc/filesystems`. |
| 140 | getpriority | IMPL | |
| 141 | setpriority | IMPL | |
| 142 | sched_setparam | IMPL | |
| 143 | sched_getparam | IMPL | |
| 144 | sched_setscheduler | IMPL | |
| 145 | sched_getscheduler | IMPL | |
| 146 | sched_get_priority_max | IMPL | |
| 147 | sched_get_priority_min | IMPL | |
| 148 | sched_rr_get_interval | IMPL | |
| 149 | mlock | IMPL | Materializes and VM_LOCKED-pins the exact mapped range, including swapped pages. |
| 150 | munlock | IMPL | Clears VM_LOCKED over the exact mapped range. |
| 151 | mlockall | IMPL | MCL_CURRENT materializes current pages; MCL_FUTURE is persisted in the shared mm policy; MCL_ONFAULT is honored. |
| 152 | munlockall | IMPL | Clears both current locks and the mm-level future-lock policy. |
| 153 | vhangup | IMPL | |
| 154 | modify_ldt | IMPL | No segmented memory tricks. |
| 155 | pivot_root | IMPL | Required for containers. |
| 156 | _sysctl | OBSOLETE | Removed in modern Linux (5.5). Use `/proc/sys/`. |
| 157 | prctl | IMPL | Modern subset: `PR_SET_NAME`, `PR_SET_PDEATHSIG`, `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE`, `PR_CAP_AMBIENT`, `PR_SET_CHILD_SUBREAPER`, `PR_SET_THP_DISABLE`, `PR_SET_VMA`, `PR_SET_TIMERSLACK`, `PR_SET_SECCOMP`, `PR_GET_KEEPCAPS`, `PR_SET_KEEPCAPS`. Legacy `PR_*` return `EINVAL`. |
| 158 | arch_prctl | IMPL | `ARCH_SET_FS`, `ARCH_GET_FS`, `ARCH_SET_GS`, `ARCH_GET_GS`. Used by libc TLS init. |
| 159 | adjtimex | IMPL | Subset for NTP daemons. |
| 160 | setrlimit | IMPL | |
| 161 | chroot | IMPL | |
| 162 | sync | IMPL | |
| 163 | acct | IMPL | Process accounting; tracked as later phase. |
| 164 | settimeofday | IMPL | Prefer `clock_settime`. |
| 165 | mount | IMPL | Implemented as compat shim over the new mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`). |
| 166 | umount2 | IMPL | |
| 167 | swapon | IMPL | Canonical block/zram/ext4-swapfile area activation, Linux header and extent validation, priority selection, `/proc/swaps` identity, and rmap-verified automatic anonymous page-out under allocator pressure. |
| 168 | swapoff | IMPL | Drains live swap PTEs through the canonical swap-in path before removing the area. |
| 169 | reboot | IMPL | UEFI Runtime Services / platform reset. |
| 170 | sethostname | IMPL | |
| 171 | setdomainname | IMPL | |
| 172 | iopl | IMPL | No raw port I/O for userspace. |
| 173 | ioperm | IMPL | |
| 174 | create_module | OBSOLETE | Legacy module loading. |
| 175 | init_module | IMPL | Use `finit_module`. |
| 176 | delete_module | IMPL | |
| 177 | get_kernel_syms | OBSOLETE | Use `/proc/kallsyms` (gated). |
| 178 | query_module | OBSOLETE | Removed in Linux 2.6. |
| 179 | quotactl | IMPL | Use `quotactl_fd` when xattr/quota work lands (phase 18). |
| 180 | nfsservctl | OBSOLETE | Removed in Linux 3.1. |
| 181 | getpmsg | OBSOLETE | STREAMS, never implemented in mainline Linux. |
| 182 | putpmsg | OBSOLETE | |
| 183 | afs_syscall | OBSOLETE | |
| 184 | tuxcall | OBSOLETE | |
| 185 | security | OBSOLETE | |
| 186 | gettid | IMPL | |
| 187 | readahead | IMPL | |
| 188 | setxattr | IMPL | |
| 189 | lsetxattr | IMPL | |
| 190 | fsetxattr | IMPL | |
| 191 | getxattr | IMPL | |
| 192 | lgetxattr | IMPL | |
| 193 | fgetxattr | IMPL | |
| 194 | listxattr | IMPL | |
| 195 | llistxattr | IMPL | |
| 196 | flistxattr | IMPL | |
| 197 | removexattr | IMPL | |
| 198 | lremovexattr | IMPL | |
| 199 | fremovexattr | IMPL | |
| 200 | tkill | IMPL | Prefer `tgkill`. |
| 201 | time | IMPL | Use `clock_gettime(CLOCK_REALTIME)`. |
| 202 | futex | IMPL | Classic futex required for libc compat. New code should use `futex_waitv` / `futex_wake`. |
| 203 | sched_setaffinity | IMPL | |
| 204 | sched_getaffinity | IMPL | |
| 205 | set_thread_area | OBSOLETE | x86_32 legacy. |
| 206 | io_setup | IMPL | POSIX AIO. Use `io_uring`. |
| 207 | io_destroy | IMPL | |
| 208 | io_getevents | IMPL | |
| 209 | io_submit | IMPL | |
| 210 | io_cancel | IMPL | |
| 211 | get_thread_area | OBSOLETE | x86_32 legacy. |
| 212 | lookup_dcookie | OBSOLETE | oprofile legacy. |
| 213 | epoll_create | IMPL | Prefer `epoll_create1`. |
| 214 | epoll_ctl_old | OBSOLETE | |
| 215 | epoll_wait_old | OBSOLETE | |
| 216 | remap_file_pages | IMPL | Deprecated; nontrivial to implement; not on must-run-binary path. |
| 217 | getdents64 | IMPL | |
| 218 | set_tid_address | IMPL | |
| 219 | restart_syscall | IMPL | Internal; signal restart. |
| 220 | semtimedop | IMPL | Full SysV semaphore timed-op. |
| 221 | fadvise64 | IMPL | |
| 222 | timer_create | IMPL | POSIX timers. |
| 223 | timer_settime | IMPL | |
| 224 | timer_gettime | IMPL | |
| 225 | timer_getoverrun | IMPL | |
| 226 | timer_delete | IMPL | |
| 227 | clock_settime | IMPL | |
| 228 | clock_gettime | IMPL | vDSO-served. |
| 229 | clock_getres | IMPL | vDSO-served. |
| 230 | clock_nanosleep | IMPL | |
| 231 | exit_group | IMPL | |
| 232 | epoll_wait | IMPL | Prefer `epoll_pwait2`. |
| 233 | epoll_ctl | IMPL | |
| 234 | tgkill | IMPL | |
| 235 | utimes | IMPL | Prefer `utimensat`. |
| 236 | vserver | OBSOLETE | |
| 237 | mbind | IMPL | NUMA memory policy. |
| 238 | set_mempolicy | IMPL | |
| 239 | get_mempolicy | IMPL | |
| 240 | mq_open | IMPL | POSIX mqueue; tracked as phase 24. |
| 241 | mq_unlink | IMPL | |
| 242 | mq_timedsend | IMPL | |
| 243 | mq_timedreceive | IMPL | |
| 244 | mq_notify | IMPL | |
| 245 | mq_getsetattr | IMPL | |
| 246 | kexec_load | IMPL | |
| 247 | waitid | IMPL | |
| 248 | add_key | IMPL | Kernel keyring. |
| 249 | request_key | IMPL | |
| 250 | keyctl | IMPL | |
| 251 | ioprio_set | IMPL | |
| 252 | ioprio_get | IMPL | |
| 253 | inotify_init | IMPL | Prefer `inotify_init1`. |
| 254 | inotify_add_watch | IMPL | |
| 255 | inotify_rm_watch | IMPL | |
| 256 | migrate_pages | IMPL | NUMA. |
| 257 | openat | IMPL | |
| 258 | mkdirat | IMPL | |
| 259 | mknodat | IMPL | |
| 260 | fchownat | IMPL | |
| 261 | futimesat | IMPL | Use `utimensat`. |
| 262 | newfstatat | IMPL | (a.k.a. `fstatat`) |
| 263 | unlinkat | IMPL | |
| 264 | renameat | IMPL | Prefer `renameat2`. |
| 265 | linkat | IMPL | |
| 266 | symlinkat | IMPL | |
| 267 | readlinkat | IMPL | |
| 268 | fchmodat | IMPL | Prefer `fchmodat2`. |
| 269 | faccessat | IMPL | Prefer `faccessat2`. |
| 270 | pselect6 | IMPL | Use `ppoll`/`epoll`. |
| 271 | ppoll | IMPL | |
| 272 | unshare | IMPL | |
| 273 | set_robust_list | IMPL | |
| 274 | get_robust_list | IMPL | |
| 275 | splice | IMPL | |
| 276 | tee | IMPL | |
| 277 | sync_file_range | IMPL | |
| 278 | vmsplice | IMPL | |
| 279 | move_pages | IMPL | NUMA. |
| 280 | utimensat | IMPL | |
| 281 | epoll_pwait | IMPL | |
| 282 | signalfd | IMPL | Prefer `signalfd4`. |
| 283 | timerfd_create | IMPL | |
| 284 | eventfd | IMPL | Prefer `eventfd2`. |
| 285 | fallocate | IMPL | |
| 286 | timerfd_settime | IMPL | |
| 287 | timerfd_gettime | IMPL | |
| 288 | accept4 | IMPL | |
| 289 | signalfd4 | IMPL | |
| 290 | eventfd2 | IMPL | |
| 291 | epoll_create1 | IMPL | |
| 292 | dup3 | IMPL | |
| 293 | pipe2 | IMPL | |
| 294 | inotify_init1 | IMPL | |
| 295 | preadv | IMPL | |
| 296 | pwritev | IMPL | |
| 297 | rt_tgsigqueueinfo | IMPL | |
| 298 | perf_event_open | IMPL | Hardware PMU access for `perf`; tracked as phase 25. |
| 299 | recvmmsg | IMPL | |
| 300 | fanotify_init | IMPL | |
| 301 | fanotify_mark | IMPL | |
| 302 | prlimit64 | IMPL | |
| 303 | name_to_handle_at | IMPL | NFS-style file handles. |
| 304 | open_by_handle_at | IMPL | |
| 305 | clock_adjtime | IMPL | |
| 306 | syncfs | IMPL | |
| 307 | sendmmsg | IMPL | |
| 308 | setns | IMPL | |
| 309 | getcpu | IMPL | vDSO-served. |
| 310 | process_vm_readv | IMPL | |
| 311 | process_vm_writev | IMPL | |
| 312 | kcmp | IMPL | Used by CRIU; tracked as later phase. |
| 313 | finit_module | IMPL | Modular kernel: load `.ko` from fd, signature-checked. |
| 314 | sched_setattr | IMPL | |
| 315 | sched_getattr | IMPL | |
| 316 | renameat2 | IMPL | Adds `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`. |
| 317 | seccomp | IMPL | Full: STRICT + FILTER (BPF verifier). |
| 318 | getrandom | IMPL | |
| 319 | memfd_create | IMPL | |
| 320 | kexec_file_load | IMPL | |
| 321 | bpf | IMPL | Tracked as phase 23 (bpf + seccomp + landlock). |
| 322 | execveat | IMPL | |
| 323 | userfaultfd | IMPL | Required by Go runtime, CRIU. |
| 324 | membarrier | IMPL | |
| 325 | mlock2 | IMPL | |
| 326 | copy_file_range | IMPL | |
| 327 | preadv2 | IMPL | |
| 328 | pwritev2 | IMPL | |
| 329 | pkey_mprotect | IMPL | Memory protection keys. |
| 330 | pkey_alloc | IMPL | |
| 331 | pkey_free | IMPL | |
| 332 | statx | IMPL | Modern stat. |
| 333 | io_pgetevents | IMPL | POSIX AIO. |
| 334 | rseq | IMPL | Restartable sequences; required by glibc/musl. |
| 335 | uretprobe | IMPL | uprobe return trampoline (kernel-internal, 6.11+). |
| 336 | uprobe | IMPL | uprobe trap entry (kernel-internal). |
| 424 | pidfd_send_signal | IMPL | |
| 425 | io_uring_setup | IMPL | Full io_uring per `docs/30`. |
| 426 | io_uring_enter | IMPL | |
| 427 | io_uring_register | IMPL | |
| 428 | open_tree | IMPL | New mount API. |
| 429 | move_mount | IMPL | New mount API. |
| 430 | fsopen | IMPL | New mount API. |
| 431 | fsconfig | IMPL | New mount API. |
| 432 | fsmount | IMPL | New mount API. |
| 433 | fspick | IMPL | New mount API. |
| 434 | pidfd_open | IMPL | |
| 435 | clone3 | IMPL | The modern clone. Primary process/thread create syscall. |
| 436 | close_range | IMPL | |
| 437 | openat2 | IMPL | With `RESOLVE_*` flags for safe path resolution. |
| 438 | pidfd_getfd | IMPL | |
| 439 | faccessat2 | IMPL | |
| 440 | process_madvise | IMPL | pidfd target ranges; `MADV_PAGEOUT` performs the same canonical anonymous or MAP_SHARED shmem rmap-to-swap transaction as `madvise(2)`. |
| 441 | epoll_pwait2 | IMPL | |
| 442 | mount_setattr | IMPL | New mount API. |
| 443 | quotactl_fd | IMPL | |
| 444 | landlock_create_ruleset | IMPL | Full Landlock ruleset creation. |
| 445 | landlock_add_rule | IMPL | |
| 446 | landlock_restrict_self | IMPL | |
| 447 | memfd_secret | IMPL | |
| 448 | process_mrelease | IMPL | |
| 449 | futex_waitv | IMPL | Modern futex; vector wait. |
| 450 | set_mempolicy_home_node | IMPL | NUMA. |
| 451 | cachestat | IMPL | Page-cache visibility. |
| 452 | fchmodat2 | IMPL | |
| 453 | map_shadow_stack | IMPL | CET shadow-stack. |
| 454 | futex_wake | IMPL | |
| 455 | futex_wait | IMPL | |
| 456 | futex_requeue | IMPL | |
| 457 | statmount | IMPL | |
| 458 | listmount | IMPL | |
| 459 | lsm_get_self_attr | IMPL | LSM stacking tracked as phase 38. |
| 460 | lsm_set_self_attr | IMPL | |
| 461 | lsm_list_modules | IMPL | |
| 462 | mseal | IMPL | Seal VMA against further mprotect/munmap/mremap. |
| 463 | setxattrat | IMPL | dirfd-relative setxattr. |
| 464 | getxattrat | IMPL | dirfd-relative getxattr. |
| 465 | listxattrat | IMPL | dirfd-relative listxattr. |
| 466 | removexattrat | IMPL | dirfd-relative removexattr. |
| 467 | open_tree_attr | IMPL | open_tree + mount-attr set in one call. |
| 468 | file_getattr | IMPL | extended file attributes (statx successor surface). |
| 469 | file_setattr | IMPL | set extended file attributes. |
| 470 | listns | IMPL | enumerate a task's namespaces. |
| 471 | rseq_slice_yield | IMPL | rseq time-slice extension yield. |

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

`iovec`,`timespec`(time_t=i64),`timeval`,`sockaddr*` (`_in`,`_in6`,`_un`),`stat` (legacy; `fstat` only),`statx`+`statx_timestamp`,`epoll_event`+`epoll_data`,`sigaction`+`siginfo_t`+`ucontext_t`+`mcontext_t` (per-arch),`rusage`,`rlimit64`,`dirent64`,`cmsghdr`+`msghdr`+`mmsghdr`,`clone_args` (clone3),`open_how` (openat2),`io_uring_*` (phase 22).

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
`16` (read/write/open/close/...), `13` (sched_*, clone3, exit), `11` (mmap/mprotect/munmap/mremap), `17` (pread/pwrite/fsync), `25` (socket/...), `23` (clock_*, vDSO), `27` (seccomp/landlock_*/capset), `26` (unshare/setns/clone3 ns flags), `30` (io_uring_*), `18` (finit_module/delete_module).

## 11 Changelog

- 2026-05-14: v1/v2 framing stripped per `02§9` rule 8. Legend simplified, deferral cells point at `00§3` phase numbers.
