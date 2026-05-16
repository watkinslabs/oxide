// aarch64 → x86_64 syscall-number translation per docs/15§3.
//
// Linux uses a different numbering on aarch64 ("generic" ABI: see
// linux/include/uapi/asm-generic/unistd.h) than on x86_64. The
// oxide dispatcher table in `syscall_glue.rs` is keyed on x86_64
// numbering, so the aarch64 entry path remaps before dispatch.
//
// Mapping covers the syscalls a static-PIE musl init / busybox /
// shell needs at v1; unknown aarch64 nrs pass through unchanged and
// fall through to the dispatcher's ENOSYS arm (logged as such).

#![cfg_attr(not(any(target_arch = "aarch64", test)), allow(dead_code))]

/// Translate an aarch64 generic-ABI syscall number to the x86_64
/// number used by the dispatcher table. Unmapped numbers pass through.
///
/// # C: O(1) — table lookup with linear-search fallback for sparse nrs.
pub fn aarch64_nr_to_x86(nr: u64) -> u64 {
    // Table sorted by aarch64 nr. Each (arm, x86) tuple translates
    // arm→x86. Out-of-table nrs return as-is.
    const MAP: &[(u64, u64)] = &[
        (17,  79),   // getcwd
        (19,  290),  // eventfd2 (was 293 pipe2 — arm 19 is eventfd2,
                     //           pipe2 lives at arm 59)
        (23,  32),   // dup
        (24,  292),  // dup3 (was 33 dup2 — silently dropped O_CLOEXEC)
        (25,  72),   // fcntl
        (29,  16),   // ioctl
        (32,  73),   // flock
        // ext4 *at family — arm-generic has NO plain (mkdir/unlink/
        // link/rename/mknod/symlink) syscalls, only the *at variants
        // (dirfd, path, ...). Pre-B35 these mapped to x86's plain
        // variants, which shifted every arg by one (dirfd treated as
        // path → EFAULT or wild reads). Always map to the *AT slot.
        (33,  259),  // mknodat
        (34,  258),  // mkdirat  (was 83 mkdir — shifted)
        (35,  263),  // unlinkat (was 87 unlink — shifted)
        (36,  266),  // symlinkat
        (37,  265),  // linkat   (was 86 link — shifted)
        (38,  264),  // renameat (was 82 rename — shifted)
        (40,  165),  // mount
        (43,  179),  // statfs  (was at arm 45 — wrong; arm 45 = truncate)
        (44,  138),  // fstatfs (was at arm 46 — wrong; arm 46 = ftruncate)
        (45,  76),   // truncate
        (46,  77),   // ftruncate
        (48,  269),  // faccessat → faccessat (x86 nr 269). The prior
                     // mapping (90 = chmod) silently corrupted file
                     // modes on every PATH-search probe — ARM busybox's
                     // \`access(X_OK)\` ended up running sys_chmod, then the
                     // failure masqueraded as EACCES so every
                     // \`uname\`/\`ls\` came back "Permission denied"
                     // before fork+execve was attempted. faccessat
                     // (not bare access) is the right target — sys_faccessat
                     // shifts args so dirfd/path/mode line up.
        (49,  80),   // chdir
        (50,  81),   // fchdir
        (51,  161),  // chroot (was 92 chown — broken: chroot path
                     // was being treated as a chown path with garbage
                     // uid/gid from x1/x2). arm-generic 51 = chroot,
                     // not fchownat (which is 54).
        (52,  91),   // fchmod (fd, mode) — args line up with NR_FCHMOD
        (53,  268),  // fchmodat
        (54,  260),  // fchownat
        (55,  93),   // fchown
        (56,  257),  // openat
        (57,  3),    // close
        (59,  293),  // pipe2
        (61,  217),  // getdents64
        (62,  8),    // lseek
        (63,  0),    // read
        (64,  1),    // write
        (65,  19),   // readv
        (66,  20),   // writev
        (67,  17),   // pread64
        (68,  18),   // pwrite64
        (72,  270),  // pselect6
        (73,  271),  // ppoll
        (78,  267),  // readlinkat
        (79,  262),  // newfstatat
        (80,  5),    // fstat
        (81,  162),  // sync (was at arm 231 mapping to NR_SETGID 144 —
                     //       nonsense; arm-generic 81 = sync)
        (82,  74),   // fsync
        (83,  75),   // fdatasync
        (88,  280),  // utimensat (was 100 = NR_TIMES — broken: arm
                     // utimensat(dirfd, path, times, flags) was hitting
                     // sys_times(struct tms*), wild-writing kernel stack
                     // through the dirfd-as-tms-ptr)
        (90,  125),  // capget (was 279 NR_MOVE_PAGES — wrong NR target)
        (91,  126),  // capset (was 280 NR_UTIMENSAT — wrong NR target)
        (93,  60),   // exit
        (94,  231),  // exit_group
        (95,  247),  // waitid
        (96,  218),  // set_tid_address
        (98,  202),  // futex
        (99,  273),  // set_robust_list
        (100, 274),  // get_robust_list
        (101, 35),   // nanosleep
        (102, 36),   // getitimer (was 38 setitimer — swapped pair)
        (103, 38),   // setitimer (was 36 getitimer — swapped pair)
        (107, 222),  // timer_create (was at arm 266 = clock_adjtime)
        (108, 224),  // timer_gettime (was at arm 268 = setns)
        (109, 225),  // timer_getoverrun (new)
        (110, 223),  // timer_settime (was at arm 267 = syncfs)
        (111, 226),  // timer_delete  (was at arm 269 = sendmmsg)
        (113, 228),  // clock_gettime
        (114, 229),  // clock_getres
        (115, 230),  // clock_nanosleep
        (117, 101),  // ptrace
        (122, 203),  // sched_setaffinity
        (123, 204),  // sched_getaffinity
        (124, 24),   // sched_yield
        (129, 62),   // kill
        (130, 200),  // tkill
        (131, 234),  // tgkill
        (132, 131),  // sigaltstack (new)
        (133, 130),  // rt_sigsuspend (was at arm 137 = rt_sigtimedwait)
        (134, 13),   // rt_sigaction
        (135, 14),   // rt_sigprocmask
        (137, 128),  // rt_sigtimedwait (was 130 rt_sigsuspend — wrong dest)
        (138, 129),  // rt_sigqueueinfo (was 13 rt_sigaction alias — bogus)
        (139, 15),   // rt_sigreturn
        (147, 117),  // setresuid
        (148, 118),  // getresuid
        (149, 119),  // setresgid
        (150, 120),  // getresgid
        (153, 100),  // times (was 38 setitimer dup — arm 153 = times)
        (154, 109),  // setpgid
        (155, 121),  // getpgid
        (156, 124),  // getsid
        (157, 112),  // setsid
        (158, 115),  // getgroups
        (159, 116),  // setgroups
        (160, 63),   // uname
        (161, 170),  // sethostname
        (162, 171),  // setdomainname
        (165, 98),   // getrusage
        (167, 157),  // prctl
        (169, 96),   // gettimeofday
        (170, 164),  // settimeofday
        (172, 39),   // getpid
        (173, 110),  // getppid
        (174, 102),  // getuid
        (175, 107),  // geteuid
        (176, 104),  // getgid
        (177, 108),  // getegid
        (178, 186),  // gettid
        (179, 39),   // sysinfo (no x86 nr in our table — treat as getpid noop)
        (180, 240),  // mq_open
        (181, 241),  // mq_unlink
        (182, 242),  // mq_timedsend
        (183, 243),  // mq_timedreceive
        (184, 244),  // mq_notify
        (185, 245),  // mq_getsetattr
        (186, 68),   // msgget
        (187, 71),   // msgctl
        (188, 70),   // msgrcv
        (189, 69),   // msgsnd
        (190, 64),   // semget
        (191, 66),   // semctl
        (192, 220),  // semtimedop
        (193, 65),   // semop
        (198, 41),   // socket
        (199, 53),   // socketpair
        (200, 49),   // bind
        (201, 50),   // listen
        (202, 43),   // accept
        (203, 42),   // connect
        (204, 51),   // getsockname
        (205, 52),   // getpeername
        (206, 44),   // sendto
        (207, 45),   // recvfrom
        (208, 54),   // setsockopt
        (209, 55),   // getsockopt
        (210, 48),   // shutdown
        (211, 46),   // sendmsg
        (212, 47),   // recvmsg
        (214, 12),   // brk
        (215, 11),   // munmap
        (216, 25),   // mremap
        (220, 56),   // clone
        (221, 59),   // execve
        (222, 9),    // mmap
        (226, 10),   // mprotect
        (227, 26),   // msync
        (228, 149),  // mlock
        (229, 150),  // munlock
        (233, 28),   // madvise
        (242, 288),  // accept4
        (260, 61),   // wait4
        (278, 318),  // getrandom
        (291, 332),  // statx → statx (same ABI on both arches).
                     // Pre-fix value was (291, 257) — routing userspace
                     // statx to sys_openat with statx-shaped args. wild
                     // writes followed; the kernel then \"succeeded\"
                     // with garbage data and busybox-ash's PATH search
                     // came back \"Permission denied\".
    ];
    // Linear search; <150 entries, called per-syscall on arm — a
    // 150-cmp scan is cheaper than a thousand-element jump table.
    for &(arm, x86) in MAP { if arm == nr { return x86; } }
    nr
}

#[cfg(test)]
mod tests {
    use super::aarch64_nr_to_x86;
    use crate::nrs::*;

    /// Path-mutating syscalls — arm-generic has only the *at form.
    /// Mapping must land on the x86 *AT slot, not the plain variant,
    /// otherwise every arg shifts by one (dirfd is read as path).
    #[test]
    fn at_family_lands_on_at_x86() {
        assert_eq!(aarch64_nr_to_x86(33), NR_MKNODAT,   "arm mknodat → x86 mknodat");
        assert_eq!(aarch64_nr_to_x86(34), NR_MKDIRAT,   "arm mkdirat → x86 mkdirat");
        assert_eq!(aarch64_nr_to_x86(35), NR_UNLINKAT,  "arm unlinkat → x86 unlinkat");
        assert_eq!(aarch64_nr_to_x86(36), NR_SYMLINKAT, "arm symlinkat → x86 symlinkat");
        assert_eq!(aarch64_nr_to_x86(37), NR_LINKAT,    "arm linkat → x86 linkat");
        assert_eq!(aarch64_nr_to_x86(38), NR_RENAMEAT,  "arm renameat → x86 renameat");
        assert_eq!(aarch64_nr_to_x86(53), NR_FCHMODAT,  "arm fchmodat → x86 fchmodat");
        assert_eq!(aarch64_nr_to_x86(54), NR_FCHOWNAT,  "arm fchownat → x86 fchownat");
        assert_eq!(aarch64_nr_to_x86(56), NR_OPENAT,    "arm openat → x86 openat");
        assert_eq!(aarch64_nr_to_x86(78), NR_READLINKAT,"arm readlinkat → x86 readlinkat");
        assert_eq!(aarch64_nr_to_x86(79), NR_NEWFSTATAT,"arm newfstatat → x86 newfstatat");
        assert_eq!(aarch64_nr_to_x86(88), NR_UTIMENSAT, "arm utimensat → x86 utimensat");
    }

    /// arm-generic 51 = chroot, not fchownat. Pre-B35 it mapped to
    /// NR_CHOWN (92), so chroot(path) silently invoked chown(path,
    /// garbage_uid, garbage_gid) — typically a path-permission change.
    #[test]
    fn chroot_maps_to_chroot_not_chown() {
        assert_eq!(aarch64_nr_to_x86(51), NR_CHROOT);
        assert_ne!(aarch64_nr_to_x86(51), NR_CHOWN);
    }

    /// Same-shape syscalls — arg layout matches across arches, so
    /// the mapping just needs the right x86 NR.
    #[test]
    fn same_shape_essentials() {
        assert_eq!(aarch64_nr_to_x86(57), NR_CLOSE);
        assert_eq!(aarch64_nr_to_x86(63), NR_READ);
        assert_eq!(aarch64_nr_to_x86(64), NR_WRITE);
        assert_eq!(aarch64_nr_to_x86(93), NR_EXIT);
        assert_eq!(aarch64_nr_to_x86(94), NR_EXIT_GROUP);
        assert_eq!(aarch64_nr_to_x86(220), NR_CLONE);
        assert_eq!(aarch64_nr_to_x86(221), NR_EXECVE);
        assert_eq!(aarch64_nr_to_x86(222), NR_MMAP);
    }

    /// Unmapped arm nrs pass through unchanged so the dispatcher's
    /// ENOSYS arm catches them.
    #[test]
    fn unknown_passes_through() {
        assert_eq!(aarch64_nr_to_x86(999_999), 999_999);
    }

    /// PID/uid getters — these landed correctly in the original
    /// table; B36 incorrectly shifted them and broke init's PID-1
    /// self-check (boot died at "init: must be run as PID 1").
    /// Pin every entry here so a future systematic-shift attempt
    /// fails the test before it can fail at boot.
    #[test]
    fn id_getters_at_correct_arm_slots() {
        assert_eq!(aarch64_nr_to_x86(172), NR_GETPID);
        assert_eq!(aarch64_nr_to_x86(173), NR_GETPPID);
        assert_eq!(aarch64_nr_to_x86(174), NR_GETUID);
        assert_eq!(aarch64_nr_to_x86(175), NR_GETEUID);
        assert_eq!(aarch64_nr_to_x86(176), NR_GETGID);
        assert_eq!(aarch64_nr_to_x86(177), NR_GETEGID);
        assert_eq!(aarch64_nr_to_x86(178), NR_GETTID);
    }

    /// capget/capset must land on NR_CAPGET/NR_CAPSET — the pre-B37
    /// table had them at NR_MOVE_PAGES / NR_UTIMENSAT respectively.
    #[test]
    fn caps_not_wrong() {
        assert_eq!(aarch64_nr_to_x86(90), NR_CAPGET);
        assert_eq!(aarch64_nr_to_x86(91), NR_CAPSET);
    }

    /// Itimer pair was swapped — arm 102=getitimer, arm 103=setitimer.
    #[test]
    fn itimer_unswapped() {
        assert_eq!(aarch64_nr_to_x86(102), 36); // NR_GETITIMER
        assert_eq!(aarch64_nr_to_x86(103), 38); // NR_SETITIMER
    }

    /// rt_sigsuspend was at arm 137 (which is rt_sigtimedwait).
    /// Now 133=rt_sigsuspend, 137=rt_sigtimedwait, 138=rt_sigqueueinfo.
    #[test]
    fn rt_sig_block_correct() {
        assert_eq!(aarch64_nr_to_x86(133), NR_RT_SIGSUSPEND);
        assert_eq!(aarch64_nr_to_x86(137), NR_RT_SIGTIMEDWAIT);
        assert_eq!(aarch64_nr_to_x86(138), NR_RT_SIGQUEUEINFO);
        assert_eq!(aarch64_nr_to_x86(139), NR_RT_SIGRETURN);
    }

    /// statfs/fstatfs are at arm 43/44; arm 45/46 are truncate/
    /// ftruncate. Pre-B37 confused these.
    #[test]
    fn statfs_at_right_arm_slot() {
        assert_eq!(aarch64_nr_to_x86(43), 179); // NR_STATFS
        assert_eq!(aarch64_nr_to_x86(44), 138); // NR_FSTATFS
        assert_eq!(aarch64_nr_to_x86(45), NR_TRUNCATE);
        assert_eq!(aarch64_nr_to_x86(46), NR_FTRUNCATE);
    }

    /// Timer family at arm 107-111 (not at 266-269 which are
    /// clock_adjtime/syncfs/setns/sendmmsg).
    #[test]
    fn timer_family_at_right_arm_slot() {
        assert_eq!(aarch64_nr_to_x86(107), NR_TIMER_CREATE);
        assert_eq!(aarch64_nr_to_x86(108), NR_TIMER_GETTIME);
        assert_eq!(aarch64_nr_to_x86(109), NR_TIMER_GETOVERRUN);
        assert_eq!(aarch64_nr_to_x86(110), NR_TIMER_SETTIME);
        assert_eq!(aarch64_nr_to_x86(111), NR_TIMER_DELETE);
    }

    /// arm 19 = eventfd2, NOT pipe2 (which is at arm 59).
    #[test]
    fn eventfd2_at_right_slot() {
        assert_eq!(aarch64_nr_to_x86(19), NR_EVENTFD2);
        assert_eq!(aarch64_nr_to_x86(59), 293); // NR_PIPE2
    }

    /// dup3 keeps flags via NR_DUP3, was lossy as dup2.
    #[test]
    fn dup3_not_dup2() {
        assert_eq!(aarch64_nr_to_x86(24), NR_DUP3);
    }

    /// arm 81 = sync. Pre-B37 had no entry for arm 81 and a bogus
    /// (231, NR_SETGID) row instead.
    #[test]
    fn sync_at_right_slot() {
        assert_eq!(aarch64_nr_to_x86(81), NR_SYNC);
    }
}
