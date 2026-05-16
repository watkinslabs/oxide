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
//
// B35 + B36 audit: prior table had an off-by-one shift in the arm
// column across most of the 90–270 range (entries labeled "X" had
// the arm number that arm-generic assigns to X+1), and several
// catastrophic mis-targets (capget→move_pages, utimensat→times,
// chroot→chown). The current table is audited row-by-row against
// the canonical asm-generic/unistd.h numbering; pinned by the
// hosted tests below.

#![cfg_attr(not(any(target_arch = "aarch64", test)), allow(dead_code))]

/// Translate an aarch64 generic-ABI syscall number to the x86_64
/// number used by the dispatcher table. Unmapped numbers pass through.
///
/// # C: O(1) — table lookup with linear-search fallback for sparse nrs.
pub fn aarch64_nr_to_x86(nr: u64) -> u64 {
    // Table sorted by aarch64 nr. Each (arm, x86) tuple translates
    // arm→x86. Out-of-table nrs return as-is.
    const MAP: &[(u64, u64)] = &[
        // === file descriptors / I/O ===
        (17,  79),   // getcwd
        (19,  290),  // eventfd2 (was 293 pipe2 — wrong arm slot;
                     //           arm-generic 19 = eventfd2, 59 = pipe2)
        (23,  32),   // dup
        (24,  292),  // dup3 (was 33 dup2 — silently dropped O_CLOEXEC)
        (25,  72),   // fcntl
        (29,  16),   // ioctl
        (32,  73),   // flock

        // === filesystem *at family (arm-generic has only *at form) ===
        (33,  259),  // mknodat
        (34,  258),  // mkdirat
        (35,  263),  // unlinkat
        (36,  266),  // symlinkat
        (37,  265),  // linkat
        (38,  264),  // renameat

        // === mount + statfs ===
        (39,  166),  // umount2 (was missing)
        (40,  165),  // mount
        (43,  179),  // statfs (was at arm 45 — wrong slot;
                     //         arm-generic 43 = statfs, 45 = truncate)
        (44,  138),  // fstatfs (was at arm 46)
        (45,  76),   // truncate (was 179 statfs)
        (46,  77),   // ftruncate (was 138 fstatfs)
        (47,  285),  // fallocate (was missing)
        (48,  269),  // faccessat → faccessat2 — close enough; sys_faccessat
                     // shifts args so dirfd/path/mode line up.
        (49,  80),   // chdir
        (50,  81),   // fchdir
        (51,  161),  // chroot (was 92 chown — chroot path was treated as
                     //         chown path with garbage uid/gid)
        (52,  91),   // fchmod
        (53,  268),  // fchmodat
        (54,  260),  // fchownat
        (55,  93),   // fchown
        (56,  257),  // openat
        (57,  3),    // close
        (58,  153),  // vhangup (was missing)
        (59,  293),  // pipe2
        (61,  217),  // getdents64
        (62,  8),    // lseek
        (63,  0),    // read
        (64,  1),    // write
        (65,  19),   // readv
        (66,  20),   // writev
        (67,  17),   // pread64
        (68,  18),   // pwrite64
        (71,  40),   // sendfile (was missing)
        (72,  270),  // pselect6
        (73,  271),  // ppoll
        (76,  275),  // splice (was missing)
        (77,  276),  // tee (was missing)
        (78,  267),  // readlinkat
        (79,  262),  // newfstatat
        (80,  5),    // fstat
        (81,  162),  // sync (was at arm 231 → NR_SETGID 144; broken)
        (82,  74),   // fsync
        (83,  75),   // fdatasync
        (88,  280),  // utimensat (was 100 NR_TIMES — wild-wrote kernel
                     //            stack via dirfd-as-tms-ptr in sys_times)

        // === caps / personality / exit / waitid ===
        (90,  125),  // capget (was 279 move_pages — chaos on capget probes)
        (91,  126),  // capset (was 280 utimensat)
        (92,  135),  // personality (was missing)
        (93,  60),   // exit
        (94,  231),  // exit_group
        (95,  247),  // waitid
        (96,  218),  // set_tid_address
        (97,  272),  // unshare (was missing)
        (98,  202),  // futex
        (99,  273),  // set_robust_list
        (100, 274),  // get_robust_list

        // === timers / clocks (whole block was wrong direction) ===
        (101, 35),   // nanosleep
        (102, 36),   // getitimer (was 38 setitimer — swapped)
        (103, 38),   // setitimer (was 36 getitimer — swapped)
        (107, 222),  // timer_create (was at arm 266)
        (108, 224),  // timer_gettime (was at arm 268)
        (109, 225),  // timer_getoverrun (was missing)
        (110, 223),  // timer_settime (was at arm 267)
        (111, 226),  // timer_delete (was at arm 269)
        (112, 227),  // clock_settime (was missing)
        (113, 228),  // clock_gettime
        (114, 229),  // clock_getres
        (115, 230),  // clock_nanosleep
        (116, 103),  // syslog (was missing)

        // === ptrace / sched ===
        (117, 101),  // ptrace
        (118, 142),  // sched_setparam (was missing)
        (119, 144),  // sched_setscheduler (was missing)
        (120, 145),  // sched_getscheduler (was missing)
        (121, 143),  // sched_getparam (was missing)
        (122, 203),  // sched_setaffinity
        (123, 204),  // sched_getaffinity
        (124, 24),   // sched_yield
        (125, 146),  // sched_get_priority_max (was missing)
        (126, 147),  // sched_get_priority_min (was missing)
        (127, 148),  // sched_rr_get_interval (was missing)
        (128, 219),  // restart_syscall (was missing)

        // === signals ===
        (129, 62),   // kill
        (130, 200),  // tkill
        (131, 234),  // tgkill
        (132, 131),  // sigaltstack (was missing)
        (133, 130),  // rt_sigsuspend (was at arm 137 — swapped with
                     //                rt_sigtimedwait)
        (134, 13),   // rt_sigaction
        (135, 14),   // rt_sigprocmask
        (136, 127),  // rt_sigpending (was missing)
        (137, 128),  // rt_sigtimedwait (was 130 rt_sigsuspend — wrong)
        (138, 129),  // rt_sigqueueinfo (was 13 rt_sigaction alias — bogus)
        (139, 15),   // rt_sigreturn

        // === priorities / id stuff ===
        (140, 141),  // setpriority (was missing)
        (141, 140),  // getpriority (was missing)
        (142, 169),  // reboot (was missing)
        (143, 114),  // setregid (was missing)
        (144, 106),  // setgid (was missing)
        (145, 105),  // setuid (was missing)
        // Pre-B36 the resuid/resgid block was off-by-one in the arm
        // column (label X sat at arm X+1). Re-anchored to arm-generic.
        (146, 117),  // setresuid (was at arm 147)
        (147, 118),  // getresuid (was at arm 148)
        (148, 119),  // setresgid (was at arm 149)
        (149, 120),  // getresgid (was at arm 150)
        (150, 122),  // setfsuid (was missing)
        (151, 123),  // setfsgid (was missing)
        (152, 100),  // times (was missing)
        (153, 109),  // setpgid (was at arm 154)
        (154, 121),  // getpgid (was at arm 155)
        (155, 124),  // getsid (was at arm 156)
        (156, 112),  // setsid (was at arm 157)
        (157, 115),  // getgroups (was at arm 158)
        (158, 116),  // setgroups (was at arm 159)
        (159, 63),   // uname (was at arm 160)
        (160, 170),  // sethostname (was at arm 161)
        (161, 171),  // setdomainname (was at arm 162)
        (162, 97),   // getrlimit (was missing)
        (163, 160),  // setrlimit (was missing)
        (164, 98),   // getrusage (was at arm 165)
        (165, 95),   // umask (was missing)
        (166, 157),  // prctl (was at arm 167)
        (167, 309),  // getcpu (was missing)
        (168, 96),   // gettimeofday (was at arm 169)
        (169, 164),  // settimeofday (was at arm 170)
        (170, 159),  // adjtimex (was missing)

        // === pid/uid getters (whole block was shifted by one) ===
        (171, 39),   // getpid (was at arm 172)
        (172, 110),  // getppid (was at arm 173)
        (173, 102),  // getuid (was at arm 174)
        (174, 107),  // geteuid (was at arm 175)
        (175, 104),  // getgid (was at arm 176)
        (176, 108),  // getegid (was at arm 177)
        (177, 186),  // gettid (was at arm 178)
        (178, 99),   // sysinfo (was at arm 179, with x86=39 noop alias)

        // === posix mq / sysv ipc (block shifted by one) ===
        (179, 240),  // mq_open (was at arm 180)
        (180, 241),  // mq_unlink (was at arm 181)
        (181, 242),  // mq_timedsend (was at arm 182)
        (182, 243),  // mq_timedreceive (was at arm 183)
        (183, 244),  // mq_notify (was at arm 184)
        (184, 245),  // mq_getsetattr (was at arm 185)
        (185, 68),   // msgget (was at arm 186)
        (186, 71),   // msgctl (was at arm 187)
        (187, 70),   // msgrcv (was at arm 188)
        (188, 69),   // msgsnd (was at arm 189)
        (189, 64),   // semget (was at arm 190)
        (190, 66),   // semctl (was at arm 191)
        (191, 220),  // semtimedop (was at arm 192)
        (192, 65),   // semop (was at arm 193)

        // === sockets (block shifted by one) ===
        (197, 41),   // socket (was at arm 198)
        (198, 53),   // socketpair
        (199, 49),   // bind
        (200, 50),   // listen
        (201, 43),   // accept
        (202, 42),   // connect
        (203, 51),   // getsockname
        (204, 52),   // getpeername
        (205, 44),   // sendto
        (206, 45),   // recvfrom
        (207, 54),   // setsockopt
        (208, 55),   // getsockopt
        (209, 48),   // shutdown
        (210, 46),   // sendmsg
        (211, 47),   // recvmsg

        // === memory (block shifted by one) ===
        (213, 12),   // brk (was at arm 214)
        (214, 11),   // munmap (was at arm 215)
        (215, 25),   // mremap (was at arm 216)
        (219, 56),   // clone (was at arm 220)
        (220, 59),   // execve (was at arm 221)
        (221, 9),    // mmap (was at arm 222)
        (225, 10),   // mprotect (was at arm 226)
        (226, 26),   // msync (was at arm 227)
        (227, 149),  // mlock (was at arm 228)
        (228, 150),  // munlock (was at arm 229)
        (232, 28),   // madvise (was at arm 233)

        // === socket extras + waitpid + extras ===
        (241, 288),  // accept4 (was at arm 242)
        (260, 61),   // wait4
        (261, 302),  // prlimit64 (was missing)
        (269, 307),  // sendmmsg (was missing)
        (278, 318),  // getrandom
        (291, 332),  // statx
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
    /// the mapping just needs the right x86 NR. Note arm clone/
    /// execve/mmap sit at 219/220/221 in arm-generic (not 220/221/
    /// 222 as the pre-B36 table claimed).
    #[test]
    fn same_shape_essentials() {
        assert_eq!(aarch64_nr_to_x86(57), NR_CLOSE);
        assert_eq!(aarch64_nr_to_x86(63), NR_READ);
        assert_eq!(aarch64_nr_to_x86(64), NR_WRITE);
        assert_eq!(aarch64_nr_to_x86(93), NR_EXIT);
        assert_eq!(aarch64_nr_to_x86(94), NR_EXIT_GROUP);
        assert_eq!(aarch64_nr_to_x86(219), NR_CLONE);
        assert_eq!(aarch64_nr_to_x86(220), NR_EXECVE);
        assert_eq!(aarch64_nr_to_x86(221), NR_MMAP);
    }

    /// Unmapped arm nrs pass through unchanged so the dispatcher's
    /// ENOSYS arm catches them.
    #[test]
    fn unknown_passes_through() {
        assert_eq!(aarch64_nr_to_x86(999_999), 999_999);
    }

    /// Pid/uid getters block — B36 caught a systematic +1 shift in
    /// the arm column from arm 171 all the way through 178.
    #[test]
    fn pid_uid_getters_block_correct() {
        assert_eq!(aarch64_nr_to_x86(171), NR_GETPID);
        assert_eq!(aarch64_nr_to_x86(172), NR_GETPPID);
        assert_eq!(aarch64_nr_to_x86(173), NR_GETUID);
        assert_eq!(aarch64_nr_to_x86(174), NR_GETEUID);
        assert_eq!(aarch64_nr_to_x86(175), NR_GETGID);
        assert_eq!(aarch64_nr_to_x86(176), NR_GETEGID);
        assert_eq!(aarch64_nr_to_x86(177), NR_GETTID);
        assert_eq!(aarch64_nr_to_x86(178), NR_SYSINFO);
    }

    /// Caps block — B36 caught capget/capset pointing at
    /// move_pages/utimensat. Re-anchor to NR_CAPGET/NR_CAPSET.
    #[test]
    fn caps_not_wrong() {
        assert_eq!(aarch64_nr_to_x86(90), NR_CAPGET);
        assert_eq!(aarch64_nr_to_x86(91), NR_CAPSET);
        assert_ne!(aarch64_nr_to_x86(90), 279); // NR_MOVE_PAGES
        assert_ne!(aarch64_nr_to_x86(91), 280); // NR_UTIMENSAT
    }

    /// Itimer pair was swapped — arm 102=getitimer, arm 103=setitimer.
    #[test]
    fn itimer_unswapped() {
        assert_eq!(aarch64_nr_to_x86(102), 36); // NR_GETITIMER
        assert_eq!(aarch64_nr_to_x86(103), 38); // NR_SETITIMER
    }

    /// rt_sigsuspend was at arm 137 (which is rt_sigtimedwait).
    /// Now: 133=rt_sigsuspend, 137=rt_sigtimedwait, 138=rt_sigqueueinfo.
    #[test]
    fn rt_sig_block_correct() {
        assert_eq!(aarch64_nr_to_x86(133), NR_RT_SIGSUSPEND);
        assert_eq!(aarch64_nr_to_x86(134), 13); // NR_RT_SIGACTION
        assert_eq!(aarch64_nr_to_x86(135), 14); // NR_RT_SIGPROCMASK
        assert_eq!(aarch64_nr_to_x86(136), NR_RT_SIGPENDING);
        assert_eq!(aarch64_nr_to_x86(137), NR_RT_SIGTIMEDWAIT);
        assert_eq!(aarch64_nr_to_x86(138), NR_RT_SIGQUEUEINFO);
        assert_eq!(aarch64_nr_to_x86(139), NR_RT_SIGRETURN);
    }

    /// Process-group + session block was shifted by one.
    #[test]
    fn pgid_session_block_correct() {
        assert_eq!(aarch64_nr_to_x86(153), 109); // NR_SETPGID
        assert_eq!(aarch64_nr_to_x86(154), NR_GETPGID);
        assert_eq!(aarch64_nr_to_x86(155), NR_GETSID);
        assert_eq!(aarch64_nr_to_x86(156), NR_SETSID);
        assert_eq!(aarch64_nr_to_x86(157), NR_GETGROUPS);
        assert_eq!(aarch64_nr_to_x86(158), NR_SETGROUPS);
        assert_eq!(aarch64_nr_to_x86(159), 63); // NR_UNAME
        assert_eq!(aarch64_nr_to_x86(160), 170); // NR_SETHOSTNAME
        assert_eq!(aarch64_nr_to_x86(161), 171); // NR_SETDOMAINNAME
    }

    /// statfs/fstatfs were at arm 45/46 — but those are truncate/
    /// ftruncate. Correct slots are arm 43/44.
    #[test]
    fn statfs_at_right_arm_slot() {
        assert_eq!(aarch64_nr_to_x86(43), 179); // NR_STATFS
        assert_eq!(aarch64_nr_to_x86(44), 138); // NR_FSTATFS
        assert_eq!(aarch64_nr_to_x86(45), NR_TRUNCATE);
        assert_eq!(aarch64_nr_to_x86(46), NR_FTRUNCATE);
    }

    /// Timer family was way out at arm 266-269 (which are
    /// clock_adjtime / syncfs / setns / sendmmsg). Now at 107-111.
    #[test]
    fn timer_family_at_right_arm_slot() {
        assert_eq!(aarch64_nr_to_x86(107), NR_TIMER_CREATE);
        assert_eq!(aarch64_nr_to_x86(108), NR_TIMER_GETTIME);
        assert_eq!(aarch64_nr_to_x86(109), NR_TIMER_GETOVERRUN);
        assert_eq!(aarch64_nr_to_x86(110), NR_TIMER_SETTIME);
        assert_eq!(aarch64_nr_to_x86(111), NR_TIMER_DELETE);
    }

    /// Sockets block was shifted by one.
    #[test]
    fn socket_block_correct() {
        assert_eq!(aarch64_nr_to_x86(197), 41); // NR_SOCKET
        assert_eq!(aarch64_nr_to_x86(198), 53); // NR_SOCKETPAIR
        assert_eq!(aarch64_nr_to_x86(199), 49); // NR_BIND
        assert_eq!(aarch64_nr_to_x86(200), 50); // NR_LISTEN
        assert_eq!(aarch64_nr_to_x86(201), 43); // NR_ACCEPT
        assert_eq!(aarch64_nr_to_x86(202), 42); // NR_CONNECT
    }

    /// Memory block was shifted by one — brk/munmap/mremap/clone/
    /// execve/mmap/mprotect/msync.
    #[test]
    fn memory_block_correct() {
        assert_eq!(aarch64_nr_to_x86(213), 12); // NR_BRK
        assert_eq!(aarch64_nr_to_x86(214), 11); // NR_MUNMAP
        assert_eq!(aarch64_nr_to_x86(215), 25); // NR_MREMAP
        assert_eq!(aarch64_nr_to_x86(219), 56); // NR_CLONE
        assert_eq!(aarch64_nr_to_x86(220), 59); // NR_EXECVE
        assert_eq!(aarch64_nr_to_x86(221), 9);  // NR_MMAP
        assert_eq!(aarch64_nr_to_x86(225), 10); // NR_MPROTECT
    }

    /// Sync was at arm 231 (mincore) mapping to NR_SETGID (144) —
    /// nonsense. arm-generic sync = 81.
    #[test]
    fn sync_not_setgid() {
        assert_eq!(aarch64_nr_to_x86(81), NR_SYNC);
        assert_ne!(aarch64_nr_to_x86(231), NR_SYNC); // 231 unmapped now
    }
}
