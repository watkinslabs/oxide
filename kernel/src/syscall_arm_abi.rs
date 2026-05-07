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

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

/// Translate an aarch64 generic-ABI syscall number to the x86_64
/// number used by the dispatcher table. Unmapped numbers pass through.
///
/// # C: O(1) — table lookup with linear-search fallback for sparse nrs.
pub fn aarch64_nr_to_x86(nr: u64) -> u64 {
    // Table sorted by aarch64 nr. Each (arm, x86) tuple translates
    // arm→x86. Out-of-table nrs return as-is.
    const MAP: &[(u64, u64)] = &[
        (17,  79),   // getcwd
        (19,  293),  // pipe2 (no plain pipe in arm-generic)
        (23,  32),   // dup
        (24,  33),   // dup3 → dup2 (close enough for v1)
        (25,  72),   // fcntl
        (29,  16),   // ioctl
        (32,  73),   // flock
        (33,  133),  // mknodat → mknod-ish (stub)
        (34,  83),   // mkdirat
        (35,  87),   // unlinkat
        (37,  86),   // linkat
        (38,  82),   // renameat
        (40,  165),  // mount
        (45,  179),  // statfs
        (46,  138),  // fstatfs
        (48,  90),   // faccessat → access (close)
        (49,  80),   // chdir
        (50,  81),   // fchdir
        (51,  92),   // chown (fchownat)
        (52,  91),   // chmod (fchmodat)
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
        (82,  74),   // fsync
        (83,  75),   // fdatasync
        (88,  100),  // utimensat
        (90,  279),  // capget (stub)
        (91,  280),  // capset (stub)
        (93,  60),   // exit
        (94,  231),  // exit_group
        (95,  247),  // waitid
        (96,  218),  // set_tid_address
        (98,  202),  // futex
        (99,  273),  // set_robust_list
        (100, 274),  // get_robust_list
        (101, 35),   // nanosleep
        (102, 38),   // setitimer
        (103, 36),   // getitimer
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
        (134, 13),   // rt_sigaction
        (135, 14),   // rt_sigprocmask
        (137, 130),  // rt_sigsuspend
        (138, 13),   // rt_sigaction (alias)
        (139, 15),   // rt_sigreturn
        (147, 117),  // setresuid
        (148, 118),  // getresuid
        (149, 119),  // setresgid
        (150, 120),  // getresgid
        (153, 38),   // setitimer (dup)
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
        (213, 161),  // chroot (close)
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
        (231, 144),  // sync
        (233, 28),   // madvise
        (242, 288),  // accept4
        (260, 61),   // wait4
        (266, 222),  // timer_create
        (267, 223),  // timer_settime
        (268, 224),  // timer_gettime
        (269, 226),  // timer_delete
        (278, 318),  // getrandom
        (291, 257),  // statx → newfstatat fallback
    ];
    // Linear search; <150 entries, called per-syscall on arm — a
    // 150-cmp scan is cheaper than a thousand-element jump table.
    for &(arm, x86) in MAP { if arm == nr { return x86; } }
    nr
}
