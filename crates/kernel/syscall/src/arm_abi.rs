// aarch64 → x86_64 syscall-number translation per docs/15§3.
//
// Linux uses a different numbering on aarch64 ("generic" ABI: see
// linux/include/uapi/asm-generic/unistd.h) than on x86_64. The
// oxide dispatcher table in `syscall_glue.rs` is keyed on x86_64
// numbering, so the aarch64 entry path remaps before dispatch.
//
// Mapping covers the syscalls a static-PIE musl init / coreutils /
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
    // Full aarch64-generic table (asm-generic/unistd.h). Every arm nr
    // an oxide kernel sees must land in either:
    //   (a) the x86 slot with matching semantics, or
    //   (b) an unmapped pass-through where x86 has the SAME nr too
    //       (post-rebase syscalls 424+ unified across arches).
    // Passing arm-only nrs through unchanged is unsafe: arm 21
    // (epoll_ctl) would dispatch as x86 21 (access), wild-arg style.
    // F123: dhcpcd hung on prlimit64 (arm 261) for exactly this reason.
    const MAP: &[(u64, u64)] = &[
        // --- 0..15 — io_setup family + xattr family ----------------
        (0,   206),  // io_setup
        (1,   207),  // io_destroy
        (2,   209),  // io_submit
        (3,   210),  // io_cancel
        (4,   208),  // io_getevents
        (5,   188),  // setxattr
        (6,   189),  // lsetxattr
        (7,   190),  // fsetxattr
        (8,   191),  // getxattr
        (9,   192),  // lgetxattr
        (10,  193),  // fgetxattr
        (11,  194),  // listxattr
        (12,  195),  // llistxattr
        (13,  196),  // flistxattr
        (14,  197),  // removexattr
        (15,  198),  // lremovexattr
        (16,  199),  // fremovexattr

        // --- 17..32 — fs + epoll + inotify -------------------------
        (17,  79),   // getcwd
        (18,  212),  // lookup_dcookie
        (19,  290),  // eventfd2 (was 293 pipe2 — arm 19 is eventfd2;
                     //           pipe2 lives at arm 59)
        (20,  291),  // epoll_create1
        (21,  233),  // epoll_ctl  (was unmapped → fell through to x86
                     //   21 = sys_access — silent path-arg corruption)
        (22,  281),  // epoll_pwait (was unmapped → fell through to x86
                     //   22 = sys_pipe — silent fd-arg corruption)
        (23,  32),   // dup
        (24,  292),  // dup3 (was 33 dup2 — silently dropped O_CLOEXEC)
        (25,  72),   // fcntl
        (26,  294),  // inotify_init1
        (27,  254),  // inotify_add_watch
        (28,  255),  // inotify_rm_watch
        (29,  16),   // ioctl
        (30,  251),  // ioprio_set
        (31,  252),  // ioprio_get
        (32,  73),   // flock

        // --- 33..38 — *at family. arm-generic has NO plain
        // (mkdir/unlink/link/rename/mknod/symlink) syscalls — only the
        // *at variants (dirfd, path, ...). Mapping to the plain x86
        // variant shifts every arg by one (dirfd treated as path →
        // EFAULT or wild reads). Always land on the *AT slot.
        (33,  259),  // mknodat
        (34,  258),  // mkdirat  (was 83 mkdir — shifted)
        (35,  263),  // unlinkat (was 87 unlink — shifted)
        (36,  266),  // symlinkat
        (37,  265),  // linkat   (was 86 link — shifted)
        (38,  264),  // renameat (was 82 rename — shifted)

        // --- 39..58 — fs + truncate + fchown ----------------------
        (39,  166),  // umount2
        (40,  165),  // mount
        (41,  155),  // pivot_root
        // arm 42 is nfsservctl (`sys_ni_syscall` on Linux). Left unmapped it
        // passed through as x86 42 = connect, so `syscall(42, ...)` on arm64
        // ran connect() on whatever the caller's registers held instead of
        // returning ENOSYS. Route it to the x86 nfsservctl slot, which
        // `obsolete::is_obsolete` answers with ENOSYS — matching Linux.
        (42,  180),  // nfsservctl → x86 nfsservctl (OBSOLETE ⇒ ENOSYS)
        (43,  137),  // statfs   (was 179 quotactl — wrong dest)
        (44,  138),  // fstatfs
        (45,  76),   // truncate
        (46,  77),   // ftruncate
        (47,  285),  // fallocate
        (48,  269),  // faccessat (was 90 chmod — silent mode-corrupt;
                     //   the shell's PATH-search on ARM hit sys_chmod, all
                     //   `uname`/`ls` came back "Permission denied")
        (49,  80),   // chdir
        (50,  81),   // fchdir
        (51,  161),  // chroot   (was 92 chown — silent path/uid corrupt)
        (52,  91),   // fchmod
        (53,  268),  // fchmodat
        (54,  260),  // fchownat
        (55,  93),   // fchown
        (56,  257),  // openat
        (57,  3),    // close
        (58,  153),  // vhangup

        // --- 59..83 — pipe + io + sync + utimensat ----------------
        (59,  293),  // pipe2
        (60,  179),  // quotactl
        (61,  217),  // getdents64
        (62,  8),    // lseek
        (63,  0),    // read
        (64,  1),    // write
        (65,  19),   // readv
        (66,  20),   // writev
        (67,  17),   // pread64
        (68,  18),   // pwrite64
        (69,  295),  // preadv
        (70,  296),  // pwritev
        (71,  40),   // sendfile
        (72,  270),  // pselect6
        (73,  271),  // ppoll
        (74,  289),  // signalfd4
        (75,  278),  // vmsplice
        (76,  275),  // splice
        (77,  276),  // tee
        (78,  267),  // readlinkat
        (79,  262),  // newfstatat
        (80,  5),    // fstat
        (81,  162),  // sync (was at arm 231 mapping to NR_SETGID 144 —
                     //       nonsense; arm-generic 81 = sync)
        (82,  74),   // fsync
        (83,  75),   // fdatasync
        (84,  277),  // sync_file_range
        (85,  283),  // timerfd_create
        (86,  286),  // timerfd_settime
        (87,  287),  // timerfd_gettime
        (88,  280),  // utimensat (was 100 = NR_TIMES — utimensat args
                     //   were wild-writing kernel stack through dirfd-
                     //   as-tms-ptr)

        // --- 89..103 — caps + exit + futex + itimer ---------------
        (89,  163),  // acct
        (90,  125),  // capget (was 279 NR_MOVE_PAGES — wrong dest)
        (91,  126),  // capset (was 280 NR_UTIMENSAT — wrong dest)
        (92,  135),  // personality
        (93,  60),   // exit
        (94,  231),  // exit_group
        (95,  247),  // waitid
        (96,  218),  // set_tid_address
        (97,  272),  // unshare
        (98,  202),  // futex
        (99,  273),  // set_robust_list
        (100, 274),  // get_robust_list
        (101, 35),   // nanosleep
        (102, 36),   // getitimer (was 38 setitimer — swapped pair)
        (103, 38),   // setitimer (was 36 getitimer — swapped pair)

        // --- 104..115 — kexec + modules + timers + clocks ---------
        (104, 246),  // kexec_load
        (105, 175),  // init_module
        (106, 176),  // delete_module
        (107, 222),  // timer_create (was at arm 266 = clock_adjtime)
        (108, 224),  // timer_gettime (was at arm 268 = setns)
        (109, 225),  // timer_getoverrun
        (110, 223),  // timer_settime (was at arm 267 = syncfs)
        (111, 226),  // timer_delete  (was at arm 269 = sendmmsg)
        (112, 227),  // clock_settime
        (113, 228),  // clock_gettime
        (114, 229),  // clock_getres
        (115, 230),  // clock_nanosleep

        // --- 116..131 — sched + signals + tkill -------------------
        (116, 103),  // syslog
        (117, 101),  // ptrace
        (118, 142),  // sched_setparam
        (119, 144),  // sched_setscheduler
        (120, 145),  // sched_getscheduler
        (121, 143),  // sched_getparam
        (122, 203),  // sched_setaffinity
        (123, 204),  // sched_getaffinity
        (124, 24),   // sched_yield
        (125, 146),  // sched_get_priority_max
        (126, 147),  // sched_get_priority_min
        (127, 148),  // sched_rr_get_interval
        (128, 219),  // restart_syscall
        (129, 62),   // kill
        (130, 200),  // tkill
        (131, 234),  // tgkill

        // --- 132..139 — signal handling ---------------------------
        (132, 131),  // sigaltstack
        (133, 130),  // rt_sigsuspend (was at arm 137 = rt_sigtimedwait)
        (134, 13),   // rt_sigaction
        (135, 14),   // rt_sigprocmask
        (136, 127),  // rt_sigpending
        (137, 128),  // rt_sigtimedwait (was 130 — wrong dest)
        (138, 129),  // rt_sigqueueinfo (was 13 alias — bogus)
        (139, 15),   // rt_sigreturn

        // --- 140..162 — priority + reboot + uid/gid + times -------
        (140, 141),  // setpriority
        (141, 140),  // getpriority
        (142, 169),  // reboot
        (143, 114),  // setregid
        (144, 106),  // setgid
        (145, 113),  // setreuid
        (146, 105),  // setuid
        (147, 117),  // setresuid
        (148, 118),  // getresuid
        (149, 119),  // setresgid
        (150, 120),  // getresgid
        (151, 122),  // setfsuid
        (152, 123),  // setfsgid
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

        // --- 163..178 — rlimit + getrusage + prctl + ids ----------
        (163, 97),   // getrlimit
        (164, 160),  // setrlimit
        (165, 98),   // getrusage
        (166, 95),   // umask
        (167, 157),  // prctl
        (168, 309),  // getcpu
        (169, 96),   // gettimeofday
        (170, 164),  // settimeofday
        (171, 159),  // adjtimex
        (172, 39),   // getpid
        (173, 110),  // getppid
        (174, 102),  // getuid
        (175, 107),  // geteuid
        (176, 104),  // getgid
        (177, 108),  // getegid
        (178, 186),  // gettid

        // --- 179..197 — sysinfo + mq + sysv ipc -------------------
        (179, 99),   // sysinfo (was 39 getpid — comment said "no x86
                     //   nr in our table" but x86 sysinfo IS slot 99;
                     //   pre-fix sysinfo silently returned pid bytes)
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
        (194, 29),   // shmget
        (195, 31),   // shmctl
        (196, 30),   // shmat
        (197, 67),   // shmdt

        // --- 198..212 — sockets -----------------------------------
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

        // --- 213..243 — mm + keys + clone/mmap + numa + perf ------
        (213, 187),  // readahead
        (214, 12),   // brk
        (215, 11),   // munmap
        (216, 25),   // mremap
        (217, 248),  // add_key
        (218, 249),  // request_key
        (219, 250),  // keyctl
        (220, 56),   // clone
        (221, 59),   // execve
        (222, 9),    // mmap
        (223, 221),  // fadvise64
        (224, 167),  // swapon
        (225, 168),  // swapoff
        (226, 10),   // mprotect
        (227, 26),   // msync
        (228, 149),  // mlock
        (229, 150),  // munlock
        (230, 151),  // mlockall
        (231, 152),  // munlockall
        (232, 27),   // mincore
        (233, 28),   // madvise
        (234, 216),  // remap_file_pages
        (235, 237),  // mbind
        (236, 239),  // get_mempolicy
        (237, 238),  // set_mempolicy
        (238, 256),  // migrate_pages
        (239, 279),  // move_pages
        (240, 297),  // rt_tgsigqueueinfo
        (241, 298),  // perf_event_open
        (242, 288),  // accept4
        (243, 299),  // recvmmsg

        // --- 260..293 — wait + prlimit + fanotify + ns ------------
        (260, 61),   // wait4
        (261, 302),  // prlimit64 (F123: was unmapped → fell through to
                     //   x86 261 = futimesat ENOSYS; dhcpcd musl wedged
                     //   after the bad return)
        (262, 300),  // fanotify_init
        (263, 301),  // fanotify_mark
        (264, 303),  // name_to_handle_at
        (265, 304),  // open_by_handle_at
        (266, 305),  // clock_adjtime
        (267, 306),  // syncfs
        (268, 308),  // setns
        (269, 307),  // sendmmsg
        (270, 310),  // process_vm_readv
        (271, 311),  // process_vm_writev
        (272, 312),  // kcmp
        (273, 313),  // finit_module
        (274, 314),  // sched_setattr
        (275, 315),  // sched_getattr
        (276, 316),  // renameat2
        (277, 317),  // seccomp
        (278, 318),  // getrandom
        (279, 319),  // memfd_create
        (280, 321),  // bpf
        (281, 322),  // execveat
        (282, 323),  // userfaultfd
        (283, 324),  // membarrier
        (284, 325),  // mlock2
        (285, 326),  // copy_file_range
        (286, 327),  // preadv2
        (287, 328),  // pwritev2
        (288, 329),  // pkey_mprotect
        (289, 330),  // pkey_alloc
        (290, 331),  // pkey_free
        (291, 332),  // statx (was 257 sys_openat — statx-shaped args
                     //   wild-wrote, kernel "succeeded" with garbage,
                     //   the shell's PATH probe returned "Permission
                     //   denied")
        (292, 333),  // io_pgetevents
        (293, 334),  // rseq
        (294, 320),  // kexec_file_load

        // --- 424..441 — unified post-rebase syscalls --------------
        // Both arches use the SAME nr for these; explicit mapping
        // documents intent and survives any future numbering drift.
        (424, 424),  // pidfd_send_signal
        (425, 425),  // io_uring_setup
        (426, 426),  // io_uring_enter
        (427, 427),  // io_uring_register
        (428, 428),  // open_tree
        (429, 429),  // move_mount
        (430, 430),  // fsopen
        (431, 431),  // fsconfig
        (432, 432),  // fsmount
        (433, 433),  // fspick
        (434, 434),  // pidfd_open
        (435, 435),  // clone3
        (436, 436),  // close_range
        (437, 437),  // openat2
        (438, 438),  // pidfd_getfd
        (439, 439),  // faccessat2
        (440, 440),  // process_madvise
        (441, 441),  // epoll_pwait2
    ];
    // Linear search; ~250 entries, called per-syscall on arm — still
    // cheaper than a thousand-element jump table at this size.
    for &(arm, x86) in MAP { if arm == nr { return x86; } }
    nr
}

#[cfg(test)]
mod tests;
