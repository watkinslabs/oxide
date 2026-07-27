use super::aarch64_nr_to_x86;
use crate::nrs::*;

#[test]
fn at_family_lands_on_at_x86() {
    assert_eq!(aarch64_nr_to_x86(33), NR_MKNODAT, "arm mknodat → x86 mknodat");
    assert_eq!(aarch64_nr_to_x86(34), NR_MKDIRAT, "arm mkdirat → x86 mkdirat");
    assert_eq!(aarch64_nr_to_x86(35), NR_UNLINKAT, "arm unlinkat → x86 unlinkat");
    assert_eq!(aarch64_nr_to_x86(36), NR_SYMLINKAT, "arm symlinkat → x86 symlinkat");
    assert_eq!(aarch64_nr_to_x86(37), NR_LINKAT, "arm linkat → x86 linkat");
    assert_eq!(aarch64_nr_to_x86(38), NR_RENAMEAT, "arm renameat → x86 renameat");
    assert_eq!(aarch64_nr_to_x86(53), NR_FCHMODAT, "arm fchmodat → x86 fchmodat");
    assert_eq!(aarch64_nr_to_x86(54), NR_FCHOWNAT, "arm fchownat → x86 fchownat");
    assert_eq!(aarch64_nr_to_x86(56), NR_OPENAT, "arm openat → x86 openat");
    assert_eq!(aarch64_nr_to_x86(78), NR_READLINKAT, "arm readlinkat → x86 readlinkat");
    assert_eq!(aarch64_nr_to_x86(79), NR_NEWFSTATAT, "arm newfstatat → x86 newfstatat");
    assert_eq!(aarch64_nr_to_x86(88), NR_UTIMENSAT, "arm utimensat → x86 utimensat");
}

#[test]
fn chroot_maps_to_chroot_not_chown() {
    assert_eq!(aarch64_nr_to_x86(51), NR_CHROOT);
    assert_ne!(aarch64_nr_to_x86(51), NR_CHOWN);
}

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

#[test]
fn unknown_passes_through() {
    assert_eq!(aarch64_nr_to_x86(999_999), 999_999);
}

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

#[test]
fn caps_not_wrong() {
    assert_eq!(aarch64_nr_to_x86(90), NR_CAPGET);
    assert_eq!(aarch64_nr_to_x86(91), NR_CAPSET);
}

#[test]
fn itimer_unswapped() {
    assert_eq!(aarch64_nr_to_x86(102), 36);
    assert_eq!(aarch64_nr_to_x86(103), 38);
}

#[test]
fn rt_sig_block_correct() {
    assert_eq!(aarch64_nr_to_x86(133), NR_RT_SIGSUSPEND);
    assert_eq!(aarch64_nr_to_x86(137), NR_RT_SIGTIMEDWAIT);
    assert_eq!(aarch64_nr_to_x86(138), NR_RT_SIGQUEUEINFO);
    assert_eq!(aarch64_nr_to_x86(139), NR_RT_SIGRETURN);
}

#[test]
fn statfs_at_right_arm_slot() {
    assert_eq!(aarch64_nr_to_x86(43), NR_STATFS);
    assert_eq!(aarch64_nr_to_x86(44), NR_FSTATFS);
    assert_eq!(aarch64_nr_to_x86(45), NR_TRUNCATE);
    assert_eq!(aarch64_nr_to_x86(46), NR_FTRUNCATE);
}

#[test]
fn timer_family_at_right_arm_slot() {
    assert_eq!(aarch64_nr_to_x86(107), NR_TIMER_CREATE);
    assert_eq!(aarch64_nr_to_x86(108), NR_TIMER_GETTIME);
    assert_eq!(aarch64_nr_to_x86(109), NR_TIMER_GETOVERRUN);
    assert_eq!(aarch64_nr_to_x86(110), NR_TIMER_SETTIME);
    assert_eq!(aarch64_nr_to_x86(111), NR_TIMER_DELETE);
}

#[test]
fn eventfd2_at_right_slot() {
    assert_eq!(aarch64_nr_to_x86(19), NR_EVENTFD2);
    assert_eq!(aarch64_nr_to_x86(59), 293);
}

#[test]
fn dup3_not_dup2() {
    assert_eq!(aarch64_nr_to_x86(24), NR_DUP3);
}

#[test]
fn sync_at_right_slot() {
    assert_eq!(aarch64_nr_to_x86(81), NR_SYNC);
}

#[test]
fn prlimit64_translated() {
    assert_eq!(aarch64_nr_to_x86(261), NR_PRLIMIT64);
    assert_ne!(aarch64_nr_to_x86(261), NR_FUTIMESAT);
}

#[test]
fn epoll_family_translated() {
    assert_eq!(aarch64_nr_to_x86(20), NR_EPOLL_CREATE1);
    assert_eq!(aarch64_nr_to_x86(21), NR_EPOLL_CTL);
    assert_eq!(aarch64_nr_to_x86(22), NR_EPOLL_PWAIT);
}

#[test]
fn inotify_family_translated() {
    assert_eq!(aarch64_nr_to_x86(26), NR_INOTIFY_INIT1);
    assert_eq!(aarch64_nr_to_x86(27), NR_INOTIFY_ADD_WATCH);
    assert_eq!(aarch64_nr_to_x86(28), NR_INOTIFY_RM_WATCH);
}

#[test]
fn sysinfo_lands_on_sysinfo() {
    assert_eq!(aarch64_nr_to_x86(179), NR_SYSINFO);
    assert_ne!(aarch64_nr_to_x86(179), NR_GETPID);
}

#[test]
fn modern_fs_syscalls_translated() {
    assert_eq!(aarch64_nr_to_x86(276), NR_RENAMEAT2);
    assert_eq!(aarch64_nr_to_x86(277), NR_SECCOMP);
    assert_eq!(aarch64_nr_to_x86(278), NR_GETRANDOM);
    assert_eq!(aarch64_nr_to_x86(279), NR_MEMFD_CREATE);
}

#[test]
fn sysv_shm_translated() {
    assert_eq!(aarch64_nr_to_x86(194), NR_SHMGET);
    assert_eq!(aarch64_nr_to_x86(195), NR_SHMCTL);
    assert_eq!(aarch64_nr_to_x86(196), NR_SHMAT);
    assert_eq!(aarch64_nr_to_x86(197), NR_SHMDT);
}

#[test]
fn rlimit_translated() {
    assert_eq!(aarch64_nr_to_x86(163), NR_GETRLIMIT);
    assert_eq!(aarch64_nr_to_x86(164), NR_SETRLIMIT);
}

#[test]
fn unified_modern_syscalls() {
    assert_eq!(aarch64_nr_to_x86(424), NR_PIDFD_SEND_SIGNAL);
    assert_eq!(aarch64_nr_to_x86(435), NR_CLONE3);
    assert_eq!(aarch64_nr_to_x86(436), NR_CLOSE_RANGE);
    assert_eq!(aarch64_nr_to_x86(439), NR_FACCESSAT2);
}

// ---------------------------------------------------------------------
// Pass-through collision guards (B1437).
//
// An unmapped arm nr is dispatched as the x86 nr of the SAME value, so a
// gap in MAP does not fail loudly — it silently runs a DIFFERENT syscall
// with the caller's arguments. These pin the cases where that mistake
// would be worst, so a future edit that drops an entry fails here.
// ---------------------------------------------------------------------

/// arm 42 is nfsservctl (`sys_ni_syscall`); x86 42 is connect. Unmapped, a
/// bare `syscall(42, ...)` on arm64 opened a socket connection instead of
/// returning ENOSYS.
#[test]
fn arm_nfsservctl_does_not_become_connect() {
    assert_ne!(aarch64_nr_to_x86(42), NR_CONNECT, "arm nfsservctl must not dispatch as connect");
    assert_eq!(aarch64_nr_to_x86(42), NR_NFSSERVCTL);
}

/// The collision the module header calls out by name: arm 21 is epoll_ctl,
/// x86 21 is access.
#[test]
fn arm_epoll_ctl_does_not_become_access() {
    assert_ne!(aarch64_nr_to_x86(21), NR_ACCESS);
    assert_eq!(aarch64_nr_to_x86(21), NR_EPOLL_CTL);
}

/// The highest-traffic syscalls, whose mistranslation would break every
/// process immediately rather than subtly.
#[test]
fn core_io_translates_exactly() {
    assert_eq!(aarch64_nr_to_x86(63), NR_READ);
    assert_eq!(aarch64_nr_to_x86(64), NR_WRITE);
    assert_eq!(aarch64_nr_to_x86(57), NR_CLOSE);
    assert_eq!(aarch64_nr_to_x86(56), NR_OPENAT);
    assert_eq!(aarch64_nr_to_x86(93), NR_EXIT);
    assert_eq!(aarch64_nr_to_x86(94), NR_EXIT_GROUP);
    assert_eq!(aarch64_nr_to_x86(98), NR_FUTEX);
    assert_eq!(aarch64_nr_to_x86(220), NR_CLONE);
    assert_eq!(aarch64_nr_to_x86(221), NR_EXECVE);
}

/// arm64 uses plain `sync_file_range` at 84, NOT `sync_file_range2`: no arch
/// defines `__ARCH_WANT_SYNC_FILE_RANGE2` in mainline. The two differ in
/// ARGUMENT ORDER — sync_file_range(fd, offset, nbytes, flags) versus
/// sync_file_range2(fd, flags, offset, nbytes) — so picking the wrong one
/// silently swaps a caller's flags and offset.
#[test]
fn arm_sync_file_range_is_not_the_reordered_variant() {
    assert_eq!(aarch64_nr_to_x86(84), NR_SYNC_FILE_RANGE);
}

/// Post-424 numbers are unified across arches, so pass-through is correct
/// there and MUST stay identity — mapping them would break them.
#[test]
fn unified_range_is_identity() {
    for nr in [442u64, 443, 448, 451, 452, 453, 457, 459, 462, 463] {
        assert_eq!(aarch64_nr_to_x86(nr), nr, "unified nr {nr} must pass through unchanged");
    }
}

#[test]
fn restart_syscall_reentry_number_round_trips() {
    // The restart-block re-entry path writes AARCH64_NR_RESTART_SYSCALL into
    // the SVC frame's x8; the dispatcher must translate it back to the x86
    // slot the restart_syscall(2) handler is registered under.
    assert_eq!(aarch64_nr_to_x86(super::AARCH64_NR_RESTART_SYSCALL), NR_RESTART_SYSCALL);
    assert_eq!(super::AARCH64_NR_RESTART_SYSCALL, 128);
}

#[test]
fn thread_primitive_numbers_map_to_their_own_slots() {
    assert_eq!(aarch64_nr_to_x86(178), NR_GETTID);
    assert_eq!(aarch64_nr_to_x86(96), NR_SET_TID_ADDRESS);
    assert_eq!(aarch64_nr_to_x86(130), NR_TKILL);
    assert_eq!(aarch64_nr_to_x86(131), NR_TGKILL);
    assert_eq!(aarch64_nr_to_x86(129), NR_KILL);
    // tkill and tgkill are distinct slots — tkill must not alias kill.
    assert_ne!(aarch64_nr_to_x86(130), NR_KILL);
}
