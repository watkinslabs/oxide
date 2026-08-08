// Verified pidfs ioctl contract: the fixed namespace command numbers, the
// extensible `PIDFD_GET_INFO` match rule, and the struct-length gate on which
// result bits may be advertised.

use super::*;

/// `_IOWR(0xFF, 11, struct pidfd_info)` for a caller whose struct is `size`.
fn get_info_cmd(size: usize) -> u64 {
    (0x3u64 << 30) | ((size as u64) << 16) | (PIDFS_IOCTL_MAGIC << 8) | PIDFD_GET_INFO_NR
}

#[test]
fn each_namespace_command_number_names_its_own_namespace() {
    // The numbers are ABI: a shift by one silently hands a caller asking for
    // its own mount namespace someone else's network namespace.
    let want = [
        (1u64, NsKind::Cgroup), (2, NsKind::Ipc), (3, NsKind::Mnt), (4, NsKind::Net),
        (5, NsKind::Pid), (6, NsKind::PidForChildren), (7, NsKind::Time),
        (8, NsKind::TimeForChildren), (9, NsKind::User), (10, NsKind::Uts),
    ];
    for (nr, kind) in want {
        assert_eq!(decide(pidfs_io(nr)), Some(PidfsIoctl::Namespace(kind)), "nr {nr}");
    }
}

#[test]
fn the_namespace_range_is_closed_at_both_ends() {
    assert_eq!(decide(pidfs_io(0)), None, "0 names no namespace");
    for nr in 11..=20u64 {
        assert!(!matches!(decide(pidfs_io(nr)), Some(PidfsIoctl::Namespace(_))),
                "nr {nr} must not be a namespace command");
    }
}

#[test]
fn a_namespace_command_is_matched_whole_not_by_number_alone() {
    // A different magic, a direction bit or a size field means a DIFFERENT
    // driver's ioctl that merely shares the low byte.
    assert_eq!(decide((0xFEu64 << 8) | 3), None, "another magic is not ours");
    assert_eq!(decide((0x1u64 << 30) | (0xFF << 8) | 3), None, "a direction bit disqualifies");
    assert_eq!(decide((4u64 << 16) | (0xFF << 8) | 3), None, "a size field disqualifies");
}

#[test]
fn get_info_matches_every_published_struct_size_and_beyond() {
    for size in [PIDFD_INFO_SIZE_VER0, PIDFD_INFO_SIZE_VER1,
                 PIDFD_INFO_SIZE_VER2, PIDFD_INFO_SIZE_VER3, 4096] {
        assert_eq!(decide(get_info_cmd(size)), Some(PidfsIoctl::Info { size }),
                   "an extensible command must match at size {size}");
    }
}

#[test]
fn get_info_below_the_first_published_size_is_refused() {
    // The size floor is what stops a stray ioctl on a non-pidfd fd, whose
    // command word happens to share the magic and number, being taken for one.
    for size in [0, 1, 8, PIDFD_INFO_SIZE_VER0 - 1] {
        assert_eq!(decide(get_info_cmd(size)), None, "size {size} cannot span the first struct");
    }
}

#[test]
fn get_info_requires_the_read_write_direction() {
    let size = PIDFD_INFO_SIZE_VER3;
    for dir in [0u64, 1, 2] {
        let cmd = (dir << 30) | ((size as u64) << 16) | (PIDFS_IOCTL_MAGIC << 8) | PIDFD_GET_INFO_NR;
        assert_eq!(decide(cmd), None, "direction {dir} is not what _IOWR encodes");
    }
}

#[test]
fn a_short_struct_never_advertises_a_field_it_cannot_hold() {
    let v0 = mask_fitting(PIDFD_INFO_SIZE_VER0);
    assert_eq!(v0 & (PIDFD_INFO_COREDUMP | PIDFD_INFO_COREDUMP_SIGNAL
                     | PIDFD_INFO_COREDUMP_CODE | PIDFD_INFO_SUPPORTED_MASK), 0);
    assert_ne!(v0 & PIDFD_INFO_PID, 0);
    assert_ne!(v0 & PIDFD_INFO_CREDS, 0);
    assert_ne!(v0 & PIDFD_INFO_CGROUPID, 0);
    assert_ne!(v0 & PIDFD_INFO_EXIT, 0);

    let v1 = mask_fitting(PIDFD_INFO_SIZE_VER1);
    assert_ne!(v1 & PIDFD_INFO_COREDUMP, 0, "coredump_mask ends inside VER1");
    assert_ne!(v1 & PIDFD_INFO_COREDUMP_SIGNAL, 0, "coredump_signal ends inside VER1");
    assert_eq!(v1 & PIDFD_INFO_COREDUMP_CODE, 0, "coredump_code does not");
    assert_eq!(v1 & PIDFD_INFO_SUPPORTED_MASK, 0);

    let v2 = mask_fitting(PIDFD_INFO_SIZE_VER2);
    assert_ne!(v2 & PIDFD_INFO_COREDUMP_CODE, 0, "coredump_code ends inside VER2");
    assert_eq!(v2 & PIDFD_INFO_SUPPORTED_MASK, 0, "supported_mask does not");

    assert_eq!(mask_fitting(PIDFD_INFO_SIZE_VER3), SUPPORTED_MASK,
               "the newest struct can carry every bit this kernel sets");
}

#[test]
fn the_fitting_mask_only_ever_grows_with_the_struct() {
    let mut prev = 0u64;
    for len in 0..=PIDFD_INFO_SIZE_VER3 + 16 {
        let m = mask_fitting(len);
        assert_eq!(m & prev, prev, "a longer struct must never lose a bit (at {len})");
        prev = m;
    }
}

#[test]
fn the_published_struct_sizes_bound_their_own_fields() {
    // The offsets and the version sizes are one ABI and must not drift apart.
    assert_eq!(INFO_OFF_EXIT_CODE + 4, PIDFD_INFO_SIZE_VER0);
    assert_eq!(INFO_OFF_COREDUMP_SIGNAL + 4, PIDFD_INFO_SIZE_VER1);
    assert_eq!(INFO_OFF_COREDUMP_CODE + 8, PIDFD_INFO_SIZE_VER2, "code plus its pad");
    assert_eq!(INFO_OFF_SUPPORTED_MASK + 8, PIDFD_INFO_SIZE_VER3);
    assert_eq!(INFO_OFF_MASK, 0);
    assert_eq!(INFO_OFF_CGROUPID, 8);
    assert_eq!(INFO_OFF_PID, 16);
}

#[test]
fn the_mask_bits_are_the_published_positions() {
    assert_eq!(PIDFD_INFO_PID, 1 << 0);
    assert_eq!(PIDFD_INFO_CREDS, 1 << 1);
    assert_eq!(PIDFD_INFO_CGROUPID, 1 << 2);
    assert_eq!(PIDFD_INFO_EXIT, 1 << 3);
    assert_eq!(PIDFD_INFO_COREDUMP, 1 << 4);
    assert_eq!(PIDFD_INFO_SUPPORTED_MASK, 1 << 5);
    assert_eq!(PIDFD_INFO_COREDUMP_SIGNAL, 1 << 6);
    assert_eq!(PIDFD_INFO_COREDUMP_CODE, 1 << 7);
    assert_eq!(PIDFD_COREDUMPED, 1 << 0);
    assert_eq!(PIDFD_COREDUMP_SKIP, 1 << 1);
    assert_eq!(PIDFD_COREDUMP_USER, 1 << 2);
    assert_eq!(PIDFD_COREDUMP_ROOT, 1 << 3);
}
