use crate::handle_policy::flags::*;
use syscall::errno::Errno;

/// The five accepted flags, and a bit outside them. `AT_HANDLE_FID` shares its
/// value with `AT_REMOVEDIR`, so a mask that forgot it would reject every
/// identity-only probe. # C: O(1)
#[test]
fn valid_flag_set_is_the_linux_five() {
    assert_eq!(name_to_handle_flags_check(0),
        Ok(HandleOpts { follow: false, empty: false, unique_mnt_id: false, connectable: false }));
    assert_eq!(name_to_handle_flags_check(AT_SYMLINK_FOLLOW).map(|o| o.follow), Ok(true));
    assert_eq!(name_to_handle_flags_check(AT_EMPTY_PATH).map(|o| o.empty), Ok(true));
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_FID), Ok(HandleOpts {
        follow: false, empty: false, unique_mnt_id: false, connectable: false }));
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_MNT_ID_UNIQUE).map(|o| o.unique_mnt_id), Ok(true));
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE).map(|o| o.connectable), Ok(true));
    for f in [0x4u32, 0x8, 0x100, 0x800, 0x2000, 0x8000_0000] {
        assert_eq!(name_to_handle_flags_check(f), Err(Errno::Einval), "flag {f:#x}");
    }
}

/// CONNECTABLE contradicts both FID and EMPTY_PATH and the combination is
/// EINVAL, not a silently-dropped flag. # C: O(1)
#[test]
fn connectable_conflicts_with_fid_and_empty_path() {
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE | AT_HANDLE_FID), Err(Errno::Einval));
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE | AT_EMPTY_PATH), Err(Errno::Einval));
    assert!(name_to_handle_flags_check(AT_HANDLE_FID | AT_EMPTY_PATH).is_ok(),
        "FID and EMPTY_PATH do not conflict with each other");
    assert!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE | AT_SYMLINK_FOLLOW).is_ok());
}

/// The unknown-bit reject runs before the conflict check, so an unknown bit
/// alongside a conflicting pair still reports the same EINVAL — and a caller
/// cannot use an unknown bit to bypass the conflict rule. # C: O(1)
#[test]
fn unknown_bits_are_rejected_alongside_conflicts() {
    assert_eq!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE | AT_HANDLE_FID | 0x4),
        Err(Errno::Einval));
}

/// Under-capacity is the grow-and-retry signal carrying the REQUIRED size, not
/// a bare error: a caller probing with `handle_bytes = 0` must learn the size
/// THIS object needs. # C: O(1)
#[test]
fn small_buffer_reports_the_required_size() {
    use crate::handle_policy::fid::{FID_LEN, FID_LEN_PARENT};
    assert_eq!(handle_capacity_check(0, FID_LEN), Ok(Err(FID_LEN)));
    assert_eq!(handle_capacity_check(FID_LEN - 1, FID_LEN), Ok(Err(FID_LEN)));
    assert_eq!(handle_capacity_check(FID_LEN, FID_LEN), Ok(Ok(())));
    // A connectable non-directory needs the LARGER size, and a buffer sized for
    // a plain handle must be told so rather than silently truncating the
    // parent — the failure mode that made AT_HANDLE_CONNECTABLE unusable.
    assert_eq!(handle_capacity_check(FID_LEN, FID_LEN_PARENT), Ok(Err(FID_LEN_PARENT)));
    assert_eq!(handle_capacity_check(FID_LEN_PARENT, FID_LEN_PARENT), Ok(Ok(())));
    assert_eq!(handle_capacity_check(MAX_HANDLE_SZ, FID_LEN), Ok(Ok(())));
}

/// A capacity above MAX_HANDLE_SZ is EINVAL, distinguishing "buffer too small"
/// from "caller passed nonsense". # C: O(1)
#[test]
fn oversized_capacity_is_einval() {
    use crate::handle_policy::fid::FID_LEN;
    assert_eq!(handle_capacity_check(MAX_HANDLE_SZ + 1, FID_LEN), Err(Errno::Einval));
    assert_eq!(handle_capacity_check(u32::MAX, FID_LEN), Err(Errno::Einval));
}
