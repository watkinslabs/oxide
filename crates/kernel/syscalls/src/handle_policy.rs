// name_to_handle_at(2) 303 / open_by_handle_at(2) 304 — the `struct
// file_handle` ABI and both syscalls' admission ladders (Linux `fs/fhandle.c`).
//
// Both slot files are kernel-gated, so the flag masks, the header validation
// and the ORDER live here where the hosted suite can assert them (CLAUDE.md
// phantom-test rule, docs/53).
//
//   struct file_handle { __u32 handle_bytes; int handle_type; unsigned char f_handle[]; }
//
// The handle this kernel emits is an 8-byte little-endian inode number with
// `handle_type == 1`: enough to compare two paths for same-object identity
// (systemd's `running_in_chroot()` / mountpoint detection) and enough for 304
// to re-open via `sb.ilookup(ino)`.

use syscall::errno::Errno;

/// `AT_HANDLE_MNT_ID_UNIQUE` — write the u64 unique mount id instead of the
/// legacy `int`.
pub const AT_HANDLE_MNT_ID_UNIQUE: u32 = 0x001;
/// `AT_HANDLE_CONNECTABLE` — request a handle that also encodes the parent, so
/// the decoded fd has a known path.
pub const AT_HANDLE_CONNECTABLE: u32 = 0x002;
/// `AT_HANDLE_FID` (numerically `AT_REMOVEDIR`) — the caller only wants an
/// identity comparison and will not open the handle.
pub const AT_HANDLE_FID: u32 = 0x200;
/// `AT_SYMLINK_FOLLOW`.
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
/// `AT_EMPTY_PATH`.
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// The complete flag set `name_to_handle_at` accepts; anything else is EINVAL.
pub const AT_HANDLE_VALID: u32 =
    AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE | AT_HANDLE_CONNECTABLE;

/// `MAX_HANDLE_SZ` (`include/linux/exportfs.h`).
pub const MAX_HANDLE_SZ: u32 = 128;
/// `handle_bytes(4) + handle_type(4)` — the fixed part of `struct file_handle`.
pub const HANDLE_HDR: u64 = 8;
/// Length of the inode FID this kernel encodes.
pub const FID_LEN: u32 = 8;
/// `handle_type` of that FID. Must be nonzero: `FILEID_ROOT == 0` means "the
/// filesystem root, no FID bytes".
pub const HANDLE_TYPE_INO: i32 = 1;

/// `FILEID_USER_FLAGS_MASK` — the `handle_type` bits userspace may set.
pub const FILEID_USER_FLAGS_MASK: i32 = 0xffff_0000u32 as i32;
/// `FILEID_IS_CONNECTABLE`.
pub const FILEID_IS_CONNECTABLE: i32 = 0x10000;
/// `FILEID_IS_DIR`.
pub const FILEID_IS_DIR: i32 = 0x20000;
/// `FILEID_VALID_USER_FLAGS`.
pub const FILEID_VALID_USER_FLAGS: i32 = FILEID_IS_CONNECTABLE | FILEID_IS_DIR;

/// What `name_to_handle_at`'s flags asked for, once validated.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HandleOpts {
    /// Resolve the final symlink (`AT_SYMLINK_FOLLOW`).
    pub follow: bool,
    /// An empty pathname operates on `dirfd` (`AT_EMPTY_PATH`).
    pub empty: bool,
    /// Write the mount id as a u64 rather than an `int`.
    pub unique_mnt_id: bool,
    /// The caller wants a connectable handle (`AT_HANDLE_CONNECTABLE`).
    pub connectable: bool,
}

/// `name_to_handle_at` flag admission, in Linux's order: the unknown-bit reject
/// first, then the CONNECTABLE conflict.
///
/// `AT_HANDLE_CONNECTABLE` means "I intend to decode this into an fd with a
/// known path"; `AT_HANDLE_FID` means "I will never decode it" and
/// `AT_EMPTY_PATH` can name a disconnected non-directory whose parent is
/// unknown. Both contradict connectability, so Linux rejects the combination
/// rather than silently dropping one.
/// # C: O(1)
pub fn name_to_handle_flags_check(flags: u32) -> Result<HandleOpts, Errno> {
    if flags & !AT_HANDLE_VALID != 0 { return Err(Errno::Einval); }
    if flags & AT_HANDLE_CONNECTABLE != 0 && flags & (AT_HANDLE_FID | AT_EMPTY_PATH) != 0 {
        return Err(Errno::Einval);
    }
    Ok(HandleOpts {
        follow:        flags & AT_SYMLINK_FOLLOW != 0,
        empty:         flags & AT_EMPTY_PATH != 0,
        unique_mnt_id: flags & AT_HANDLE_MNT_ID_UNIQUE != 0,
        connectable:   flags & AT_HANDLE_CONNECTABLE != 0,
    })
}

/// `name_to_handle_at`'s capacity check, run AFTER the path has resolved (Linux
/// looks the path up first, so a missing path reports ENOENT and not the
/// EOVERFLOW a zero-capacity probe would otherwise get).
///
/// `Ok(())` when the caller's buffer holds the FID; `Err(needed)` is the
/// grow-and-retry protocol: write `needed` back into `handle_bytes` and return
/// EOVERFLOW. Over `MAX_HANDLE_SZ` is EINVAL — a capacity no handle can ever
/// need means the caller passed garbage, not a small buffer.
/// # C: O(1)
pub fn handle_capacity_check(caller_bytes: u32) -> Result<Result<(), u32>, Errno> {
    if caller_bytes > MAX_HANDLE_SZ { return Err(Errno::Einval); }
    if caller_bytes < FID_LEN { return Ok(Err(FID_LEN)); }
    Ok(Ok(()))
}

/// `handle_to_path`'s header validation for `open_by_handle_at`, in Linux's
/// order and BEFORE the mount fd is resolved or any capability is consulted:
/// a malformed handle is EINVAL even for an unprivileged caller with a bad fd.
///
/// `handle_bytes == 0` and `> MAX_HANDLE_SZ` are both EINVAL; a negative
/// `handle_type` is EINVAL; and `handle_type`'s user-flag bits must lie inside
/// `FILEID_VALID_USER_FLAGS`.
/// # C: O(1)
pub fn handle_header_check(handle_bytes: u32, handle_type: i32) -> Result<(), Errno> {
    if handle_bytes > MAX_HANDLE_SZ || handle_bytes == 0 { return Err(Errno::Einval); }
    if handle_type < 0 { return Err(Errno::Einval); }
    if handle_type & FILEID_USER_FLAGS_MASK & !FILEID_VALID_USER_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// True when a validated header names the inode FID this kernel encodes. A
/// well-formed handle from another encoder passes [`handle_header_check`] but
/// cannot be decoded here — Linux's answer for an undecodable-but-valid handle
/// is ESTALE, not EINVAL, because the handle may simply describe an object this
/// filesystem no longer has.
/// # C: O(1)
pub fn header_is_our_fid(handle_bytes: u32, handle_type: i32) -> bool {
    handle_bytes == FID_LEN && (handle_type & !FILEID_VALID_USER_FLAGS) == HANDLE_TYPE_INO
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five accepted flags, and a bit outside them. `AT_HANDLE_FID` shares
    /// its value with `AT_REMOVEDIR`, so a mask that forgot it would reject
    /// every `fanotify`-style identity probe. # C: O(1)
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
    /// alongside a conflicting pair still reports the same EINVAL — and a
    /// caller cannot use an unknown bit to bypass the conflict rule. # C: O(1)
    #[test]
    fn unknown_bits_are_rejected_alongside_conflicts() {
        assert_eq!(name_to_handle_flags_check(AT_HANDLE_CONNECTABLE | AT_HANDLE_FID | 0x4),
            Err(Errno::Einval));
    }

    /// Under-capacity is the grow-and-retry signal carrying the REQUIRED size,
    /// not a bare error: a caller probing with `handle_bytes = 0` must learn 8.
    /// # C: O(1)
    #[test]
    fn small_buffer_reports_the_required_size() {
        assert_eq!(handle_capacity_check(0), Ok(Err(FID_LEN)));
        assert_eq!(handle_capacity_check(7), Ok(Err(FID_LEN)));
        assert_eq!(handle_capacity_check(FID_LEN), Ok(Ok(())));
        assert_eq!(handle_capacity_check(MAX_HANDLE_SZ), Ok(Ok(())));
    }

    /// A capacity above MAX_HANDLE_SZ is EINVAL, distinguishing "buffer too
    /// small" from "caller passed nonsense". # C: O(1)
    #[test]
    fn oversized_capacity_is_einval() {
        assert_eq!(handle_capacity_check(MAX_HANDLE_SZ + 1), Err(Errno::Einval));
        assert_eq!(handle_capacity_check(u32::MAX), Err(Errno::Einval));
    }

    /// Header validation covers zero, oversize, negative type, and unknown
    /// user-flag bits — all EINVAL, all before any fd or capability is looked
    /// at. # C: O(1)
    #[test]
    fn header_check_rejects_malformed_handles() {
        assert_eq!(handle_header_check(FID_LEN, HANDLE_TYPE_INO), Ok(()));
        assert_eq!(handle_header_check(0, HANDLE_TYPE_INO), Err(Errno::Einval));
        assert_eq!(handle_header_check(MAX_HANDLE_SZ + 1, HANDLE_TYPE_INO), Err(Errno::Einval));
        assert_eq!(handle_header_check(FID_LEN, -1), Err(Errno::Einval));
        assert_eq!(handle_header_check(FID_LEN, i32::MIN), Err(Errno::Einval));
        assert_eq!(handle_header_check(FID_LEN, 0x4000_0000), Err(Errno::Einval),
            "a user-flag bit outside FILEID_VALID_USER_FLAGS");
    }

    /// The two documented user flags are accepted in `handle_type`, and a
    /// handle carrying them still decodes as our FID — 303 sets them for a
    /// connectable/dir handle and 304 must not treat them as a foreign type.
    /// # C: O(1)
    #[test]
    fn valid_user_flags_pass_and_do_not_change_the_fid_type() {
        for f in [FILEID_IS_CONNECTABLE, FILEID_IS_DIR, FILEID_VALID_USER_FLAGS] {
            assert_eq!(handle_header_check(FID_LEN, HANDLE_TYPE_INO | f), Ok(()), "flag {f:#x}");
            assert!(header_is_our_fid(FID_LEN, HANDLE_TYPE_INO | f), "flag {f:#x}");
        }
    }

    /// A well-formed handle from a different encoder is NOT ours. Its errno is
    /// the caller's business (ESTALE, per Linux's undecodable-handle contract),
    /// but the classification has to be right first. # C: O(1)
    #[test]
    fn foreign_handles_are_recognised_as_not_ours() {
        assert!(!header_is_our_fid(4, HANDLE_TYPE_INO), "wrong length");
        assert!(!header_is_our_fid(FID_LEN, 2), "wrong type");
        assert!(!header_is_our_fid(FID_LEN, 0), "FILEID_ROOT is not an inode FID");
        assert!(header_is_our_fid(FID_LEN, HANDLE_TYPE_INO));
    }
}
