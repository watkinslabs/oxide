// `name_to_handle_at(2)` flag admission + the grow-and-retry capacity protocol.

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

/// `MAX_HANDLE_SZ` — the largest `f_handle` payload any encoder may need.
pub const MAX_HANDLE_SZ: u32 = 128;
/// `handle_bytes(4) + handle_type(4)` — the fixed part of `struct file_handle`.
pub const HANDLE_HDR: u64 = 8;

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
/// `needed` is what THIS object's handle costs — a connectable non-directory
/// carries a parent and so costs more than a plain one, which is why the size
/// cannot be a constant.
///
/// `Ok(())` when the caller's buffer holds the FID; `Err(needed)` is the
/// grow-and-retry protocol: write `needed` back into `handle_bytes` and return
/// EOVERFLOW. Over `MAX_HANDLE_SZ` is EINVAL — a capacity no handle can ever
/// need means the caller passed garbage, not a small buffer.
/// # C: O(1)
pub fn handle_capacity_check(caller_bytes: u32, needed: u32) -> Result<Result<(), u32>, Errno> {
    if caller_bytes > MAX_HANDLE_SZ { return Err(Errno::Einval); }
    if caller_bytes < needed { return Ok(Err(needed)); }
    Ok(Ok(()))
}
