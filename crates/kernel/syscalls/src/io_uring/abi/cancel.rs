// `IORING_OP_ASYNC_CANCEL` and `IORING_REGISTER_SYNC_CANCEL` argument decode,
// and the rule that decides whether one in-flight request is a match.
//
// The match rule is the whole of cancellation: everything else is a search
// order over the in-flight table. Kept out of the (kernel-gated) engine so
// each key combination is unit-tested (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_abi::ops::OP_LAST;
use crate::io_uring_sqe::Sqe;

/// `IORING_ASYNC_CANCEL_ALL` — cancel every match, not just the first.
pub const IORING_ASYNC_CANCEL_ALL:      u32 = 1 << 0;
/// `IORING_ASYNC_CANCEL_FD` — match on the descriptor, not on `user_data`.
pub const IORING_ASYNC_CANCEL_FD:       u32 = 1 << 1;
/// `IORING_ASYNC_CANCEL_ANY` — match every request in the ring.
pub const IORING_ASYNC_CANCEL_ANY:      u32 = 1 << 2;
/// `IORING_ASYNC_CANCEL_FD_FIXED` — the descriptor is a registered-file index.
pub const IORING_ASYNC_CANCEL_FD_FIXED: u32 = 1 << 3;
/// `IORING_ASYNC_CANCEL_USERDATA` — match `user_data` as well as fd/opcode.
pub const IORING_ASYNC_CANCEL_USERDATA: u32 = 1 << 4;
/// `IORING_ASYNC_CANCEL_OP` — match on the opcode.
pub const IORING_ASYNC_CANCEL_OP:       u32 = 1 << 5;

/// Every defined cancel flag; a bit outside this mask is `EINVAL`.
pub const CANCEL_FLAGS: u32 =
    IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ANY
    | IORING_ASYNC_CANCEL_FD_FIXED | IORING_ASYNC_CANCEL_USERDATA | IORING_ASYNC_CANCEL_OP;

/// `sizeof(struct io_uring_sync_cancel_reg)`.
pub const SYNC_CANCEL_BYTES: usize = 64;

/// What a cancellation is looking for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CancelKey {
    pub flags: u32,
    /// `user_data` to match, when `user_data` is part of the key.
    pub data: u64,
    /// Descriptor to match, when `IORING_ASYNC_CANCEL_FD` is set.
    pub fd: i32,
    /// Opcode to match, when `IORING_ASYNC_CANCEL_OP` is set.
    pub opcode: u8,
}

impl CancelKey {
    /// Whether every match is wanted rather than only the first. # C: O(1)
    pub fn all(&self) -> bool {
        self.flags & (IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_ANY) != 0
    }

    /// Whether the descriptor names a registered-file slot. # C: O(1)
    pub fn fd_fixed(&self) -> bool { self.flags & IORING_ASYNC_CANCEL_FD_FIXED != 0 }

    /// Whether `user_data` is part of the key. Naming an fd or an opcode
    /// replaces the `user_data` match rather than narrowing it, unless the
    /// caller asks for both explicitly. # C: O(1)
    pub fn matches_user_data(&self) -> bool {
        if self.flags & (IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_OP) == 0 { return true; }
        self.flags & IORING_ASYNC_CANCEL_USERDATA != 0
    }

    /// Whether an in-flight request described by `(user_data, fd, opcode)` is
    /// a match. # C: O(1)
    pub fn matches(&self, user_data: u64, fd: i32, opcode: u8) -> bool {
        if self.flags & IORING_ASYNC_CANCEL_ANY != 0 { return true; }
        if self.flags & IORING_ASYNC_CANCEL_FD != 0 && fd != self.fd { return false; }
        if self.flags & IORING_ASYNC_CANCEL_OP != 0 && opcode != self.opcode { return false; }
        if self.matches_user_data() && user_data != self.data { return false; }
        true
    }
}

/// Decode `IORING_OP_ASYNC_CANCEL`. # C: O(1)
pub fn prep_cancel(sqe: &Sqe) -> Result<CancelKey, Errno> {
    use crate::io_uring_abi::ops::IOSQE_BUFFER_SELECT;
    if sqe.flags & IOSQE_BUFFER_SELECT != 0 { return Err(Errno::Einval); }
    if sqe.off != 0 || sqe.splice_fd_in != 0 { return Err(Errno::Einval); }
    let flags = sqe.op_flags;
    if flags & !CANCEL_FLAGS != 0 { return Err(Errno::Einval); }
    let mut key = CancelKey { flags, data: sqe.addr, ..CancelKey::default() };
    if flags & IORING_ASYNC_CANCEL_FD != 0 {
        // "this one descriptor" and "anything at all" are two different
        // searches; asking for both describes nothing.
        if flags & IORING_ASYNC_CANCEL_ANY != 0 { return Err(Errno::Einval); }
        key.fd = sqe.fd;
    }
    if flags & IORING_ASYNC_CANCEL_OP != 0 {
        if flags & IORING_ASYNC_CANCEL_ANY != 0 { return Err(Errno::Einval); }
        if sqe.len >= OP_LAST as u32 { return Err(Errno::Einval); }
        key.opcode = sqe.len as u8;
    }
    Ok(key)
}

/// The sentinel `struct io_uring_sync_cancel_reg.timeout` carries when the
/// caller wants no deadline at all.
pub const SYNC_CANCEL_NO_TIMEOUT: (i64, i64) = (-1, -1);

/// One decoded `IORING_REGISTER_SYNC_CANCEL` argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SyncCancel {
    pub key: CancelKey,
    /// How long to keep retrying a match that is mid-flight. `None` = forever.
    pub timeout: Option<(i64, i64)>,
}

/// Decode the 64-byte `struct io_uring_sync_cancel_reg` image. # C: O(1)
pub fn decode_sync_cancel(b: &[u8; SYNC_CANCEL_BYTES]) -> Result<SyncCancel, Errno> {
    let g32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let g64 = |o: usize| {
        let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); i64::from_le_bytes(v)
    };
    let flags = g32(12);
    if flags & !CANCEL_FLAGS != 0 { return Err(Errno::Einval); }
    // The padding is refused rather than ignored so the struct can grow.
    if b[33..40].iter().any(|&x| x != 0) { return Err(Errno::Einval); }
    if b[40..64].iter().any(|&x| x != 0) { return Err(Errno::Einval); }
    let ts = (g64(16), g64(24));
    Ok(SyncCancel {
        key: CancelKey {
            flags, data: g64(0) as u64, fd: g32(8) as i32, opcode: b[32],
        },
        timeout: if ts == SYNC_CANCEL_NO_TIMEOUT { None } else { Some(ts) },
    })
}

/// The value `IORING_REGISTER_SYNC_CANCEL` reports. Finding nothing is a
/// success: the caller asked for the request to be gone, and it is.
/// # C: O(1)
pub fn sync_cancel_result(rv: i64) -> i64 {
    if rv > 0 { return 0; }
    if rv == -(Errno::Enoent.as_i32() as i64) { return 0; }
    rv
}

/// The value `IORING_OP_ASYNC_CANCEL` reports: a count when every match was
/// wanted, otherwise the single attempt's own result. # C: O(1)
pub fn cancel_result(key: &CancelKey, nr: u32, rv: i64) -> i64 {
    if key.all() { return nr as i64; }
    rv
}

#[cfg(test)]
#[path = "cancel/tests.rs"]
mod tests;
