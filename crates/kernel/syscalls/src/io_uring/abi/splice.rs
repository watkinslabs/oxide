// `IORING_OP_SPLICE` and `IORING_OP_TEE` — moving bytes between two
// descriptions without either of them passing through the caller.
//
// The entry names its OUTPUT description the ordinary way, in `fd`, and its
// INPUT description in `splice_fd_in`. That second descriptor has an
// indirection of its own that no other opcode has: `SPLICE_F_FD_IN_FIXED`
// makes it an index into the ring's registered-file table rather than a
// descriptor of the task. The bit is a flag of io_uring, not of the transfer,
// so it is stripped before the flag word reaches the splice machinery — left
// in, it would be an undefined bit and the transfer would refuse the whole
// request.
//
// `tee` duplicates rather than consumes, so neither side has an offset: an
// entry that supplies one is describing an operation that does not exist, and
// is refused rather than served with the offset dropped.
//
// Ungated: every line here is a decision about the entry, and the file that
// moves the bytes is kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

use super::ops::{IORING_OP_SPLICE, IORING_OP_TEE};

/// `SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT` — every
/// flag the transfer itself defines.
pub const SPLICE_F_ALL: u32 = 0xf;
/// `SPLICE_F_FD_IN_FIXED` — `splice_fd_in` is a registered-file index. The top
/// bit of the word, so it cannot collide with a transfer flag added later.
pub const SPLICE_F_FD_IN_FIXED: u32 = 1 << 31;
/// Every bit an entry of this family may carry.
pub const SPLICE_VALID_FLAGS: u32 = SPLICE_F_ALL | SPLICE_F_FD_IN_FIXED;

/// The offset value meaning "use the description's own position".
pub const NO_OFFSET: u64 = u64::MAX;

/// Whether the opcode is one of the two. # C: O(1)
pub fn is_splice_family(op: u8) -> bool { matches!(op, IORING_OP_SPLICE | IORING_OP_TEE) }

/// One entry of the family, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpliceOp {
    /// The input description: a registered-file index when `fd_in_fixed`, a
    /// descriptor of the task otherwise.
    pub fd_in: i32,
    /// Whether `fd_in` is a registered-file index.
    pub fd_in_fixed: bool,
    /// The flag word the transfer sees — the io_uring-only bit removed.
    pub flags: u32,
    pub len: u32,
    /// Input offset, or `None` for "the description's own position". Always
    /// `None` for a tee.
    pub off_in: Option<u64>,
    /// Output offset, or `None`. Always `None` for a tee.
    pub off_out: Option<u64>,
}

/// Decode and admit one entry.
///
/// | rung | errno |
/// |---|---|
/// | a flag bit neither the transfer nor io_uring defines | `EINVAL` |
/// | a tee carrying either offset | `EINVAL` |
///
/// The offset rung is a tee's alone: a duplicate leaves both descriptions
/// where they were, so there is no position for an offset to name, and
/// accepting one would answer a request the caller did not make. # C: O(1)
pub fn prep(sqe: &Sqe) -> Result<SpliceOp, Errno> {
    let raw = sqe.op_flags;
    if raw & !SPLICE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    let tee = sqe.opcode == IORING_OP_TEE;
    // `splice_off_in` and `addr` are the same word; `off` and `addr2` are the
    // same word. A tee reads neither, so both must be zero.
    if tee && (sqe.addr != 0 || sqe.off != 0) { return Err(Errno::Einval); }
    let off = |v: u64| if v == NO_OFFSET { None } else { Some(v) };
    Ok(SpliceOp {
        fd_in: sqe.splice_fd_in,
        fd_in_fixed: raw & SPLICE_F_FD_IN_FIXED != 0,
        flags: raw & !SPLICE_F_FD_IN_FIXED,
        len: sqe.len,
        off_in:  if tee { None } else { off(sqe.addr) },
        off_out: if tee { None } else { off(sqe.off) },
    })
}

#[cfg(test)]
#[path = "splice/tests.rs"]
mod tests;
