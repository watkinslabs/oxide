// `IORING_OP_READV_FIXED` / `IORING_OP_WRITEV_FIXED` — the read/write shape
// whose operands are not the plain (address, length) pair.
//
// A vectored-fixed transfer names a SEGMENT VECTOR in `addr`/`len` and a
// REGISTERED BUFFER in `buf_index`, and each segment addresses a window inside
// that registration. That is what separates it from an ordinary `readv`: the
// segments never name arbitrary memory, so the transfer reaches the frames
// pinned at registration time whatever the process has done to its mappings
// since, and it can still be split into pieces the way a vector allows.
//
// Ungated: the operand ladder is a decision, and the files that move the bytes
// are kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

use super::ops::{IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED, IOSQE_BUFFER_SELECT};

/// `UIO_MAXIOV` — most segments one vector may hold.
pub const UIO_MAXIOV: u32 = 1024;

/// Whether the opcode is a vectored transfer through a registered buffer.
/// # C: O(1)
pub fn is_vec_fixed(op: u8) -> bool {
    matches!(op, IORING_OP_READV_FIXED | IORING_OP_WRITEV_FIXED)
}

/// A vectored-fixed transfer, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VecFixedOp {
    /// The `struct iovec` array's user address.
    pub uvec: u64,
    /// How many segments it holds.
    pub nr: u32,
    /// Which registered buffer the segments address.
    pub buf_index: u16,
    /// The file offset, or `None` for "the description's own position".
    pub off: Option<u64>,
    /// Whether the bytes move out of the buffer rather than into it.
    pub write: bool,
}

/// The file-offset value meaning "use the description's own position".
pub const CUR_POS: u64 = u64::MAX;

/// Admit and decode a vectored-fixed transfer.
///
/// | rung | errno |
/// |---|---|
/// | an empty vector, or one longer than `UIO_MAXIOV` | `EINVAL` |
/// | the entry also draws from a provided-buffer group | `EINVAL` |
///
/// The group rung is the one that would otherwise go unnoticed: `buf_index`
/// and `buf_group` are the same field, so an entry carrying
/// `IOSQE_BUFFER_SELECT` would have that field read as a group by the
/// selection path and as a registration by this one — two different buffers
/// for one transfer, and whichever ran second would win silently. # C: O(1)
pub fn prep_vec_fixed(sqe: &Sqe) -> Result<VecFixedOp, Errno> {
    if sqe.len == 0 || sqe.len > UIO_MAXIOV { return Err(Errno::Einval); }
    if sqe.flags & IOSQE_BUFFER_SELECT != 0 { return Err(Errno::Einval); }
    Ok(VecFixedOp {
        uvec: sqe.addr,
        nr: sqe.len,
        buf_index: sqe.buf_index,
        off: if sqe.off == CUR_POS { None } else { Some(sqe.off) },
        write: sqe.opcode == IORING_OP_WRITEV_FIXED,
    })
}

/// One segment of a vector, as it addresses a registered buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seg {
    pub base: u64,
    pub len: u64,
}

/// `struct iovec` — two pointer-width words, identical on both arches.
pub const IOVEC_BYTES: u64 = 16;
/// `iov_len`'s offset inside it.
pub const IOVEC_LEN_OFF: u64 = 8;

/// Decode one segment from its 16 wire bytes. # C: O(1)
pub fn seg_from_wire(b: &[u8; IOVEC_BYTES as usize]) -> Seg {
    let w = |o: usize| u64::from_le_bytes([b[o], b[o+1], b[o+2], b[o+3], b[o+4], b[o+5], b[o+6], b[o+7]]);
    Seg { base: w(0), len: w(IOVEC_LEN_OFF as usize) }
}

#[cfg(test)]
#[path = "rw_vec/tests.rs"]
mod tests;
