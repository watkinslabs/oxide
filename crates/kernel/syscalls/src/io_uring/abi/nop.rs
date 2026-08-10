// `IORING_OP_NOP` / `IORING_OP_NOP128`: the operation that does nothing, and
// the flags that make it do nothing in a particular shape.
//
// It exists to exercise the ring itself — a caller uses it to check that a
// descriptor resolves, that a registered buffer is present, that an injected
// result arrives unchanged, and that a completion of the requested WIDTH comes
// back. That last one is what makes it the operation a 32-byte completion is
// tested through: it is the only one whose payload the caller chooses.
//
// `IORING_OP_NOP128` is the same operation on a 128-byte entry, which is what
// makes `IORING_SETUP_SQE128` and `IORING_SETUP_SQE_MIXED` mean something: a
// ring that carries only 64-byte entries refuses it.

use syscall::errno::Errno;

/// `sqe->nop_flags` bits.
///
/// `IORING_NOP_INJECT_RESULT` — report `sqe->len` as the result.
pub const IORING_NOP_INJECT_RESULT: u32 = 1 << 0;
/// Resolve `sqe->fd` and report EBADF if it names nothing.
pub const IORING_NOP_FILE: u32 = 1 << 1;
/// `sqe->fd` is a registered-file index rather than a descriptor.
pub const IORING_NOP_FIXED_FILE: u32 = 1 << 2;
/// `sqe->buf_index` must name a registered buffer, else EFAULT.
pub const IORING_NOP_FIXED_BUFFER: u32 = 1 << 3;
/// Complete through deferred work rather than inline.
pub const IORING_NOP_TW: u32 = 1 << 4;
/// Post a 32-byte completion carrying `sqe->off` and `sqe->addr`.
pub const IORING_NOP_CQE32: u32 = 1 << 5;

/// Every bit `sqe->nop_flags` may carry. Anything else is EINVAL — the entry
/// asked for behaviour that has no meaning, and answering "done" would tell it
/// the behaviour happened.
pub const NOP_FLAGS: u32 =
    IORING_NOP_INJECT_RESULT | IORING_NOP_FILE | IORING_NOP_FIXED_FILE
    | IORING_NOP_FIXED_BUFFER | IORING_NOP_TW | IORING_NOP_CQE32;

/// What one nop entry asks for, decoded once.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Nop {
    /// The result to report — the entry's own when it injected one, else zero.
    pub result: i32,
    /// Resolve a descriptor first, and fail the operation if it names nothing.
    pub check_file: bool,
    /// The descriptor is a registered-file index.
    pub fixed_file: bool,
    /// Check that `buf_index` names a registered buffer.
    pub check_buffer: bool,
    /// The completion carries a 32-byte payload.
    pub cqe32: bool,
    /// The two extra words that payload carries.
    pub extra: [u64; 2],
}

/// Decode one nop entry against the ring it was submitted to.
///
/// `ring_posts_32` is whether the ring can carry a 32-byte completion at all
/// ([`super::cqe_slot::posts_32`]). Asking for one on a ring that cannot is
/// EINVAL at this point, before any side effect: the alternative is a
/// completion whose second half the caller reads as whatever the CQ slot after
/// it happened to hold. # C: O(1)
pub fn prep(nop_flags: u32, len: u32, fd: i32, off: u64, addr: u64, ring_posts_32: bool)
    -> Result<Nop, Errno>
{
    if nop_flags & !NOP_FLAGS != 0 { return Err(Errno::Einval); }
    let cqe32 = nop_flags & IORING_NOP_CQE32 != 0;
    if cqe32 && !ring_posts_32 { return Err(Errno::Einval); }
    let _ = fd;
    Ok(Nop {
        result: if nop_flags & IORING_NOP_INJECT_RESULT != 0 { len as i32 } else { 0 },
        check_file: nop_flags & IORING_NOP_FILE != 0,
        fixed_file: nop_flags & IORING_NOP_FIXED_FILE != 0,
        check_buffer: nop_flags & IORING_NOP_FIXED_BUFFER != 0,
        cqe32,
        extra: if cqe32 { [off, addr] } else { [0; 2] },
    })
}

#[cfg(test)]
#[path = "nop/tests.rs"]
mod tests;
