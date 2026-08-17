// `IORING_OP_FUTEX_WAIT`, `IORING_OP_FUTEX_WAKE`, `IORING_OP_FUTEX_WAITV` —
// the futex2 operations as submission entries.
//
// The entry carries the same operands the futex2 syscalls take, in fields
// chosen for their WIDTH rather than their name: the futex2 flag word lands in
// `fd` because the operation names no file, the compare value in `addr2` and
// the bitset in `addr3` because both are `unsigned long`. Reading any of them
// from the field its name suggests silently swaps two arguments that are both
// plausible integers, which is the one class of mistake no runtime error would
// reveal.
//
// The per-opcode flag word (`futex_flags`) is reserved on all three: it is the
// extension point, and accepting a value there would make a future meaning
// unusable. Every field the operation does not read is refused non-zero for
// the same reason.
//
// Ungated: the whole ladder is a decision, and the file that parks the caller
// is kernel-gated (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

use super::ops::{IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAITV, IORING_OP_FUTEX_WAKE};

/// `FUTEX_WAITV_MAX` — most futexes one vectored wait may name.
pub const FUTEX_WAITV_MAX: u32 = 128;

/// Whether the opcode is one of the three. # C: O(1)
pub fn is_futex(op: u8) -> bool {
    matches!(op, IORING_OP_FUTEX_WAIT | IORING_OP_FUTEX_WAKE | IORING_OP_FUTEX_WAITV)
}

/// A single-futex entry, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FutexOp {
    /// The futex word's user address.
    pub uaddr: u64,
    /// The value a wait compares against, and the count a wake is limited to.
    pub val: u64,
    /// The bitset both sides intersect on.
    pub mask: u64,
    /// The futex2 flag word.
    pub flags: u32,
}

/// A vectored wait, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FutexvOp {
    /// The `struct futex_waitv` array's user address.
    pub uaddr: u64,
    /// How many entries it holds.
    pub nr: u32,
}

/// Admit and decode a single-futex entry.
///
/// | rung | errno |
/// |---|---|
/// | `len`, the reserved flag word, `buf_index` or `file_index` non-zero | `EINVAL` |
/// | a futex2 flag bit that is not defined | `EINVAL` |
/// | a size class the futex contract does not implement | `EINVAL` |
/// | a compare value or bitset wider than the futex word | `EINVAL` |
/// | a wait with an empty bitset | `EINVAL` |
///
/// The width rung is the one that matters most: `val` and `mask` arrive as 64
/// bits and the futex word is 32, so a truncation would let a caller's
/// mismatched compare value alias a real word value and park forever. It is a
/// refusal, never a narrowing. The empty-bitset rung belongs to the wait
/// alone — a waiter no wake can ever intersect is a request for a completion
/// that cannot arrive. # C: O(1)
pub fn prep(sqe: &Sqe) -> Result<FutexOp, Errno> {
    use ::ipc::futex2_flags::{validate_futex2_flags, validate_futex2_input};
    if sqe.len != 0 || sqe.op_flags != 0 || sqe.buf_index != 0 || sqe.file_index() != 0 {
        return Err(Errno::Einval);
    }
    let flags = sqe.fd as u32;
    let f = validate_futex2_flags(flags).map_err(|_| Errno::Einval)?;
    let (val, mask) = (sqe.off, sqe.addr3);
    if !validate_futex2_input(f.size_bytes, val) || !validate_futex2_input(f.size_bytes, mask) {
        return Err(Errno::Einval);
    }
    // A wait with no bit set intersects no wake: the submission would stay
    // outstanding for the life of the ring.
    if sqe.opcode == IORING_OP_FUTEX_WAIT && mask == 0 { return Err(Errno::Einval); }
    Ok(FutexOp { uaddr: sqe.addr, val, mask, flags })
}

/// Admit and decode a vectored wait.
///
/// | rung | errno |
/// |---|---|
/// | `fd`, `addr2`, `addr3`, the reserved flag word, `buf_index` or `file_index` non-zero | `EINVAL` |
/// | an empty vector, or one longer than `FUTEX_WAITV_MAX` | `EINVAL` |
///
/// Neither a flag word nor a mask is supported here: each element of the
/// vector carries its own, so a second copy on the entry would be a value with
/// two answers. # C: O(1)
pub fn prep_waitv(sqe: &Sqe) -> Result<FutexvOp, Errno> {
    if sqe.fd != 0 || sqe.off != 0 || sqe.addr3 != 0 || sqe.op_flags != 0
        || sqe.buf_index != 0 || sqe.file_index() != 0 {
        return Err(Errno::Einval);
    }
    if sqe.len == 0 || sqe.len > FUTEX_WAITV_MAX { return Err(Errno::Einval); }
    Ok(FutexvOp { uaddr: sqe.addr, nr: sqe.len })
}

#[cfg(test)]
#[path = "futex_op/tests.rs"]
mod tests;
