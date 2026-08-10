// Where one submission entry lives in the SQE array, and how many slots it
// costs.
//
// Three ring shapes, mirroring the completion side:
//
//   plain       — every entry is 64 bytes; the array strides at 64 and an
//                 entry costs one slot.
//   `SQE128`    — every entry is 128 bytes; the ARRAY strides at 128, so an
//                 entry still costs one slot. A 64-byte operation on such a
//                 ring simply leaves the second half unread.
//   `SQE_MIXED` — the array strides at 64 and a 128-byte operation costs TWO
//                 adjacent slots.
//
// Which operations are 128 bytes is a property of the opcode, not of the
// entry: an operation whose command does not fit in 64 bytes is 128 bytes on
// every ring, and a ring that cannot carry one refuses it with EINVAL rather
// than reading 64 bytes of a command that is longer than that.
//
// On a mixed ring the two slots must be ADJACENT and must not straddle the
// wrap, for the same reason a 32-byte completion may not: the two halves would
// land at opposite ends of the array. Unlike the completion side there is no
// filler to reach the wrap with — the entries are userspace's to place, and
// the kernel's only move is to refuse the one that was placed badly.

use syscall::errno::Errno;

use super::uapi::{IORING_SETUP_SQE128, IORING_SETUP_SQE_MIXED, SQE128_SIZE, SQE_SIZE};

/// Byte offset of SQE `idx` in an array whose stride is `sqe_size`.
/// `idx` is already masked into the array. # C: O(1)
pub fn sqe_offset(sqe_size: u32, idx: u32) -> u64 { idx as u64 * sqe_size as u64 }

/// Whether an opcode's command needs 128 bytes.
///
/// It is stated as an opcode property here, and not looked up in the dispatch
/// table, so the ring geometry and the submission engine cannot disagree about
/// which entries are wide. # C: O(1)
pub fn op_is_128(op: u8) -> bool {
    use super::ops::{IORING_OP_NOP128, IORING_OP_URING_CMD128};
    op == IORING_OP_NOP128 || op == IORING_OP_URING_CMD128
}

/// Whether a ring can carry a 128-byte entry at all. # C: O(1)
pub fn carries_128(ring_flags: u32) -> bool {
    ring_flags & (IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED) != 0
}

/// Bytes one array slot occupies. # C: O(1)
pub fn slot_size(ring_flags: u32) -> u32 {
    if ring_flags & IORING_SETUP_SQE128 != 0 { SQE128_SIZE as u32 } else { SQE_SIZE as u32 }
}

/// Extra slots a wide entry consumes beyond the one already taken.
///
/// `idx` is the entry's index in the SQE array, `sq_entries` the array's
/// depth, and `left` how many entries the caller still has to place in this
/// batch. Errors:
///
/// * EINVAL — the opcode is 128 bytes and the ring carries only 64-byte
///   entries, so the second half of the command is not in the ring at all.
/// * EINVAL — a mixed ring, but the batch has only one entry left, or the
///   entry sits in the array's last slot so its second half would wrap.
/// # C: O(1)
pub fn extra_slots(ring_flags: u32, op: u8, idx: u32, sq_entries: u32, left: u32)
    -> Result<u32, Errno>
{
    if !op_is_128(op) { return Ok(0); }
    // A dedicated wide ring already strides at 128: the whole command is in
    // the one slot.
    if ring_flags & IORING_SETUP_SQE128 != 0 { return Ok(0); }
    if ring_flags & IORING_SETUP_SQE_MIXED == 0 { return Err(Errno::Einval); }
    if left < 2 { return Err(Errno::Einval); }
    if idx + 1 >= sq_entries { return Err(Errno::Einval); }
    Ok(1)
}

#[cfg(test)]
#[path = "sqe_slot/tests.rs"]
mod tests;
