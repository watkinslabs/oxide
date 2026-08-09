// `IORING_REGISTER_RESIZE_RINGS` — what moves from the old rings to the new
// ones, and when the move is refused.
//
// The ordering the opcode must keep: admit the request and size the new
// geometry, ALLOCATE the new regions, seed their constant words, report the
// new geometry to the caller, and only then swap. Nothing is dropped from the
// live ring until both regions exist and the caller has been told about them,
// so every failure before the swap leaves the ring exactly as it was.
//
// The one failure that can be discovered late is `EOVERFLOW`: a new ring too
// small to hold what the old one is already carrying. It is decided from the
// head/tail pairs BEFORE anything is copied, so the rollback is "drop the new
// regions", never "undo a half-finished copy".

use syscall::errno::Errno;

/// Entries between `head` and `tail`. Both are free-running counters masked
/// only at access, so the difference is wraparound-correct. # C: O(1)
pub fn pending(head: u32, tail: u32) -> u32 { tail.wrapping_sub(head) }

/// Refuse a resize whose new ring cannot hold what the old one carries.
/// # C: O(1)
pub fn admit_pending(head: u32, tail: u32, new_entries: u32) -> Result<u32, Errno> {
    let n = pending(head, tail);
    if n > new_entries { return Err(Errno::Eoverflow); }
    Ok(n)
}

/// What SQ entry `i` becomes in the new ring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SqMove {
    /// Copy the SQE at `src` to `dst`. `array` is what the new SQ index array
    /// records for `dst`, or `None` for a ring without an index array.
    Copy { dst: u32, src: u32, array: Option<u32> },
    /// The old index array named no SQE. Nothing is copied; the new array
    /// records the same "no entry" marker so the slot cannot alias a live SQE.
    NoEntry { dst: u32 },
}

/// Where SQ entry `i` moves. `old_array` is the old SQ index array's value for
/// this entry, or `None` when the ring's head/tail index the SQE array
/// directly (`IORING_SETUP_NO_SQARRAY`). Both rings are power-of-two sized, so
/// a slot is the free-running counter masked. # C: O(1)
pub fn sq_move(i: u32, new_entries: u32, old_entries: u32, old_array: Option<u32>) -> SqMove {
    let dst = i & (new_entries - 1);
    match old_array {
        None => SqMove::Copy { dst, src: i & (old_entries - 1), array: None },
        Some(idx) => {
            if idx >= old_entries { return SqMove::NoEntry { dst }; }
            SqMove::Copy { dst, src: idx, array: Some(dst) }
        }
    }
}

/// Where CQ entry `i` moves. # C: O(1)
pub fn cq_move(i: u32, new_entries: u32, old_entries: u32) -> (u32, u32) {
    (i & (new_entries - 1), i & (old_entries - 1))
}

#[cfg(test)]
#[path = "resize/tests.rs"]
mod tests;
