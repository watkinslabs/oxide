// Where one completion goes in the CQ array, and how many slots it costs.
//
// Three ring shapes, one placement rule:
//
//   plain       — every completion is 16 bytes and costs one slot.
//   `CQE32`     — every completion is 32 bytes; the ARRAY strides at 32, so a
//                 completion still costs one slot.
//   `CQE_MIXED` — the array strides at 16 and a 32-byte completion costs TWO
//                 adjacent slots, marked `IORING_CQE_F_32` so the reader knows
//                 which of the two shapes it is looking at.
//
// The mixed ring is the only one where placement can fail for a reason other
// than "the ring is full": a 32-byte completion cannot straddle the wrap,
// because the two halves would land at opposite ends of the array. When the
// last free slot before the wrap is the one the tail points at, a filler
// completion is posted into it — `IORING_CQE_F_SKIP`, which the reader is
// required to ignore — and the real completion starts at slot zero. Dropping
// the filler and simply skipping the slot instead would leave a slot the
// reader never consumes, and the head would never catch the tail again.

use super::uapi::{IORING_SETUP_CQE32, IORING_SETUP_CQE_MIXED};

/// `IORING_CQE_F_SKIP` — this completion carries nothing; the reader must step
/// over it. It is the filler a mixed ring posts to reach the wrap.
pub const IORING_CQE_F_SKIP: u32 = 1 << 5;

/// Slots one completion occupies. # C: O(1)
pub fn slots(ring_flags: u32, is32: bool) -> u32 {
    if is32 && ring_flags & IORING_SETUP_CQE_MIXED != 0 { 2 } else { 1 }
}

/// Whether a ring posts 32-byte completions at all. A ring that is neither
/// `CQE32` nor `CQE_MIXED` has nowhere to put the second half, which is why
/// asking for one on such a ring is `EINVAL` at prep time rather than a
/// silently truncated record. # C: O(1)
pub fn posts_32(ring_flags: u32) -> bool {
    ring_flags & (IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED) != 0
}

/// Whether a completion carrying a 32-byte payload must announce itself with
/// `IORING_CQE_F_32`. Only a mixed ring's reader has to be told: on a `CQE32`
/// ring every completion is 32 bytes and on a plain ring none is. # C: O(1)
pub fn marks_32(ring_flags: u32) -> bool { ring_flags & IORING_SETUP_CQE_MIXED != 0 }

/// Where one completion lands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Placement {
    /// A filler completion must be written at this ring index first.
    pub filler_at: Option<u32>,
    /// Ring index of the completion itself.
    pub at: u32,
    /// Total slots the tail advances by, filler included.
    pub advance: u32,
}

/// Completions posted and not yet reaped. # C: O(1)
fn queued(tail: u32, head: u32) -> u32 { tail.wrapping_sub(head) }

/// Place one completion, or `None` when the ring cannot hold it and it must go
/// to the overflow backlog instead.
///
/// `cq_entries` is a power of two, so the index is the free-running tail
/// masked. # C: O(1)
pub fn place(ring_flags: u32, tail: u32, head: u32, cq_entries: u32, is32: bool)
    -> Option<Placement>
{
    let want = slots(ring_flags, is32);
    let mut tail = tail;
    let mut filler_at = None;
    let mut advance = 0u32;

    if want == 2 {
        let off = tail & (cq_entries - 1);
        if off + 1 == cq_entries {
            // Room for the filler itself, before anything else is decided.
            if queued(tail, head) >= cq_entries { return None; }
            filler_at = Some(off);
            tail = tail.wrapping_add(1);
            advance += 1;
        }
    }

    let off = tail & (cq_entries - 1);
    let free = cq_entries.saturating_sub(queued(tail, head));
    // The slots must be contiguous, so the run is bounded by the wrap too.
    let run = core::cmp::min(free, cq_entries - off);
    if run < want { return None; }
    Some(Placement { filler_at, at: off, advance: advance + want })
}

#[cfg(test)]
#[path = "cqe_slot/tests.rs"]
mod tests;
