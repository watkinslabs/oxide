// Where a submission pass starts reading the SQ ring, how far it may go, and
// whether it tells userspace where it stopped.
//
// Two disciplines:
//
// Ordinary ring — head and tail are free-running counters shared with
//   userspace. A pass starts at the head, takes at most `tail - head` entries,
//   and publishes the head it reached so userspace knows which slots it may
//   refill. The publication is the release half of the pair: once the head
//   moves, the entries behind it may be overwritten, so it happens only after
//   every one of them has been read.
//
// `IORING_SETUP_SQ_REWIND` — the ring is not a queue but an array userspace
//   rewrites in place. Every pass starts at slot zero and may take up to the
//   whole array; the caller's `to_submit` is the only thing that says how much
//   of it is live this time. The head is NOT published: userspace is not
//   waiting to be told which slots are free, because it owns all of them
//   between calls, and moving the head would make the next pass start
//   somewhere other than zero.
//
// The flag needs `IORING_SETUP_NO_SQARRAY` (the slot IS the entry index, so
// "start at zero" is unambiguous) and refuses `IORING_SETUP_SQPOLL` (a poll
// thread drains continuously and has no pass boundary to rewind to). Both
// pairings are decided at setup.

use super::uapi::IORING_SETUP_SQ_REWIND;

/// Whether this ring rewinds to slot zero on every pass. # C: O(1)
pub fn rewinds(ring_flags: u32) -> bool { ring_flags & IORING_SETUP_SQ_REWIND != 0 }

/// Whether the consumed head is published back to the shared word. # C: O(1)
pub fn publishes_head(ring_flags: u32) -> bool { !rewinds(ring_flags) }

/// The SQ index one pass starts reading at. # C: O(1)
pub fn batch_start(ring_flags: u32, sq_head: u32) -> u32 {
    if rewinds(ring_flags) { 0 } else { sq_head }
}

/// Entries one pass may take.
///
/// A rewinding ring is bounded by the array, not by the tail: userspace never
/// moved the tail, because it rewrote the slots in place. Every other ring is
/// bounded by what userspace published — head and tail are free-running, so
/// the difference is wraparound-correct. # C: O(1)
pub fn batch_len(ring_flags: u32, to_submit: u32, sq_tail: u32, sq_head: u32, sq_entries: u32)
    -> u32
{
    let available = if rewinds(ring_flags) { sq_entries } else { sq_tail.wrapping_sub(sq_head) };
    core::cmp::min(to_submit, available)
}

#[cfg(test)]
#[path = "sq_cursor/tests.rs"]
mod tests;
