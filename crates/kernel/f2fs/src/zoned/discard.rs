//! What "forget these blocks" means on a drive that has zones.
//!
//! On a conventional drive a freed run is announced and that is the whole of
//! it: the drive may or may not act, and either way the blocks can be written
//! again immediately. A SEQUENTIAL zone does not work that way. Its blocks
//! become writable again only when its write pointer goes back to the start,
//! and the only thing that moves the pointer back is a zone RESET. A run
//! announced as an ordinary discard leaves the pointer where it was, so the
//! space comes back in the accounting and not on the drive — and the next
//! allocation into that segment is refused by the drive, at write time, with
//! nothing to say why.
//!
//! The reset is a whole-zone operation, which is the second half of the rule.
//! A drive cannot send a pointer back part way, so a run that is not exactly
//! one zone starting at a zone boundary is REFUSED rather than rounded:
//! rounding outward would reset a neighbouring zone holding live blocks, and
//! rounding inward would issue a reset the drive rejects. Refusing loses an
//! optimisation; either rounding loses data.
//!
//! Everything here is a decision over stated facts, so the caller reads the
//! drive, applies what this returns, and is the only side that talks to a
//! device.

/// What one freed run turns into on the drive that holds it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// Announce it the ordinary way. A conventional zone, or a drive with no
    /// zones at all.
    Discard,
    /// Send the zone's write pointer back to its start; the run is exactly
    /// that zone.
    Reset,
    /// A run inside a sequential zone that is not the whole zone. Nothing is
    /// sent: an ordinary discard would not free it on the drive, and a reset
    /// would take blocks the run does not name.
    Unaligned,
}

/// The zone a run's first block falls in, on the member holding it.
///
/// `blocks_per_zone` is zero for a member that reported no zones, which is the
/// answer a conventional drive gives.
/// # C: O(1)
pub fn zone_of(local_start: u64, blocks_per_zone: u32) -> Option<usize> {
    if blocks_per_zone == 0 { return None; }
    usize::try_from(local_start / u64::from(blocks_per_zone)).ok()
}

/// What to do about a freed run of `len` blocks starting at `local_start`,
/// measured from the start of the member that holds it.
///
/// `seq` is whether that member's zone at `local_start` must be written
/// sequentially — read off the drive's own report, never assumed from the
/// zone size the format uses.
/// # C: O(1)
pub fn action(seq: bool, local_start: u64, len: u64, blocks_per_zone: u32) -> Action {
    if !seq || blocks_per_zone == 0 { return Action::Discard; }
    let per = u64::from(blocks_per_zone);
    if local_start % per != 0 || len != per { return Action::Unaligned; }
    Action::Reset
}

#[cfg(test)]
#[path = "../tests/zoned/discard.rs"]
mod tests;
