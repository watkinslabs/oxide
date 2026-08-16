//! What happens to an I/O that arrives while a device is not accepting them.
//!
//! Kept apart from the device that performs the deferral so the rule can be
//! tested on its own: whether an arriving I/O is mapped, parked, or failed is
//! a decision, and the queue it is parked on is a mechanism.

use crate::suspend::DmFlags;

/// What to do with an I/O that has just arrived.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Map it now.
    Map,
    /// Park it; it is submitted again when the device resumes.
    Defer,
    /// Fail it immediately.
    Fail,
}

/// Decide what happens to an arriving I/O.
///
/// A device with no live table has nothing to map onto, so its I/O fails
/// rather than parking forever — a device is created before its table is
/// loaded, and a caller that opens it in that window must get an answer.
/// # C: O(1)
pub fn admit(flags: DmFlags, has_map: bool) -> Admission {
    if flags.contains(DmFlags::FREEING) { return Admission::Fail; }
    if flags.intersects(DmFlags::BLOCK_IO_FOR_SUSPEND | DmFlags::SUSPENDED) {
        return Admission::Defer;
    }
    if !has_map { return Admission::Fail; }
    Admission::Map
}

/// What becomes of the parked I/O when the suspend ends.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Drain {
    /// Submit it again against the now-live table.
    Resubmit,
    /// Fail it. A no-flush suspend promised not to write it, and the table it
    /// was aimed at may no longer exist.
    Fail,
}

/// Decide the fate of the deferred queue as the block is lifted. # C: O(1)
pub fn drain(flags: DmFlags) -> Drain {
    if flags.contains(DmFlags::NOFLUSH_SUSPENDING) { Drain::Fail } else { Drain::Resubmit }
}
