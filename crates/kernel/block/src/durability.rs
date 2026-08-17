// What a submitter promises about WHEN a write is on the medium, and the
// sequence of device commands that keeps the promise.
//
// Deliberately NOT part of `flags::RequestFlags`. That word is hints: every
// bit in it may be dropped by a device without changing which bytes land, so a
// queue is free to ignore the lot. These two bits are the opposite — dropping
// one means a write the caller was told was durable is still in the drive's
// volatile cache, and a power cut loses it. Two words, because a submitter
// that reorders for speed and a submitter that needs an ordering guarantee are
// asking for different things and must not be able to be confused.
//
// The pair mirrors Linux's `REQ_PREFLUSH` / `REQ_FUA`, and `sequence` mirrors
// the decision that turns them into commands: which of pre-flush, the write,
// and a post-flush standing in for an absent forced-unit-access has to be
// issued for one request, given what the device actually advertises.
//
// Ungated on purpose: the decision is the contract, and it is hosted-tested
// here rather than in a driver.

use core::ops::BitOr;

pub mod submit;

/// What a submitter promises about when this request is durable.
///
/// Constructed from the named constants and combined with `|`. An empty word
/// is an ordinary write, which is what every submitter that has no ordering
/// requirement produces.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Durability(u32);

/// Everything written to this device BEFORE this request must be on the medium
/// before this request's own data is written.
///
/// The barrier a commit record needs: the record names blocks, and a record
/// that became durable first would name blocks a power loss never finished
/// writing. Linux `REQ_PREFLUSH`.
pub const PREFLUSH: Durability = Durability(1 << 0);

/// THIS request's data must be on the medium when it completes, not merely in
/// the device's cache.
///
/// Linux `REQ_FUA`. A device that cannot do it natively is served by a flush
/// AFTER the write instead, which is slower and promises the same thing; what
/// is never done is to report completion with the data still volatile.
pub const FUA: Durability = Durability(1 << 1);

impl Durability {
    /// No promise — an ordinary write. # C: O(1)
    pub const NONE: Durability = Durability(0);

    /// Whether every bit in `other` is set here. # C: O(1)
    pub const fn contains(self, other: Durability) -> bool { self.0 & other.0 == other.0 }

    /// Whether this request promises nothing about durability. # C: O(1)
    pub const fn is_empty(self) -> bool { self.0 == 0 }
}

impl BitOr for Durability {
    type Output = Durability;
    /// # C: O(1)
    fn bitor(self, rhs: Durability) -> Durability { Durability(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for Durability {
    /// # C: O(1)
    fn bitor_assign(&mut self, rhs: Durability) { self.0 |= rhs.0; }
}

/// The commands one request decomposes into.
///
/// All four fields are independent answers, not a ladder: a request may need a
/// pre-flush and carry no data (that is what an explicit cache flush is), or
/// carry data and need a post-flush, or need nothing at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Sequence {
    /// Flush the device's cache BEFORE the write.
    pub preflush: bool,
    /// Write this request's payload.
    pub data: bool,
    /// Flush the device's cache AFTER the write, standing in for a
    /// forced-unit-access the device cannot do itself.
    pub postflush: bool,
    /// Leave forced-unit-access on the request for the driver to honour.
    pub fua: bool,
}

impl Sequence {
    /// Whether this request needs no command at all.
    ///
    /// A cache flush aimed at a device with no volatile cache decomposes to
    /// nothing, and nothing is the correct, complete answer: there is no cache
    /// whose contents could be lost. Reporting an error instead would make
    /// every caller carry a capability test the layer below already has.
    /// # C: O(1)
    pub const fn is_noop(self) -> bool { !self.preflush && !self.data && !self.postflush }
}

/// Which commands one request needs, given what the device advertises.
///
/// `write_cache` is the device's volatile write cache as it stands — the
/// hardware feature AND the cache not having been turned off. `fua_capable` is
/// forced-unit-access in hardware. Both are read from the device rather than
/// assumed, because a promise honoured by construction on one device and
/// silently dropped on another is the failure this whole word exists to
/// prevent.
///
/// A device with no volatile cache needs no flush of either kind: everything
/// written to it is already on the medium, so the ordering the submitter asked
/// for holds without a command. The forced-unit-access bit still leaves for
/// the driver when the hardware has it, because the driver's own path may
/// depend on it.
/// # C: O(1)
pub fn sequence(write_cache: bool, fua_capable: bool, want: Durability, has_data: bool)
    -> Sequence {
    let mut s = Sequence { data: has_data, ..Sequence::default() };
    if write_cache {
        s.preflush = want.contains(PREFLUSH);
        // A post-flush is the substitute, not an addition: a device that can
        // write through its own cache needs no second command, and issuing one
        // anyway would double the cost of every commit record.
        s.postflush = want.contains(FUA) && !fua_capable;
    }
    s.fua = want.contains(FUA) && fua_capable;
    s
}

/// What is left of the promise for the DRIVER to see.
///
/// The pre-flush is gone because this layer issues it; forced-unit-access
/// survives only where the device can honour it. Handing a driver a bit it
/// does not implement would let it report a completion for data still in its
/// cache — the exact lie the caller asked to be protected from.
/// # C: O(1)
pub fn residue(seq: Sequence) -> Durability {
    if seq.fua { FUA } else { Durability::NONE }
}

#[cfg(test)]
#[path = "durability/tests.rs"]
mod tests;
