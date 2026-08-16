//! The two arrays in memory, and the bytes they become.
//!
//! Kept apart from the superblock's bytes on purpose. A mount raises errors
//! from paths that cannot write — a read on a read-only mount, a fault found
//! while the medium is refusing — so the record accumulates in memory and is
//! pushed through in one place. The dirty flags are what make that push
//! cheap enough to attempt often: a commit that would rewrite both superblock
//! copies for nothing is a commit nobody will call.

use super::uapi::{Error, StopReason, MAX_F2FS_ERRORS, MAX_STOP_REASON};

/// What this mount has seen, in the two shapes the superblock stores.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ErrorRecord {
    /// One bit per kind, least significant bit of the first byte first.
    errors: [u8; MAX_F2FS_ERRORS],
    /// One saturating count per reason.
    stop_reason: [u8; MAX_STOP_REASON],
    error_dirty: bool,
    stop_dirty: bool,
}

impl ErrorRecord {
    /// A record holding nothing, for a volume with no stored arrays.
    /// # C: O(1)
    pub fn empty() -> Self {
        Self { errors: [0; MAX_F2FS_ERRORS], stop_reason: [0; MAX_STOP_REASON],
               error_dirty: false, stop_dirty: false }
    }

    /// The record a mount starts from: what the medium already holds.
    ///
    /// Seeded rather than cleared, because the arrays are cumulative. A mount
    /// that started from zero would erase every kind an earlier mount recorded
    /// the first time it wrote one of its own.
    /// # C: O(1)
    pub fn at_mount(errors: [u8; MAX_F2FS_ERRORS], stop_reason: [u8; MAX_STOP_REASON])
        -> Self {
        Self { errors, stop_reason, error_dirty: false, stop_dirty: false }
    }

    /// Read both arrays out of a superblock copy's bytes. # C: O(1)
    pub fn from_super(b: &[u8]) -> Self {
        let mut errors = [0u8; MAX_F2FS_ERRORS];
        let mut stop_reason = [0u8; MAX_STOP_REASON];
        if let Some(s) = b.get(crate::uapi::SB_S_ERRORS..crate::uapi::SB_S_ERRORS + MAX_F2FS_ERRORS) {
            errors.copy_from_slice(s);
        }
        if let Some(s) =
            b.get(crate::uapi::SB_S_STOP_REASON..crate::uapi::SB_S_STOP_REASON + MAX_STOP_REASON) {
            stop_reason.copy_from_slice(s);
        }
        Self::at_mount(errors, stop_reason)
    }

    /// Note that `e` has been seen, reporting whether it is news.
    ///
    /// A kind already recorded dirties nothing: the array is a SET, so the
    /// second occurrence of an error changes no byte, and treating it as a
    /// change would make a volume with one recurring fault rewrite both
    /// superblock copies on every occurrence.
    /// # C: O(1)
    pub fn save_error(&mut self, e: Error) -> bool {
        let (byte, bit) = (e.bit() / 8, e.bit() % 8);
        if byte >= MAX_F2FS_ERRORS { return false; }
        if self.errors[byte] & (1 << bit) != 0 { return false; }
        self.errors[byte] |= 1 << bit;
        self.error_dirty = true;
        true
    }

    /// Whether `e` has been recorded. # C: O(1)
    pub fn has_error(&self, e: Error) -> bool {
        let (byte, bit) = (e.bit() / 8, e.bit() % 8);
        byte < MAX_F2FS_ERRORS && self.errors[byte] & (1 << bit) != 0
    }

    /// Count one stop for `r`.
    ///
    /// The count SATURATES rather than wrapping. A byte that wrapped would
    /// take a volume that has failed 256 times and report it as one that has
    /// never failed — the one reading the array most needs to be right about.
    /// # C: O(1)
    pub fn save_stop_reason(&mut self, r: StopReason) {
        let slot = r.slot();
        if slot < MAX_STOP_REASON && self.stop_reason[slot] < u8::MAX {
            self.stop_reason[slot] += 1;
        }
        self.stop_dirty = true;
    }

    /// How many times `r` has been counted. # C: O(1)
    pub fn stops(&self, r: StopReason) -> u8 {
        self.stop_reason.get(r.slot()).copied().unwrap_or(0)
    }

    /// Whether anything is waiting to be written. # C: O(1)
    pub fn dirty(&self) -> bool { self.error_dirty || self.stop_dirty }

    /// # C: O(1)
    pub fn error_dirty(&self) -> bool { self.error_dirty }
    /// # C: O(1)
    pub fn stop_dirty(&self) -> bool { self.stop_dirty }

    /// Patch both arrays into a superblock copy's bytes and report whether a
    /// stop reason was among them.
    ///
    /// The error bitmap is written only when it CHANGED, and the stop-reason
    /// array always. That is not an inconsistency: the bitmap is a set this
    /// mount may only add to, so an unchanged one is already on the medium,
    /// while the counts are what a caller asked to have recorded and a caller
    /// that asked twice must see two.
    /// # C: O(1)
    pub fn into_super(&mut self, b: &mut [u8]) -> bool {
        let at = crate::uapi::SB_S_ERRORS;
        if self.error_dirty {
            if let Some(s) = b.get_mut(at..at + MAX_F2FS_ERRORS) {
                s.copy_from_slice(&self.errors);
                self.error_dirty = false;
            }
        }
        let at = crate::uapi::SB_S_STOP_REASON;
        let reported = self.stop_dirty;
        if let Some(s) = b.get_mut(at..at + MAX_STOP_REASON) {
            s.copy_from_slice(&self.stop_reason);
            self.stop_dirty = false;
        }
        reported
    }
}

#[cfg(test)]
#[path = "../tests/errrec/record.rs"]
mod tests;
