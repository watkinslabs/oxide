//! What a freeze and a thaw of one volume decide.
//!
//! A freeze arrives with the writers already stopped and the filesystem
//! already synced, so this filesystem's part is narrow: satisfy itself that
//! the medium is genuinely clean, and RAISE the freezing mark. It does not
//! write a checkpoint of its own — one was written by the sync the freeze
//! already ran, and a second one here would be a write taken while the volume
//! is supposed to be quiescent.
//!
//! The order of the refusals is the contract and is not interchangeable:
//!
//! - A READ-ONLY mount is frozen by doing nothing. It has no writes to stop
//!   and no mark to raise, and refusing it would make a snapshot of a
//!   read-only mount impossible.
//! - A volume whose checkpoint records an I/O error cannot be sealed. The
//!   snapshot would name a state the medium never held.
//! - A volume still DIRTY after the sync has work the freeze was told to
//!   flush and did not, which is a defect in the caller rather than in the
//!   volume — so it is refused as an invalid request, not as an I/O failure.
//!
//! The mark itself is not decoration. It says a freeze is part way through,
//! which is what tells the paths that would ordinarily take freeze protection
//! for an internal write not to take it — a volume being frozen cannot wait
//! for a freeze that is waiting for it.

use syscall::errno::Errno;

/// What the mount is, at the moment a freeze is asked for.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Facts {
    /// Whether this mount may write at all.
    pub readonly: bool,
    /// Whether the checkpoint on the medium records an I/O error.
    pub cp_error: bool,
    /// Whether anything this mount changed is still only in memory.
    pub dirty: bool,
}

/// What a freeze comes to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Nothing to freeze and nothing to mark.
    Nothing,
    /// Raise the freezing mark.
    Mark,
}

/// Whether this volume can be frozen, and what that costs. # C: O(1)
pub fn decide(f: Facts) -> Result<Outcome, Errno> {
    if f.readonly { return Ok(Outcome::Nothing); }
    if f.cp_error { return Err(Errno::Eio); }
    if f.dirty { return Err(Errno::Einval); }
    Ok(Outcome::Mark)
}

/// Whether a thaw must issue whatever discards are still parked.
///
/// A snapshot taken over a volume can leave the device advertising no discard
/// capacity at all for as long as it exists, so runs parked while the volume
/// was frozen may never be issued by the device's own accounting. Where the
/// DEVICE does the discarding this does not arise and the parked runs are the
/// device's business; where the mount asked for discard and the device does
/// not support it, the parked runs are this filesystem's, and a thaw is the
/// point they are handed over.
/// # C: O(1)
pub fn thaw_issues_discards(discard: bool, hw_support_discard: bool) -> bool {
    discard && !hw_support_discard
}

#[cfg(test)]
#[path = "../tests/freeze.rs"]
mod tests;
