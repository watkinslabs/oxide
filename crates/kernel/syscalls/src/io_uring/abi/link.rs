// Link chains, drain barriers and silent success — the ordering rules the
// submission engine applies between one entry and the next.
//
// A chain is a run of entries each of which carries a link flag, terminated by
// the first entry that does not. The rule the whole mechanism exists for: if a
// member of a chain fails, the rest of the chain does NOT run, and each
// remaining member completes with ECANCELED. A hard link is the exception —
// it keeps the chain alive whatever it returns.
//
// Kept out of the (kernel-gated) engine so the state machine is unit-tested
// (CLAUDE.md phantom-test rule).

use super::ops::{IOSQE_CQE_SKIP_SUCCESS, IOSQE_IO_DRAIN, IOSQE_IO_HARDLINK, SQE_LINK_FLAGS};

/// What the engine should do with the entry it just read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Execute it.
    Run,
    /// Do not execute it: a link ahead of it failed. It completes with
    /// ECANCELED.
    Cancel,
}

/// The chain state carried from one entry to the next.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Chain {
    /// The previous entry carried a link flag, so this one belongs to a chain.
    pub linked: bool,
    /// A member of the current chain has already failed.
    pub broken: bool,
}

impl Chain {
    /// What to do with an entry carrying `flags`. # C: O(1)
    pub fn action(&self, _flags: u8) -> Action {
        if self.linked && self.broken { Action::Cancel } else { Action::Run }
    }

    /// Fold this entry's flags and result into the chain state. # C: O(1)
    pub fn advance(&mut self, flags: u8, res: i64) {
        let links_on = flags & SQE_LINK_FLAGS != 0;
        let hard = flags & IOSQE_IO_HARDLINK != 0;
        if (self.linked || links_on) && res < 0 && !hard { self.broken = true; }
        if links_on {
            self.linked = true;
        } else {
            // The chain ended with this entry, whatever happened inside it.
            self.linked = false;
            self.broken = false;
        }
    }
}

/// Whether a completion is posted at all. An entry that asked for its success
/// to be silent still counts as submitted; it just says nothing when it works.
/// # C: O(1)
pub fn posts_cqe(flags: u8, res: i64) -> bool {
    !(res >= 0 && flags & IOSQE_CQE_SKIP_SUCCESS != 0)
}

/// Whether an entry disables later drain barriers. Counting completions cannot
/// order anything once some completions are deliberately never posted.
/// # C: O(1)
pub fn disables_drain(flags: u8) -> bool { flags & IOSQE_CQE_SKIP_SUCCESS != 0 }

/// Whether the entry asks for a drain barrier. # C: O(1)
pub fn wants_drain(flags: u8) -> bool { flags & IOSQE_IO_DRAIN != 0 }

#[cfg(test)]
#[path = "link/tests.rs"]
mod tests;
