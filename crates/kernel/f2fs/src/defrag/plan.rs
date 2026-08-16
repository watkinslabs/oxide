//! Whether a range is worth rewriting, and what rewriting it would cost.
//!
//! Every decision here is a pure function of stated facts, so the refusal
//! ORDER and the fragmentation rule are exercised with no volume, no medium
//! and no file — which is the only way the ordering is testable at all.

use syscall::errno::Errno;

/// What the file is, as the decision reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Facts {
    /// The blocks compression saved have been handed back, so the file's
    /// stored form is no longer a form anything may rewrite.
    pub compress_released: bool,
    /// The file is between the start and the commit of an atomic span.
    pub atomic: bool,
    /// The file's addresses are promised not to move.
    pub pinned: bool,
    /// The mount would write this file's blocks back where they came from, so
    /// a rewrite could not move one anywhere.
    pub inplace_update: bool,
}

/// May a range of this file be rewritten?
///
/// The two-then-one shape is the contract: the state refusals come first and
/// share one errno, and only then is the question asked whether a rewrite
/// would move anything at all. A file the mount updates in place is refused
/// rather than silently rewritten in the same blocks, because reporting the
/// blocks as moved when they did not move is worse than saying no.
/// # C: O(1)
pub fn admit(f: &Facts) -> Result<(), Errno> {
    if f.compress_released || f.atomic { return Err(Errno::Einval); }
    // A pinned file is written where it sits, whatever the mount's policy:
    // something outside the filesystem is holding its addresses.
    if f.pinned || f.inplace_update { return Err(Errno::Einval); }
    Ok(())
}

/// The running answer to "is this range scattered, and how big is it".
///
/// Fed one MAPPED block at a time in file order. Holes are simply not fed:
/// a gap in the logical order says nothing about the physical order, and a
/// run broken at every hole would call every sparse file fragmented.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Survey {
    /// Blocks that exist in the range, which is what a rewrite would move.
    pub total: u64,
    /// Whether two of them are not physically adjacent.
    pub fragmented: bool,
    /// The address the next block would have to hold to continue the run.
    next: u32,
}

impl Survey {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Take one mapped block, at physical address `addr`. # C: O(1)
    pub fn note(&mut self, addr: u32) {
        if self.next != 0 && self.next != addr { self.fragmented = true; }
        self.total += 1;
        self.next = addr.wrapping_add(1);
    }

    /// Sections a rewrite of what has been surveyed would fill. # C: O(1)
    pub fn sections_needed(&self, blks_per_sec: u32) -> u32 {
        let per = u64::from(blks_per_sec.max(1));
        u32::try_from(self.total.div_ceil(per)).unwrap_or(u32::MAX)
    }
}

/// Does the inode's cached extent already say the whole range is one run?
///
/// The cache describes exactly one contiguous run. One that starts at or
/// before the range and reaches its end is proof the range is contiguous,
/// which is the cheap answer the survey exists to avoid computing.
/// # C: O(1)
pub fn extent_covers(extent: Option<(u32, u32, u32)>, first: u64, end: u64) -> bool {
    let Some((fofs, _, len)) = extent else { return false };
    if len == 0 { return false; }
    let from = u64::from(fofs);
    let to = from + u64::from(len);
    from <= first && to >= end
}

#[cfg(test)]
#[path = "../tests/defrag/plan.rs"]
mod tests;
