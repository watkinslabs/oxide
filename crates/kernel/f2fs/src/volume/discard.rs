//! Telling the device which blocks the volume no longer needs.
//!
//! Two rules make this safe, and both are easy to get wrong in a way nothing
//! notices until data is gone:
//!
//! - **Never before the checkpoint that frees the block.** A released block is
//!   still referenced by the checkpoint currently on the medium; that is the
//!   whole point of out-of-place update. Discarding it at release time
//!   destroys the state a crash would otherwise recover to. The ranges are
//!   held until a checkpoint retires them and only then handed over.
//! - **Never a block that came back.** A block freed and reallocated before
//!   the checkpoint must not be discarded, or the discard erases live data.
//!   The pending set is filtered against the segment table at the moment it is
//!   drained, not at the moment it is recorded.
//!
//! The granularity is a mount option because it is a property of the device,
//! not of the filesystem: flash erases in large units, and a discard smaller
//! than one is work the controller cannot use.

use alloc::vec::Vec;

use sectors::SectorSource;

use crate::opts::DiscardUnit;
use crate::uapi::BLKS_PER_SEG;

use super::Volume;

/// A run of blocks the device may forget, as a start and a length.
pub type Range = (u32, u32);

/// Blocks remembered between checkpoints before the set is abandoned.
/// Forgetting one loses an optimisation, never data.
pub const MAX_PENDING: usize = 1 << 16;

/// Merge sorted block addresses into runs. # C: O(N log N)
pub fn coalesce(mut blocks: Vec<u32>) -> Vec<Range> {
    blocks.sort_unstable();
    blocks.dedup();
    let mut out: Vec<Range> = Vec::new();
    for b in blocks {
        match out.last_mut() {
            Some((start, len)) if *start + *len == b => *len += 1,
            _ => out.push((b, 1)),
        }
    }
    out
}

/// Keep only the runs worth announcing at `unit`.
///
/// A run shorter than the unit, or one not aligned to it, is dropped rather
/// than rounded outward — rounding outward would announce blocks that are
/// still in use.
/// # C: O(runs)
pub fn at_granularity(runs: Vec<Range>, unit: DiscardUnit, main: u32, segs_per_sec: u32)
    -> Vec<Range> {
    let span = match unit {
        DiscardUnit::Block => return runs,
        DiscardUnit::Segment => BLKS_PER_SEG,
        DiscardUnit::Section => BLKS_PER_SEG.saturating_mul(segs_per_sec.max(1)),
    };
    runs.into_iter()
        .filter_map(|(start, len)| {
            // A run below the main area is not a run of file blocks at all;
            // measuring alignment against it would wrap.
            let skew = start.checked_sub(main)? % span;
            let aligned = if skew == 0 { start } else { start + (span - skew) };
            let drop = aligned - start;
            let left = len.checked_sub(drop)?;
            let whole = (left / span) * span;
            if whole == 0 { None } else { Some((aligned, whole)) }
        })
        .collect()
}

impl<S: SectorSource> Volume<S> {
    /// Note that `addr` is no longer referenced.
    ///
    /// Recording is all that happens here: the block is still part of the
    /// checkpoint on the medium until the next one replaces it.
    /// # C: O(1)
    pub(crate) fn note_discard(&mut self, addr: u32) {
        if !self.opts.discard { return; }
        if crate::node::is_hole(addr) { return; }
        // A mount that writes a great deal between checkpoints must not grow
        // this without bound. Forgetting a range costs nothing but space the
        // device still believes is used, so the oldest are dropped rather
        // than the memory.
        if self.pending_discard.len() >= MAX_PENDING { self.pending_discard.clear(); }
        self.pending_discard.push(addr);
    }

    /// The runs a just-written checkpoint has made safe to announce.
    ///
    /// Called after the checkpoint lands, never before. Any block that came
    /// back into use in the meantime is dropped here — the segment table at
    /// this instant is the only thing that knows.
    /// # C: O(pending log pending)
    pub(crate) fn take_discards(&mut self) -> Vec<Range> {
        if !self.opts.discard || self.pending_discard.is_empty() { return Vec::new(); }
        let pending = core::mem::take(&mut self.pending_discard);
        let live: Vec<u32> =
            pending.into_iter().filter(|&a| !self.block_is_live(a).unwrap_or(true)).collect();
        let runs = coalesce(live);
        at_granularity(runs, self.opts.discard_unit, self.sb.main_blkaddr, self.sb.segs_per_sec)
    }

    /// Whether this mount announces freed space at all. # C: O(1)
    pub fn discards(&self) -> bool { self.opts.discard }

    /// Runs the discard machinery is holding and has not announced.
    ///
    /// Read from the DISCARD CONTROL, which is the one owner of what is
    /// outstanding: `pending_discard` above is a different stage of the same
    /// pipeline — addresses released since the last checkpoint, which may not be
    /// announced at all until that checkpoint lands — and reporting it as
    /// outstanding would count blocks the device may not be told about.
    ///
    /// A mount with no discard thread announces every run as its checkpoint
    /// lands, so nothing is ever outstanding and zero is the true answer rather
    /// than a missing one.
    /// # C: O(MAX_PLIST_NUM)
    pub fn discard_runs_waiting(&self) -> u64 {
        self.bg.as_ref().map_or(0, |b| b.dcc.lock().cmd_count() as u64)
    }

    /// The same, in blocks. # C: O(runs waiting)
    pub fn discard_blocks_waiting(&self) -> u64 {
        self.bg.as_ref().map_or(0, |b| b.dcc.lock().undiscard_blks())
    }
}

#[cfg(test)]
#[path = "../tests/discard.rs"]
mod tests;
