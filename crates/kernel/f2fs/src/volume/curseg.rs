//! The six open logs a write appends to, and which one a write goes to.
//!
//! Nothing is overwritten in place. Every write takes the next block of one of
//! six OPEN SEGMENTS, chosen by what is being written: directory data and
//! directory nodes go to the hot logs, file data and file nodes to the warm
//! ones, and the indirection nodes — which change least — to the cold ones.
//! Putting everything in one log is legal but destroys the separation the
//! cleaner depends on, so the choice is made the way the reference makes it.
//!
//! A log runs out. When its segment fills, the log's summary block is written
//! to the summary area — that block is the only record of who owns each block
//! of the segment, and losing it makes the segment uncleanable — and a fresh
//! segment is opened, either an empty one (append) or a partly-used one whose
//! free blocks are reused (recycle).

use alloc::vec;
use alloc::vec::Vec;

use crate::opts::AllocMode;
use crate::uapi::*;

/// One open log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Curseg {
    /// The segment this log is writing into, or `NULL_SEGNO` when it has none.
    pub segno: u32,
    /// The next block of that segment to write.
    pub next_blkoff: u16,
    /// Whether the log appends or recycles.
    pub alloc_type: u8,
    /// The summary block for the open segment: one entry per block, naming
    /// the node that owns it.
    pub sum: Vec<u8>,
}

impl Curseg {
    /// A log with nothing open. # C: O(BLKSIZE)
    pub fn empty() -> Self {
        Self { segno: NULL_SEGNO, next_blkoff: 0, alloc_type: ALLOC_LFS, sum: vec![0u8; BLKSIZE] }
    }

    /// Whether the log has an open segment with room. # C: O(1)
    pub fn has_room(&self) -> bool {
        self.segno != NULL_SEGNO && u32::from(self.next_blkoff) < BLKS_PER_SEG
    }

    /// The block address this log would hand out next. # C: O(1)
    pub fn next_addr(&self, main_blkaddr: u32) -> u32 {
        main_blkaddr + self.segno * BLKS_PER_SEG + u32::from(self.next_blkoff)
    }

    /// Record who owns the block at `slot`. # C: O(1)
    pub fn set_summary(&mut self, slot: usize, s: Summary) {
        let at = summary_off(slot);
        self.sum[at..at + 4].copy_from_slice(&s.nid.to_le_bytes());
        self.sum[at + 4] = s.version;
        self.sum[at + 5..at + 7].copy_from_slice(&s.ofs_in_node.to_le_bytes());
    }

    /// Read back who owns the block at `slot`. # C: O(1)
    pub fn summary(&self, slot: usize) -> Summary {
        let at = summary_off(slot);
        Summary {
            nid: le32(&self.sum, at).unwrap_or(0),
            version: self.sum[at + 4],
            ofs_in_node: le16(&self.sum, at + 5).unwrap_or(0),
        }
    }

    /// Stamp the footer that says whether this block holds node or data
    /// summaries. Without it a checker cannot tell the two apart.
    /// # C: O(1)
    pub fn seal(&mut self, node: bool) {
        let at = BLKSIZE - SUM_FOOTER_SIZE;
        self.sum[at] = if node { SUM_TYPE_NODE } else { SUM_TYPE_DATA };
        let crc = crate::checksum::crc32(&self.sum[..at]);
        self.sum[at + 1..at + 5].copy_from_slice(&crc.to_le_bytes());
    }
}

/// A summary entry: which node owns a block, and where in that node.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Summary {
    pub nid: u32,
    pub version: u8,
    pub ofs_in_node: u16,
}

/// The type byte a summary block's footer carries.
pub const SUM_TYPE_NODE: u8 = 1;
pub const SUM_TYPE_DATA: u8 = 0;

/// What is being written, which is what picks the log.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A block of a directory's entries.
    DirData,
    /// A block of a regular file.
    FileData,
    /// An inode or direct node of a directory.
    DirNode,
    /// An inode or direct node of anything else.
    FileNode,
    /// An indirect or double-indirect node.
    IndirectNode,
}

impl Kind {
    /// Whether the block is a node rather than data. # C: O(1)
    pub fn is_node(self) -> bool {
        matches!(self, Kind::DirNode | Kind::FileNode | Kind::IndirectNode)
    }
}

/// Which log `kind` is written to, given how many logs the volume keeps.
///
/// Two logs separate nodes from data and nothing else; four add a hot/cold
/// split; six give each of node and data three temperatures. A volume
/// formatted for six logs whose writer used two would leave three logs shut
/// and pile everything into the hot ones.
/// # C: O(1)
pub fn log_for(kind: Kind, active_logs: u8) -> usize {
    match active_logs {
        2 => if kind.is_node() { CURSEG_HOT_NODE } else { CURSEG_HOT_DATA },
        4 => match kind {
            Kind::DirData => CURSEG_HOT_DATA,
            Kind::FileData => CURSEG_COLD_DATA,
            Kind::DirNode | Kind::FileNode => CURSEG_HOT_NODE,
            Kind::IndirectNode => CURSEG_COLD_NODE,
        },
        _ => match kind {
            Kind::DirData => CURSEG_HOT_DATA,
            Kind::FileData => CURSEG_WARM_DATA,
            Kind::DirNode => CURSEG_HOT_NODE,
            Kind::FileNode => CURSEG_WARM_NODE,
            Kind::IndirectNode => CURSEG_COLD_NODE,
        },
    }
}

/// Whether a log opens a fresh segment or recycles a partly-used one.
/// # C: O(1)
pub fn wants_recycle(mode: AllocMode) -> bool { mode == AllocMode::Reuse }

/// The checkpoint slot a log's segment number is recorded in: the data logs
/// and the node logs have separate arrays. # C: O(1)
pub fn cp_slot(log: usize) -> (bool, usize) {
    if log >= NR_CURSEG_DATA_TYPE { (true, log - NR_CURSEG_DATA_TYPE) } else { (false, log) }
}

#[cfg(test)]
#[path = "../tests/curseg.rs"]
mod tests;
