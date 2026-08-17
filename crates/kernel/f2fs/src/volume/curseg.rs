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

    /// Whether the log has an open segment with room, given how many blocks
    /// that segment may hold.
    ///
    /// The bound is passed in rather than taken as a segment's worth because
    /// on a volume laid out for a drive's zones the last segments of a section
    /// hold fewer blocks — or none — and appending past a zone's capacity is a
    /// write the drive refuses.
    /// # C: O(1)
    pub fn has_room_within(&self, usable: u32) -> bool {
        self.segno != NULL_SEGNO && u32::from(self.next_blkoff) < usable
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
    /// A block of a file that has been pinned.
    ///
    /// Its own log, whatever the volume's log count: a pinned block may not be
    /// moved, so it may not be mixed into a section the cleaner may choose.
    PinnedData,
    /// A block the age-threshold cleaner is moving.
    ///
    /// Also its own log, and for the mirror-image reason: these blocks are OLD,
    /// and the policy that chose them works by section age. Appending them to
    /// the cold log would mix old data into a segment still taking fresh
    /// writes, which raises that section's apparent youth and lowers the
    /// victim's — so the very blocks the cleaner has just proved are cold stop
    /// looking cold, and the next pass picks worse victims than the last.
    AtgcData,
}

impl Kind {
    /// Whether the block is a node rather than data. # C: O(1)
    pub fn is_node(self) -> bool {
        matches!(self, Kind::DirNode | Kind::FileNode | Kind::IndirectNode)
    }
}

/// Stamp a node block's temperature mark from the kind of node it is.
///
/// Only the cold bit is touched. The other three fields of the flag word — the
/// node's offset in its file's tree, and the two recovery marks — are set by
/// whoever knows them and must survive a rewrite that only changes contents.
/// # C: O(1)
pub fn stamp_node_temp(block: &mut [u8], kind: Kind) {
    if !kind.is_node() { return; }
    let at = NODE_FOOTER_OFF + FOOTER_FLAG;
    let Some(old) = le32(block, at) else { return; };
    let bit = 1u32 << crate::flags::COLD_BIT_SHIFT;
    // A file's node carries the mark and a directory's does not, which is the
    // sense the reference stamps it in: the two dnode logs are told apart by
    // it, and reading it backwards puts every file's nodes in the log the
    // directories should have.
    let w = if kind == Kind::FileNode { old | bit } else { old & !bit };
    block[at..at + 4].copy_from_slice(&w.to_le_bytes());
}

/// Which kind of node a block is, read off the block's own footer.
///
/// The one thing that says which log a node belongs in once the caller that
/// changed it is gone — which is the whole reason a node's temperature is
/// recorded in the block rather than carried beside it. A node whose offset
/// says it holds node ids rather than addresses is an indirection node
/// whatever its mark says; below that, the mark decides.
/// # C: O(1)
pub fn node_kind_of(f: &crate::node::footer::Footer) -> Kind {
    if !crate::volume::recover::marks::is_dnode(f.ofs_of_node()) { return Kind::IndirectNode; }
    if f.is_cold() { Kind::FileNode } else { Kind::DirNode }
}

/// Which log `kind` is written to, given how many logs the volume keeps.
///
/// Two logs separate nodes from data and nothing else; four add a hot/cold
/// split; six give each of node and data three temperatures. A volume
/// formatted for six logs whose writer used two would leave three logs shut
/// and pile everything into the hot ones.
/// # C: O(1)
pub fn log_for(kind: Kind, active_logs: u8) -> usize {
    // The pinned log is not one of the volume's, so the log count does not
    // reach it: a two-log volume still keeps pinned blocks apart, because the
    // reason they are apart is the cleaner and not the temperature.
    if kind == Kind::PinnedData { return CURSEG_COLD_DATA_PINNED; }
    if kind == Kind::AtgcData { return CURSEG_ALL_DATA_ATGC; }
    match active_logs {
        2 => if kind.is_node() { CURSEG_HOT_NODE } else { CURSEG_HOT_DATA },
        // With four logs the node side splits on TEMPERATURE, not on what the
        // node is: only a file's own dnode is warm, and a directory's dnode
        // goes cold beside the indirection nodes.
        4 => match kind {
            Kind::DirData => CURSEG_HOT_DATA,
            Kind::FileData => CURSEG_COLD_DATA,
            Kind::FileNode => CURSEG_WARM_NODE,
            Kind::DirNode | Kind::IndirectNode => CURSEG_COLD_NODE,
            Kind::PinnedData => CURSEG_COLD_DATA_PINNED,
            Kind::AtgcData => CURSEG_ALL_DATA_ATGC,
        },
        _ => match kind {
            Kind::DirData => CURSEG_HOT_DATA,
            Kind::FileData => CURSEG_WARM_DATA,
            Kind::DirNode => CURSEG_HOT_NODE,
            Kind::FileNode => CURSEG_WARM_NODE,
            Kind::IndirectNode => CURSEG_COLD_NODE,
            Kind::PinnedData => CURSEG_COLD_DATA_PINNED,
            Kind::AtgcData => CURSEG_ALL_DATA_ATGC,
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
