//! Which indirection steps reach the block at a given index of a file.
//!
//! Five ranges, in order: the addresses inside the inode itself, two direct
//! nodes, two indirect nodes, and one double-indirect node. Each range is
//! subtracted off before the next is tested, so every boundary is an exact
//! equality — index `direct_index` is the FIRST block of the first direct
//! node, not the last inside the inode.
//!
//! The first range's width is not a constant. It shrinks by the extra
//! attribute region and by the inline attribute reservation, both of which
//! live at the head of the same array, so a build that uses the nominal width
//! puts the boundary in the wrong place and reads every block past it one slot
//! out.

use crate::uapi::*;

/// One step of the path from an inode to a data block.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// Slot `index` of the inode's own address array.
    InInode { index: usize },
    /// Slot `index` of the direct node named by `i_nid[nid_slot]`.
    Direct { nid_slot: usize, index: usize },
    /// Through the indirect node at `i_nid[nid_slot]`, its `dnode` entry, then
    /// slot `index` of that direct node.
    Indirect { nid_slot: usize, dnode: usize, index: usize },
    /// Through the double-indirect node at `i_nid[nid_slot]`, its `indirect`
    /// entry, that node's `dnode` entry, then slot `index`.
    DoubleIndirect { nid_slot: usize, indirect: usize, dnode: usize, index: usize },
}

/// A resolved path, in the same shape the format's own walker uses.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NodePath {
    /// How many node blocks stand between the inode and the address: zero for
    /// an address in the inode, three for the deepest.
    pub level: u8,
    /// The index taken at each step. `offset[0]` is either a slot in the
    /// inode's address array or one of the five node-id positions.
    pub offset: [usize; 4],
    /// Each step's node number within the inode's own node tree, which is what
    /// a node's footer records.
    pub noffset: [usize; 4],
}

impl NodePath {
    /// The path as the step a reader takes. # C: O(1)
    pub fn step(&self) -> Step {
        match self.level {
            0 => Step::InInode { index: self.offset[0] },
            1 => Step::Direct { nid_slot: self.offset[0] - NODE_DIR1_BLOCK, index: self.offset[1] },
            2 => Step::Indirect {
                nid_slot: self.offset[0] - NODE_DIR1_BLOCK,
                dnode: self.offset[1],
                index: self.offset[2],
            },
            _ => Step::DoubleIndirect {
                nid_slot: self.offset[0] - NODE_DIR1_BLOCK,
                indirect: self.offset[1],
                dnode: self.offset[2],
                index: self.offset[3],
            },
        }
    }
}

/// Resolve `block`, the index of a block within a file.
///
/// `addrs_per_inode` is the inode's OWN width, already reduced by its extra
/// attributes and inline attribute reservation. `None` means the index is past
/// what the format can address at all.
/// # C: O(1)
pub fn node_path(addrs_per_inode: usize, block: u64) -> Option<NodePath> {
    let direct_index = addrs_per_inode as u64;
    let direct_blks = DEF_ADDRS_PER_BLOCK as u64;
    let dptrs_per_blk = NIDS_PER_BLOCK as u64;
    let indirect_blks = direct_blks * dptrs_per_blk;
    let dindirect_blks = indirect_blks * dptrs_per_blk;

    let mut offset = [0usize; 4];
    let mut noffset = [0usize; 4];

    let mut b = block;
    if b < direct_index {
        offset[0] = b as usize;
        return Some(NodePath { level: 0, offset, noffset });
    }
    b -= direct_index;
    for (slot, first) in [(NODE_DIR1_BLOCK, 1usize), (NODE_DIR2_BLOCK, 2usize)] {
        if b < direct_blks {
            offset[0] = slot;
            noffset[1] = first;
            offset[1] = b as usize;
            return Some(NodePath { level: 1, offset, noffset });
        }
        b -= direct_blks;
    }
    for (slot, base) in [
        (NODE_IND1_BLOCK, 3usize),
        (NODE_IND2_BLOCK, 4 + dptrs_per_blk as usize),
    ] {
        if b < indirect_blks {
            offset[0] = slot;
            noffset[1] = base;
            offset[1] = (b / direct_blks) as usize;
            noffset[2] = base + 1 + offset[1];
            offset[2] = (b % direct_blks) as usize;
            return Some(NodePath { level: 2, offset, noffset });
        }
        b -= indirect_blks;
    }
    if b < dindirect_blks {
        offset[0] = NODE_DIND_BLOCK;
        noffset[1] = 5 + (dptrs_per_blk as usize * 2);
        offset[1] = (b / indirect_blks) as usize;
        noffset[2] = noffset[1] + 1 + offset[1] * (dptrs_per_blk as usize + 1);
        offset[2] = ((b / direct_blks) % dptrs_per_blk) as usize;
        noffset[3] = noffset[2] + 1 + offset[2];
        offset[3] = (b % direct_blks) as usize;
        return Some(NodePath { level: 3, offset, noffset });
    }
    None
}

/// One past the highest block index the format can address for an inode of
/// this width. # C: O(1)
pub fn max_block(addrs_per_inode: usize) -> u64 {
    let direct_blks = DEF_ADDRS_PER_BLOCK as u64;
    let dptrs = NIDS_PER_BLOCK as u64;
    addrs_per_inode as u64
        + 2 * direct_blks
        + 2 * direct_blks * dptrs
        + direct_blks * dptrs * dptrs
}

#[cfg(test)]
#[path = "../tests/path.rs"]
mod tests;
