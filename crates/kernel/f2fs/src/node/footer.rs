//! The twenty-four bytes every node block ends with.

use crate::flags::{DENT_BIT_SHIFT, OFFSET_BIT_SHIFT};
use crate::uapi::*;

/// A node block's trailer.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Footer {
    /// This block's own node id.
    pub nid: u32,
    /// The inode this node belongs to; equal to `nid` for an inode block.
    pub ino: u32,
    /// Cold/fsync/dentry marks, and the node's offset within its inode.
    pub flag: u32,
    /// The checkpoint this node was written under.
    pub cp_ver: u64,
    pub next_blkaddr: u32,
}

impl Footer {
    /// Whether this block is an INODE rather than a direct or indirect node.
    ///
    /// An inode is the node whose own id is its inode number; every other node
    /// of the same file carries the inode's number in `ino` and its own
    /// elsewhere in `nid`.
    /// # C: O(1)
    pub fn is_inode(&self) -> bool { self.nid == self.ino }

    /// This node's offset within the inode's node tree. # C: O(1)
    pub fn ofs_of_node(&self) -> u32 { self.flag >> OFFSET_BIT_SHIFT }

    /// Whether the node holds a directory's data. # C: O(1)
    pub fn is_dent(&self) -> bool { self.flag & (1 << DENT_BIT_SHIFT) != 0 }
}

/// Why a node block was rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NodeError {
    /// The block is shorter than a node block.
    Truncated,
    /// Its footer names a different node than the one that was asked for.
    WrongNid { want: u32, got: u32 },
    /// Its footer names a different inode than the file being read.
    WrongIno { want: u32, got: u32 },
    /// A stored block address falls outside the main area.
    BadAddr(u32),
    /// A node id is zero, reserved, or past the table's end.
    BadNid(u32),
    /// The stored inode checksum does not match the block.
    Checksum,
}

/// Read a block's footer. # C: O(1)
pub fn parse(block: &[u8]) -> Option<Footer> {
    let f = NODE_FOOTER_OFF;
    Some(Footer {
        nid: le32(block, f + FOOTER_NID)?,
        ino: le32(block, f + FOOTER_INO)?,
        flag: le32(block, f + FOOTER_FLAG)?,
        cp_ver: le64(block, f + FOOTER_CP_VER)?,
        next_blkaddr: le32(block, f + FOOTER_NEXT_BLKADDR)?,
    })
}

/// Read a block's footer and confirm it is the node that was asked for.
///
/// `ino` is checked too when the caller knows it: a direct node reached
/// through the right inode but belonging to another file is a table that has
/// drifted, and its addresses point into someone else's data.
/// # C: O(1)
pub fn expect(block: &[u8], nid: u32, ino: Option<u32>) -> Result<Footer, NodeError> {
    if block.len() < BLKSIZE { return Err(NodeError::Truncated); }
    let f = parse(block).ok_or(NodeError::Truncated)?;
    if f.nid != nid { return Err(NodeError::WrongNid { want: nid, got: f.nid }); }
    if let Some(want) = ino {
        if f.ino != want { return Err(NodeError::WrongIno { want, got: f.ino }); }
    }
    Ok(f)
}

#[cfg(test)]
#[path = "../tests/footer.rs"]
mod tests;
