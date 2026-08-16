//! Node blocks: the three shapes one block can be, and the footer that says
//! which.
//!
//! Every node block — inode, direct, indirect — is the same size and ends with
//! the same footer. The footer's `nid` is the block's own identity: a block
//! fetched for one node id and carrying another is a table that points
//! somewhere stale, and reading it as if it were the node asked for is how a
//! stale address becomes a wrong file.
//!
//! Module manifest:
//! - `footer`: the trailer, and whether a block is the node that was asked for.
//! - `inode`:  the inode block's fields, and the address array's real extent.
//! - `path`:   which indirection steps a block index takes.

pub mod footer;
pub mod inode;
pub mod path;

pub use footer::{Footer, NodeError};
pub use inode::Inode;
pub use path::{node_path, NodePath, Step};

use crate::uapi::*;

/// One address out of a DIRECT node block. # C: O(1)
pub fn direct_addr(block: &[u8], index: usize) -> Option<u32> {
    if index >= DEF_ADDRS_PER_BLOCK { return None; }
    le32(block, index * 4)
}

/// One node id out of an INDIRECT node block. # C: O(1)
pub fn indirect_nid(block: &[u8], index: usize) -> Option<u32> {
    if index >= NIDS_PER_BLOCK { return None; }
    le32(block, index * 4)
}

/// Whether a stored address names real data rather than a hole.
///
/// Both hole spellings read as zeroes: `NULL_ADDR` is a block never written,
/// and `NEW_ADDR` is one reserved by an allocation whose data has not landed.
/// Treating either as an address reads whatever block zero happens to hold.
/// # C: O(1)
pub fn is_hole(addr: u32) -> bool { addr == NULL_ADDR || addr == NEW_ADDR }

/// Whether an address is the head of a compressed cluster. # C: O(1)
pub fn is_compressed(addr: u32) -> bool { addr == COMPRESS_ADDR }
