//! Whether a block of the victim is genuinely still in use.
//!
//! Three records describe the same block and any of them can be stale, so the
//! cleaner believes a block only when all three agree:
//!
//! - The **segment table** bit says the block is live. It is the allocator's
//!   truth, but it is a count, not an owner: a bit left set by a lost release
//!   names no file at all.
//! - The **summary block** names the node that owns the block and the slot
//!   inside it. It was written when the segment was sealed and is never
//!   revised, so it describes where the block WAS wanted, not where anything
//!   points now.
//! - The **owning node** holds the address it currently uses for that slot.
//!   This is the only record that can say the block still belongs to the file.
//!
//! Trusting the table alone migrates blocks nothing references and then writes
//! their addresses back into a file that had moved on — data loss, not a leak.
//! Trusting the summary alone migrates a block whose owner has since been
//! rewritten out of place, and the migration overwrites the owner's newer
//! address with the copy. The cross-check is the part that has to be right.

use crate::flags::OFFSET_BIT_SHIFT;
use crate::uapi::*;
use crate::volume::curseg::{Summary, SUM_TYPE_NODE};

/// The node offset a block carrying attributes is stamped with: every bit the
/// field has.
pub const XATTR_NODE_OFS: u32 = u32::MAX >> OFFSET_BIT_SHIFT;

/// The summary entry for block `slot` of a segment. # C: O(1)
pub fn entry(block: &[u8], slot: usize) -> Option<Summary> {
    let at = summary_off(slot);
    if at + SUMMARY_SIZE > SUM_JOURNAL_OFF { return None; }
    Some(Summary {
        nid: le32(block, at)?,
        version: *block.get(at + 4)?,
        ofs_in_node: le16(block, at + 5)?,
    })
}

/// Whether a summary block describes NODE blocks rather than file data.
///
/// The distinction decides which record is consulted for the owner: a data
/// block's owner is another node, a node block's owner is the node table.
/// # C: O(1)
pub fn holds_nodes(block: &[u8]) -> bool {
    block.get(BLKSIZE - SUM_FOOTER_SIZE) == Some(&SUM_TYPE_NODE)
}

/// Whether a summary entry names an owner at all.
///
/// Node id zero is not a node; a summary slot never written reads as zero, and
/// so does one belonging to a segment whose summary block was lost.
/// # C: O(1)
pub fn owned(s: &Summary) -> bool { s.nid >= RESERVED_NODE_NUM }

/// Whether the block at `addr` is live by all three records.
///
/// `owner_addr` is what the owning node currently records for the slot the
/// summary named, or `None` when the owner could not be read at all.
/// # C: O(1)
pub fn alive(bitmap_live: bool, s: &Summary, owner_addr: Option<u32>, addr: u32) -> bool {
    bitmap_live && owned(s) && owner_addr == Some(addr)
}

/// Whether a node at file-tree offset `ofs` holds block ADDRESSES rather than
/// further node ids.
///
/// The offsets that hold ids are the three the inode names directly and, past
/// them, every offset that starts a run of direct nodes under an indirect one.
/// An attribute block holds neither but is written to the same log as a node
/// that holds addresses.
/// # C: O(1)
pub fn holds_addresses(ofs: u32) -> bool {
    if ofs == XATTR_NODE_OFS { return true; }
    let n = NIDS_PER_BLOCK as u32;
    if ofs == 3 || ofs == 4 + n || ofs == 5 + 2 * n { return false; }
    if ofs >= 6 + 2 * n && (ofs - (6 + 2 * n)) % (n + 1) == 0 { return false; }
    true
}
