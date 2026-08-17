//! The footer bits roll-forward recovery turns on, and the arithmetic that
//! decides whether a node block belongs to the generation being replayed.
//!
//! Nothing here touches a medium. Every decision recovery makes about ONE node
//! block — is it fsync'd, is it of this generation, which file blocks does it
//! cover — is a function of that block's twenty-four byte footer and of the
//! inode's own width, so all of it is testable without an image, and all of it
//! is tested that way.
//!
//! Three bits share the footer's flag word with the node's offset:
//! `COLD` at bit zero, `FSYNC` at bit one, `DENT` at bit two, and the offset
//! from bit three up. A build that puts one of them elsewhere writes a chain
//! the next mount reads as a different chain.

use crate::flags::{COLD_BIT_SHIFT, DENT_BIT_SHIFT, FSYNC_BIT_SHIFT, OFFSET_BIT_SHIFT};
use crate::node::footer::Footer;
use crate::uapi::*;

/// The offset value reserved for a file's attribute node, which is otherwise
/// out of the range a node offset can take. # C: O(1)
pub fn xattr_node_offset() -> u32 { u32::MAX >> OFFSET_BIT_SHIFT }

/// Build a footer flag word from a node's offset and its three marks.
/// # C: O(1)
pub fn flag_word(ofs: u32, fsync: bool, dent: bool, cold: bool) -> u32 {
    let mut w = ofs << OFFSET_BIT_SHIFT;
    if cold { w |= 1 << COLD_BIT_SHIFT; }
    if fsync { w |= 1 << FSYNC_BIT_SHIFT; }
    if dent { w |= 1 << DENT_BIT_SHIFT; }
    w
}

/// Put a flag word into a node block's footer. # C: O(1)
pub fn set_flag(block: &mut [u8], flag: u32) {
    let at = NODE_FOOTER_OFF + FOOTER_FLAG;
    block[at..at + 4].copy_from_slice(&flag.to_le_bytes());
}

/// Put a forward pointer into a node block's footer. # C: O(1)
pub fn set_next_blkaddr(block: &mut [u8], addr: u32) {
    let at = NODE_FOOTER_OFF + FOOTER_NEXT_BLKADDR;
    block[at..at + 4].copy_from_slice(&addr.to_le_bytes());
}

/// Whether a node block was written under the checkpoint now being mounted.
///
/// This is the whole stopping rule for the walk. A block left over from an
/// earlier generation is indistinguishable from a fresh one by shape alone —
/// it has a plausible footer, a plausible forward pointer and plausible
/// addresses — and replaying it would restore blocks a later checkpoint has
/// already released to the allocator.
///
/// `nocrc` names the volume state in which the upper half of the stamped
/// version carries a checksum a checker may have rewritten, so only the
/// version half is compared.
/// # C: O(1)
pub fn is_recoverable(f: &Footer, cp_ver: u64, nocrc: bool) -> bool {
    if nocrc { return (cp_ver << 32) == (f.cp_ver << 32); }
    cp_ver == f.cp_ver
}

/// Whether a node at offset `ofs` holds block ADDRESSES rather than node ids.
///
/// The inode, the two direct nodes, and every direct node hanging under an
/// indirect one qualify; the indirect and double-indirect nodes themselves do
/// not, and neither carries data indices to replay.
/// # C: O(1)
pub fn is_dnode(ofs: u32) -> bool {
    if ofs == xattr_node_offset() { return true; }
    let nids = NIDS_PER_BLOCK as u32;
    if ofs == 3 || ofs == 4 + nids || ofs == 5 + 2 * nids { return false; }
    if ofs >= 6 + 2 * nids {
        let rel = ofs - (6 + 2 * nids);
        if rel % (nids + 1) == 0 { return false; }
    }
    true
}

/// The first file block index the node at offset `ofs` covers.
///
/// The offsets are the node tree's own numbering, in which every indirect node
/// occupies a number of its own between the direct nodes it points at; the
/// subtractions below remove those, leaving the count of DIRECT nodes that
/// precede this one.
/// # C: O(1)
pub fn start_bidx_of_node(ofs: u32, addrs_per_inode: usize) -> u64 {
    if ofs == 0 { return 0; }
    let nids = NIDS_PER_BLOCK as u32;
    let indirect_blks = 2 * nids + 4;
    let bidx = if ofs <= 2 {
        ofs - 1
    } else if ofs <= indirect_blks {
        ofs - 2 - (ofs - 4) / (nids + 1)
    } else {
        ofs - 5 - (ofs - indirect_blks - 3) / (nids + 1)
    };
    u64::from(bidx) * DEF_ADDRS_PER_BLOCK as u64 + addrs_per_inode as u64
}

/// How many addresses one node block holds: an inode's array is narrowed by
/// its extra attributes and its inline attribute reservation, a direct node's
/// is not. # C: O(1)
pub fn addrs_per_page(is_inode: bool, addrs_per_inode: usize) -> usize {
    if is_inode { addrs_per_inode } else { DEF_ADDRS_PER_BLOCK }
}

#[cfg(test)]
#[path = "../../tests/recover/marks.rs"]
mod tests;
