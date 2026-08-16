//! The index: a B-tree, which is how a directory holds its names.
//!
//! A directory is not a list. Its entries live in a tree ordered by name, with
//! the top of the tree in the record's `$INDEX_ROOT` attribute and the rest in
//! fixed-size blocks in `$INDEX_ALLOCATION`. An entry that has a child carries
//! that child's block number in its LAST EIGHT BYTES — after the key, not in a
//! field of its own — so an implementation that reads only the root sees the
//! handful of names that fit there and reports every other file as absent.
//!
//! Module manifest:
//! - `entry`: one index entry, and the filename key it carries.
//! - `walk`:  in-order traversal, and descent to one name.

use crate::uapi::*;

pub mod entry;
pub mod walk;

pub use entry::{IndexEntry, Key};

/// The header every index node begins with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeHeader {
    /// Offset of the first entry, from the header.
    pub de_off: u32,
    /// Bytes of the node in use.
    pub used: u32,
    /// Bytes the node has.
    pub total: u32,
    pub flags: u32,
}

impl NodeHeader {
    /// Whether the entries in this node carry child pointers. # C: O(1)
    pub fn has_subnodes(&self) -> bool { self.flags & INDEX_HDR_HAS_SUBNODES != 0 }
}

/// The `$INDEX_ROOT` attribute: the top of the tree, and the shape of the
/// rest of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Root {
    /// The attribute type the index is over — `$FILE_NAME` for a directory.
    pub indexed_type: u32,
    pub collation: u32,
    /// Bytes of one index block.
    pub block_size: u32,
    /// Clusters, or sectors, per block.
    pub block_clst: u8,
    pub header: NodeHeader,
    /// Where the header sits within the attribute's data.
    pub header_at: usize,
}

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Decode an index node's header at `at`. # C: O(1)
pub fn node_header(bytes: &[u8], at: usize) -> Option<NodeHeader> {
    if at + SIZEOF_IHDR > bytes.len() { return None; }
    let header = NodeHeader {
        de_off: le32(bytes, at + IHDR_OFF_DE_OFF),
        used: le32(bytes, at + IHDR_OFF_USED),
        total: le32(bytes, at + IHDR_OFF_TOTAL),
        flags: le32(bytes, at + IHDR_OFF_FLAGS),
    };
    // The entries must begin inside the node and end inside it: a used length
    // past the node's own bytes walks into whatever follows.
    if header.de_off < SIZEOF_IHDR as u32 { return None; }
    if header.used < header.de_off { return None; }
    if at.checked_add(header.used as usize)? > bytes.len() { return None; }
    Some(header)
}

/// Decode an `$INDEX_ROOT` attribute's data. # C: O(1)
pub fn parse_root(data: &[u8]) -> Option<Root> {
    if data.len() < IROOT_OFF_IHDR + SIZEOF_IHDR { return None; }
    let header = node_header(data, IROOT_OFF_IHDR)?;
    Some(Root {
        indexed_type: le32(data, IROOT_OFF_TYPE),
        collation: le32(data, IROOT_OFF_RULE),
        block_size: le32(data, IROOT_OFF_BLOCK_SIZE),
        block_clst: data[IROOT_OFF_BLOCK_CLST],
        header,
        header_at: IROOT_OFF_IHDR,
    })
}

/// Decode an index BLOCK, whose update sequence has already been undone.
///
/// Returns where the node's header sits and the block number it claims. A
/// block whose claimed number is not the one that was read is one the volume
/// has moved or a stale copy, and reading it as this block's contents lists
/// another directory's names.
/// # C: O(1)
pub fn parse_block(bytes: &[u8], expect_vbn: u64) -> Option<(NodeHeader, u64)> {
    if bytes.len() < IB_OFF_IHDR + SIZEOF_IHDR { return None; }
    if &bytes[REC_OFF_SIGN..REC_OFF_SIGN + 4] != SIG_INDX.as_slice() { return None; }
    let mut vbn = [0u8; 8];
    vbn.copy_from_slice(&bytes[IB_OFF_VBN..IB_OFF_VBN + 8]);
    let vbn = u64::from_le_bytes(vbn);
    if vbn != expect_vbn { return None; }
    let header = node_header(bytes, IB_OFF_IHDR)?;
    Some((header, vbn))
}

/// Build an empty index block, ready for entries. # C: O(size)
pub fn format_block(size: u32, vbn: u64) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; size as usize];
    out[REC_OFF_SIGN..REC_OFF_SIGN + 4].copy_from_slice(SIG_INDX.as_slice());
    // The array goes AFTER the node header, not at it: a block's header sits
    // at 0x18 where a record's sits at 0x30, and putting the array where a
    // record's goes writes it over the node's own lengths.
    let fix_off = (IB_OFF_IHDR + SIZEOF_IHDR) as u16;
    let fix_num = (size >> SECTOR_SHIFT) as u16 + 1;
    out[REC_OFF_FIX_OFF..REC_OFF_FIX_OFF + 2].copy_from_slice(&fix_off.to_le_bytes());
    out[REC_OFF_FIX_NUM..REC_OFF_FIX_NUM + 2].copy_from_slice(&fix_num.to_le_bytes());
    out[IB_OFF_VBN..IB_OFF_VBN + 8].copy_from_slice(&vbn.to_le_bytes());
    let first = (usize::from(fix_off) + usize::from(fix_num) * 2).next_multiple_of(8);
    let de_off = (first - IB_OFF_IHDR) as u32;
    let at = IB_OFF_IHDR;
    out[at + IHDR_OFF_DE_OFF..at + IHDR_OFF_DE_OFF + 4].copy_from_slice(&de_off.to_le_bytes());
    // One end entry, which every node has and which no key belongs to.
    let used = de_off + SIZEOF_DE as u32;
    out[at + IHDR_OFF_USED..at + IHDR_OFF_USED + 4].copy_from_slice(&used.to_le_bytes());
    let total = size - at as u32;
    out[at + IHDR_OFF_TOTAL..at + IHDR_OFF_TOTAL + 4].copy_from_slice(&total.to_le_bytes());
    let e = at + de_off as usize;
    out[e + DE_OFF_SIZE..e + DE_OFF_SIZE + 2].copy_from_slice(&(SIZEOF_DE as u16).to_le_bytes());
    out[e + DE_OFF_FLAGS..e + DE_OFF_FLAGS + 2].copy_from_slice(&NTFS_IE_LAST.to_le_bytes());
    out
}

#[cfg(test)]
#[path = "tests/index.rs"]
mod tests;
