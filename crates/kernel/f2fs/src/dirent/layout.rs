//! The four regions of a dentry area, and their sizes.
//!
//! Every size follows from one number — how many entries the area holds — and
//! that number follows from the area's byte length by the same formula in both
//! cases: each entry costs a record, a name slot and one bit of bitmap.
//!
//! The inline case is where the two diverge and where a shared formula earns
//! its keep. An inline area is whatever the inode has left after its extra
//! attributes and its inline attribute reservation, so its entry count is not
//! a constant and its padding is not three bytes.

use crate::uapi::*;

/// Where each region of one dentry area begins, and how many entries it holds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Layout {
    /// Entries the area holds.
    pub max: usize,
    /// Bytes of validity bitmap, at offset zero.
    pub bitmap_len: usize,
    /// Byte offset of the record array.
    pub dentry_at: usize,
    /// Byte offset of the name-slot array.
    pub filename_at: usize,
    /// Total bytes the area occupies.
    pub len: usize,
}

impl Layout {
    /// The layout of a whole dentry BLOCK. # C: O(1)
    pub const fn block() -> Self {
        Self {
            max: NR_DENTRY_IN_BLOCK,
            bitmap_len: SIZE_OF_DENTRY_BITMAP,
            dentry_at: SIZE_OF_DENTRY_BITMAP + SIZE_OF_RESERVED,
            filename_at: SIZE_OF_DENTRY_BITMAP
                + SIZE_OF_RESERVED
                + SIZE_OF_DIR_ENTRY * NR_DENTRY_IN_BLOCK,
            len: BLKSIZE,
        }
    }

    /// The layout of the INLINE area of `bytes` bytes.
    ///
    /// The padding is what is left over once the three sized regions are
    /// placed, which is why it is computed rather than named: an inline area
    /// reserves more of it than a block does, and hard-coding a block's three
    /// bytes here would put every record three bytes early.
    /// # C: O(1)
    pub const fn inline(bytes: usize) -> Self {
        let max = (bytes * 8) / ((SIZE_OF_DIR_ENTRY + SLOT_LEN) * 8 + 1);
        let bitmap_len = max.div_ceil(8);
        let reserved = bytes - ((SIZE_OF_DIR_ENTRY + SLOT_LEN) * max + bitmap_len);
        Self {
            max,
            bitmap_len,
            dentry_at: bitmap_len + reserved,
            filename_at: bitmap_len + reserved + SIZE_OF_DIR_ENTRY * max,
            len: bytes,
        }
    }

    /// Byte offset of record `slot`. # C: O(1)
    pub const fn dentry_off(&self, slot: usize) -> usize {
        self.dentry_at + slot * SIZE_OF_DIR_ENTRY
    }

    /// Byte offset of name slot `slot`. # C: O(1)
    pub const fn name_off(&self, slot: usize) -> usize { self.filename_at + slot * SLOT_LEN }

    /// Whether the area is big enough to hold what the layout claims.
    /// # C: O(1)
    pub const fn fits(&self) -> bool {
        self.max > 0 && self.filename_at + self.max * SLOT_LEN <= self.len
    }
}

/// Whether bit `n` of the validity bitmap at the head of `area` is set.
/// # C: O(1)
pub fn is_used(area: &[u8], n: usize) -> bool {
    match area.get(n / 8) { Some(b) => b & (1 << (n % 8)) != 0, None => false }
}

#[cfg(test)]
#[path = "../tests/layout.rs"]
mod tests;
