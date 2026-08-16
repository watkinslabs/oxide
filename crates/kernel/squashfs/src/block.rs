//! The two block encodings, and why decoding one with the other's mask is the
//! failure that looks like success.
//!
//! A METADATA block is preceded by a 16-bit length word; a DATA block's length
//! word lives in the inode's block list and is 32 bits wide. Both spend one bit
//! on "stored uncompressed", but at different positions, and in both the bit
//! is set when the block is NOT compressed. Reading a metadata word with the
//! data mask leaves the uncompressed flag inside the length, so a 40-byte
//! uncompressed block reads as a 32808-byte compressed one — from the right
//! offset, which is what makes it survive a casual look.

use syscall::errno::Errno;

use crate::uapi::{BLOCK_SIZE_BITS, COMPRESSED_BIT, COMPRESSED_BIT_BLOCK};

/// One block's length and whether it is compressed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlockLen {
    /// Bytes occupied ON THE MEDIUM.
    pub on_disk: usize,
    /// Whether those bytes must be run through the codec.
    pub compressed: bool,
}

impl BlockLen {
    /// A block occupying no bytes at all — a sparse data block, which reads as
    /// zeroes and is never fetched. # C: O(1)
    pub fn is_sparse(self) -> bool { self.on_disk == 0 }
}

/// Decode a metadata block's 16-bit length word.
///
/// A word of exactly the flag bit and nothing else denotes the largest length
/// the encoding can express, which no metadata block may actually be; the
/// caller's bound against the metadata block size is what rejects it. Encoding
/// the quirk here and rejecting it there keeps the two decisions where they
/// belong.
/// # C: O(1)
pub fn metadata_length(word: u16) -> BlockLen {
    let bare = word & !COMPRESSED_BIT;
    let on_disk = if bare != 0 { bare as usize } else { COMPRESSED_BIT as usize };
    BlockLen { on_disk, compressed: word & COMPRESSED_BIT == 0 }
}

/// Decode a data block's 32-bit length word.
///
/// A word with any bit above the flag set cannot describe a block this format
/// can hold, so it is corruption and not a large block.
/// # C: O(1)
pub fn data_length(word: u32) -> Result<BlockLen, Errno> {
    if word >> BLOCK_SIZE_BITS != 0 { return Err(Errno::Eio); }
    Ok(BlockLen {
        on_disk: (word & !COMPRESSED_BIT_BLOCK) as usize,
        compressed: word & COMPRESSED_BIT_BLOCK == 0,
    })
}

#[cfg(test)]
#[path = "tests/block.rs"]
mod tests;
