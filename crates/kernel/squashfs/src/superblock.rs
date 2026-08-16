//! The superblock, and every reason a volume is refused before a byte of its
//! content is believed.

use crate::compress::{Codec, CodecError};
use crate::limits::{FILE_MAX_LOG, FILE_MAX_SIZE, PAGE_BYTES};
use crate::uapi::{self, flags, size, INVALID_BLK, METADATA_SIZE, SQUASHFS_MAGIC, SUPER_BYTES,
                  SUPPORTED_MAJOR, SUPPORTED_MINOR};

/// A superblock that passed every check in [`Super::parse`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Super {
    pub inodes: u32,
    pub mkfs_time: u32,
    pub block_size: u32,
    pub fragments: u32,
    pub codec: Codec,
    pub block_log: u16,
    pub flags: u16,
    pub no_ids: u16,
    pub major: u16,
    pub minor: u16,
    /// Packed `(metadata block << 16) | offset within it`.
    pub root_inode: u64,
    pub bytes_used: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub lookup_table_start: u64,
}

/// Why a volume is not mountable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SuperError {
    /// Fewer than a superblock's worth of bytes.
    Short,
    /// The magic word is absent — not a squashfs image.
    BadMagic,
    /// A layout version this reader does not know, either direction.
    Version(u16, u16),
    /// The compressor cannot be used here.
    Codec(CodecError),
    /// A field the format constrains holds a value it forbids.
    Insane(&'static str),
    /// The image claims more bytes than the medium holds.
    Truncated { claimed: u64, medium: u64 },
}

/// Read one little-endian word out of a superblock image.
fn u16_at(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

/// Field offsets within the superblock.
mod at {
    pub const MAGIC: usize = 0;
    pub const INODES: usize = 4;
    pub const MKFS_TIME: usize = 8;
    pub const BLOCK_SIZE: usize = 12;
    pub const FRAGMENTS: usize = 16;
    pub const COMPRESSION: usize = 20;
    pub const BLOCK_LOG: usize = 22;
    pub const FLAGS: usize = 24;
    pub const NO_IDS: usize = 26;
    pub const MAJOR: usize = 28;
    pub const MINOR: usize = 30;
    pub const ROOT_INODE: usize = 32;
    pub const BYTES_USED: usize = 40;
    pub const ID_TABLE: usize = 48;
    pub const XATTR_ID_TABLE: usize = 56;
    pub const INODE_TABLE: usize = 64;
    pub const DIRECTORY_TABLE: usize = 72;
    pub const FRAGMENT_TABLE: usize = 80;
    pub const LOOKUP_TABLE: usize = 88;
}

impl Super {
    /// Parse and VALIDATE a superblock read from the front of a volume.
    ///
    /// `medium` is how many bytes the medium actually holds. An image that
    /// claims more is refused here and not later: every table address in this
    /// structure is bounded against `bytes_used`, so believing an inflated
    /// `bytes_used` is what lets a crafted image aim a read off the end.
    /// # C: O(1)
    pub fn parse(b: &[u8], medium: u64) -> Result<Self, SuperError> {
        if b.len() < SUPER_BYTES { return Err(SuperError::Short); }
        if u32_at(b, at::MAGIC) != SQUASHFS_MAGIC { return Err(SuperError::BadMagic); }

        let major = u16_at(b, at::MAJOR);
        let minor = u16_at(b, at::MINOR);
        if major != SUPPORTED_MAJOR || minor > SUPPORTED_MINOR {
            return Err(SuperError::Version(major, minor));
        }

        let codec = Codec::from_id(u16_at(b, at::COMPRESSION)).map_err(SuperError::Codec)?;

        let bytes_used = u64_at(b, at::BYTES_USED);
        if bytes_used < SUPER_BYTES as u64 { return Err(SuperError::Insane("bytes_used")); }
        if bytes_used > medium {
            return Err(SuperError::Truncated { claimed: bytes_used, medium });
        }

        let block_size = u32_at(b, at::BLOCK_SIZE);
        let block_log = u16_at(b, at::BLOCK_LOG);
        if block_size > FILE_MAX_SIZE { return Err(SuperError::Insane("block_size")); }
        if block_size < PAGE_BYTES { return Err(SuperError::Insane("block_size < page")); }
        if block_log > FILE_MAX_LOG { return Err(SuperError::Insane("block_log")); }
        if block_size != 1u32 << block_log { return Err(SuperError::Insane("block_log mismatch")); }

        let root_inode = u64_at(b, at::ROOT_INODE);
        if inode_offset(root_inode) as usize > METADATA_SIZE {
            return Err(SuperError::Insane("root_inode offset"));
        }

        let sb = Self {
            inodes: u32_at(b, at::INODES),
            mkfs_time: u32_at(b, at::MKFS_TIME),
            block_size,
            fragments: u32_at(b, at::FRAGMENTS),
            codec,
            block_log,
            flags: u16_at(b, at::FLAGS),
            no_ids: u16_at(b, at::NO_IDS),
            major,
            minor,
            root_inode,
            bytes_used,
            id_table_start: u64_at(b, at::ID_TABLE),
            xattr_id_table_start: u64_at(b, at::XATTR_ID_TABLE),
            inode_table_start: u64_at(b, at::INODE_TABLE),
            directory_table_start: u64_at(b, at::DIRECTORY_TABLE),
            fragment_table_start: u64_at(b, at::FRAGMENT_TABLE),
            lookup_table_start: u64_at(b, at::LOOKUP_TABLE),
        };
        sb.check_geometry()?;
        Ok(sb)
    }

    /// The table addresses must lie inside the image and in the order the
    /// build tool writes them. Without this an inode-table address past
    /// `bytes_used` reads whatever follows the image on the medium.
    fn check_geometry(&self) -> Result<(), SuperError> {
        if self.inode_table_start >= self.directory_table_start {
            return Err(SuperError::Insane("inode_table >= directory_table"));
        }
        if self.directory_table_start >= self.bytes_used {
            return Err(SuperError::Insane("directory_table past image"));
        }
        if self.id_table_start > self.bytes_used {
            return Err(SuperError::Insane("id_table past image"));
        }
        if self.no_ids == 0 { return Err(SuperError::Insane("no ids")); }
        for (addr, what) in [(self.fragment_table_start, "fragment_table"),
                             (self.lookup_table_start, "lookup_table"),
                             (self.xattr_id_table_start, "xattr_id_table")] {
            if addr != INVALID_BLK && addr > self.bytes_used {
                return Err(SuperError::Insane(what));
            }
        }
        if self.fragments != 0 && self.fragment_table_start == INVALID_BLK {
            return Err(SuperError::Insane("fragments without a table"));
        }
        Ok(())
    }

    /// Whether one superblock flag is set. # C: O(1)
    pub fn flag(&self, bit: u16) -> bool { (self.flags >> bit) & 1 == 1 }

    /// Inode metadata is stored uncompressed. # C: O(1)
    pub fn uncompressed_inodes(&self) -> bool { self.flag(flags::NOI) }
    /// Data blocks are stored uncompressed. # C: O(1)
    pub fn uncompressed_data(&self) -> bool { self.flag(flags::NOD) }
    /// Fragment blocks are stored uncompressed. # C: O(1)
    pub fn uncompressed_fragments(&self) -> bool { self.flag(flags::NOF) }
    /// The inode lookup table is present, so the image is exportable. # C: O(1)
    pub fn exportable(&self) -> bool { self.flag(flags::EXPORT) }

    /// Bytes the id INDEX table occupies. # C: O(1)
    pub fn id_index_bytes(&self) -> u64 {
        index_bytes(u64::from(self.no_ids) * size::ID_ENTRY as u64)
    }

    /// Bytes the fragment INDEX table occupies. # C: O(1)
    pub fn fragment_index_bytes(&self) -> u64 {
        index_bytes(u64::from(self.fragments) * size::FRAGMENT_ENTRY as u64)
    }

    /// Bytes the inode-lookup INDEX table occupies. # C: O(1)
    pub fn lookup_index_bytes(&self) -> u64 {
        index_bytes(u64::from(self.inodes) * size::TABLE_INDEX as u64)
    }
}

/// How many index entries cover `bytes` of a metadata-block-chunked table, in
/// bytes. Each index entry is one 64-bit address of one metadata block.
fn index_bytes(bytes: u64) -> u64 {
    bytes.div_ceil(METADATA_SIZE as u64) * size::TABLE_INDEX as u64
}

/// The metadata BLOCK an inode reference names. # C: O(1)
pub fn inode_block(reference: u64) -> u64 { reference >> uapi::INODE_BLOCK_SHIFT }

/// The byte OFFSET within that block. # C: O(1)
pub fn inode_offset(reference: u64) -> u64 { reference & uapi::INODE_OFFSET_MASK }

/// Pack a block and offset into an inode reference. # C: O(1)
pub fn make_reference(block: u64, offset: u64) -> u64 {
    (block << uapi::INODE_BLOCK_SHIFT) | (offset & uapi::INODE_OFFSET_MASK)
}

#[cfg(test)]
#[path = "tests/superblock.rs"]
mod tests;
