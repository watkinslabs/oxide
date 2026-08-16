//! On-disk numbers the format is defined in terms of.
//!
//! Numbers only. A rule about what a number MEANS belongs to the module that
//! acts on it.

/// `hsqs` little-endian — what tells a squashfs image from anything else.
pub const SQUASHFS_MAGIC: u32 = 0x7371_7368;

/// Reported through `statfs` as `f_type`.
pub const SQUASHFS_SUPER_MAGIC: u64 = SQUASHFS_MAGIC as u64;

/// The only major version whose layout this reader knows.
pub const SUPPORTED_MAJOR: u16 = 4;
/// The highest minor of that major whose layout this reader knows.
pub const SUPPORTED_MINOR: u16 = 0;

/// A metadata block holds at most this many bytes once decompressed.
pub const METADATA_SIZE: usize = 8192;
/// The two-byte length word that precedes every metadata block.
pub const BLOCK_OFFSET: u64 = 2;

/// Superblock length in bytes.
pub const SUPER_BYTES: usize = 96;

/// Set in a metadata length word when the block is stored UNCOMPRESSED.
pub const COMPRESSED_BIT: u16 = 1 << 15;
/// Set in a data-block length word when the block is stored UNCOMPRESSED.
pub const COMPRESSED_BIT_BLOCK: u32 = 1 << 24;

/// A data-block length word wider than this is corrupt.
pub const BLOCK_SIZE_BITS: u32 = 25;

/// An inode reference packs its metadata block above its offset by this shift.
pub const INODE_BLOCK_SHIFT: u32 = 16;
/// and keeps the offset in the word below it.
pub const INODE_OFFSET_MASK: u64 = 0xffff;

/// An xattr reference packs its metadata block and offset the same way.
pub const XATTR_BLOCK_SHIFT: u32 = 16;
pub const XATTR_OFFSET_MASK: u64 = 0xffff;

/// Sentinel `fragment` field: the file has no tail in a fragment.
pub const INVALID_FRAG: u32 = u32::MAX;
/// Sentinel `xattr` field: the inode carries no extended attributes.
pub const INVALID_XATTR: u32 = u32::MAX;
/// Sentinel table address: the table is absent from the image.
pub const INVALID_BLK: u64 = u64::MAX;

/// Superblock flag bit positions.
pub mod flags {
    /// Inode table stored uncompressed.
    pub const NOI: u16 = 0;
    /// Data blocks stored uncompressed.
    pub const NOD: u16 = 1;
    /// Fragment blocks stored uncompressed.
    pub const NOF: u16 = 3;
    /// Image was built with fragments disabled.
    pub const NO_FRAG: u16 = 4;
    /// Image was built always packing tails into fragments.
    pub const ALWAYS_FRAG: u16 = 5;
    /// Duplicate file bodies were shared at build time.
    pub const DUPLICATE: u16 = 6;
    /// The inode lookup table is present.
    pub const EXPORT: u16 = 7;
    /// Compressor options follow the superblock.
    pub const COMP_OPT: u16 = 10;
}

/// Inode type discriminants, basic and extended.
pub mod itype {
    pub const DIR: u16 = 1;
    pub const REG: u16 = 2;
    pub const SYMLINK: u16 = 3;
    pub const BLKDEV: u16 = 4;
    pub const CHRDEV: u16 = 5;
    pub const FIFO: u16 = 6;
    pub const SOCKET: u16 = 7;
    pub const LDIR: u16 = 8;
    pub const LREG: u16 = 9;
    pub const LSYMLINK: u16 = 10;
    pub const LBLKDEV: u16 = 11;
    pub const LCHRDEV: u16 = 12;
    pub const LFIFO: u16 = 13;
    pub const LSOCKET: u16 = 14;
}

/// The largest type a DIRECTORY ENTRY may carry — a directory records only the
/// basic types, never the extended ones.
pub const MAX_DIR_TYPE: u16 = 7;

/// Compressor identifiers.
pub mod comp {
    pub const ZLIB: u16 = 1;
    pub const LZMA: u16 = 2;
    pub const LZO: u16 = 3;
    pub const XZ: u16 = 4;
    pub const LZ4: u16 = 5;
    pub const ZSTD: u16 = 6;
}

/// Extended-attribute name-prefix discriminants, and the out-of-line bit.
pub mod xattr {
    pub const USER: u16 = 0;
    pub const TRUSTED: u16 = 1;
    pub const SECURITY: u16 = 2;
    /// Set in an entry's type word when the VALUE is a reference elsewhere.
    pub const VALUE_OOL: u16 = 256;
    /// The prefix lives in the low byte; the out-of-line bit is above it.
    pub const PREFIX_MASK: u16 = 0xff;
}

/// On-disk structure lengths, in bytes.
pub mod size {
    pub const BASE_INODE: usize = 16;
    pub const IPC_INODE: usize = 20;
    pub const LIPC_INODE: usize = 24;
    pub const DEV_INODE: usize = 24;
    pub const LDEV_INODE: usize = 28;
    pub const SYMLINK_INODE: usize = 24;
    pub const REG_INODE: usize = 32;
    pub const LREG_INODE: usize = 56;
    pub const DIR_INODE: usize = 32;
    pub const LDIR_INODE: usize = 40;
    pub const DIR_INDEX: usize = 12;
    pub const DIR_HEADER: usize = 12;
    pub const DIR_ENTRY: usize = 8;
    pub const FRAGMENT_ENTRY: usize = 16;
    pub const XATTR_ID: usize = 16;
    pub const XATTR_ID_TABLE: usize = 16;
    pub const XATTR_ENTRY: usize = 4;
    pub const XATTR_VAL: usize = 4;
    pub const BLOCK_LIST_ENTRY: usize = 4;
    /// One entry of the id, lookup or fragment INDEX tables.
    pub const TABLE_INDEX: usize = 8;
    /// One entry of the id table proper.
    pub const ID_ENTRY: usize = 4;
}
