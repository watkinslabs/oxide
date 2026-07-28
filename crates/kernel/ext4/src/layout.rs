/// ABI unit of `i_blocks`: the field counts 512-byte sectors, never
/// filesystem blocks (Linux `ext4_inode.i_blocks_lo`, `fs/ext4/ext4.h`;
/// `fs/quota/dquot.c` `__dquot_alloc_space` -> `inode_add_bytes` charges the
/// same bytes to quota). Only `EXT4_HUGE_FILE_FL` changes the unit, and
/// `Inode::parse` normalises that back to sectors.
pub(crate) const I_BLOCKS_SECTOR_BYTES: u32 = 512;

pub(crate) const I_GENERATION: usize = 0x64;
pub(crate) const I_EXTRA_ISIZE: usize = 0x80;
pub(crate) const I_CHECKSUM_LO: usize = 0x7C;
pub(crate) const I_CHECKSUM_HI: usize = 0x82;
pub(crate) const GD_BLOCK_BITMAP_CSUM_LO: usize = 0x18;
pub(crate) const GD_INODE_BITMAP_CSUM_LO: usize = 0x1A;
pub(crate) const GD_CHECKSUM: usize = 0x1E;
pub(crate) const GD_BLOCK_BITMAP_CSUM_HI: usize = 0x38;
pub(crate) const GD_INODE_BITMAP_CSUM_HI: usize = 0x3A;
