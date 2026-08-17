//! Bounds a structure read off the medium is checked against before it is used
//! to index anything.

/// The largest data block the format can describe.
pub const FILE_MAX_SIZE: u32 = 1 << FILE_MAX_LOG;
/// `block_log` may not exceed this, and `block_size` must equal `1 << block_log`.
pub const FILE_MAX_LOG: u16 = 20;
/// A data block smaller than the page this kernel maps in cannot be served
/// through the page cache, so an image built with one is refused at mount.
pub const PAGE_BYTES: u32 = 4096;

/// A stored name is at most this long, INCLUDING the length word's `+1`.
pub const NAME_LEN: usize = 256;

/// A directory header describes at most this many entries.
pub const DIR_COUNT: u32 = 256;

/// A symlink target longer than this is corrupt — the reference caps it at one
/// page, which is the only bound the format itself gives.
pub const SYMLINK_MAX: u64 = 4096;

/// Cap on how many metadata blocks one logical read may cross before the image
/// is treated as a loop. A metadata read is bounded by its own length, so this
/// only catches a table whose `next` chain does not advance.
pub const MAX_META_BLOCKS: usize = 4096;

/// The largest attribute value this reader will assemble. Linux caps a value
/// at this, so a record claiming more is corruption and not a large attribute.
pub const XATTR_SIZE_MAX: usize = 65536;

/// The most attributes one inode may carry before its record is treated as
/// corrupt. A count is a plain word off the medium; without a bound it decides
/// how many allocations a single lookup makes.
pub const XATTR_COUNT_MAX: u32 = 4096;
