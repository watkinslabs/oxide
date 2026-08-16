//! The on-disk numbers of verity metadata.

/// Bytes of one little-endian field of each width these records use.
pub const U16_LEN: usize = 2;
pub const U32_LEN: usize = 4;
pub const U64_LEN: usize = 8;

/// The attribute value stored on a verity inode is a POINTER to the
/// descriptor, not the descriptor. The descriptor must be protected the same
/// way the file's data is, and an attribute is not, so only a location as
/// wide as this lives there.
pub const LOC_VERSION: usize = 0;
pub const LOC_SIZE: usize = LOC_VERSION + U32_LEN;
pub const LOC_POS: usize = LOC_SIZE + U32_LEN;
/// Bytes of the location record. A value of any other length is a format
/// this build does not know rather than a truncated one.
pub const LOCATION_SIZE: usize = LOC_POS + U64_LEN;
/// The one location layout that exists.
pub const LOCATION_VERSION: u32 = 1;

/// The name the location is stored under, within the verity attribute index.
pub const XATTR_NAME: &[u8] = b"v";

/// Alignment the metadata starts at past the file's data.
///
/// Not the block size: the boundary is chosen so the layout is identical on a
/// machine with far larger pages, and the gap it leaves is a hole rather than
/// allocated space.
pub const METADATA_ALIGN: u64 = 65536;

// --------------------------------------------------------------- descriptor

/// Widest digest and salt the fixed fields hold, whatever the algorithm in
/// use produces; the used part of each is stated beside it.
pub const MAX_ROOT_HASH: usize = 64;
pub const MAX_SALT: usize = 32;
/// Bytes held back for later fields, which must be zero.
pub const RESERVED_LEN: usize = 144;

pub const D_VERSION: usize = 0;
pub const D_HASH_ALGORITHM: usize = D_VERSION + 1;
pub const D_LOG_BLOCKSIZE: usize = D_HASH_ALGORITHM + 1;
pub const D_SALT_SIZE: usize = D_LOG_BLOCKSIZE + 1;
pub const D_SIG_SIZE: usize = D_SALT_SIZE + 1;
pub const D_DATA_SIZE: usize = D_SIG_SIZE + U32_LEN;
pub const D_ROOT_HASH: usize = D_DATA_SIZE + U64_LEN;
pub const D_SALT: usize = D_ROOT_HASH + MAX_ROOT_HASH;
pub const D_RESERVED: usize = D_SALT + MAX_SALT;
/// Bytes of the fixed part; a built-in signature follows it.
pub const DESCRIPTOR_SIZE: usize = D_RESERVED + RESERVED_LEN;

/// The one descriptor layout that exists.
pub const DESCRIPTOR_VERSION: u8 = 1;
/// Widest descriptor, signature included, that will be read.
pub const MAX_DESCRIPTOR_SIZE: usize = 16384;

// ------------------------------------------------------------------- hashes

pub const HASH_ALG_SHA256: u8 = 1;
pub const HASH_ALG_SHA512: u8 = 2;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA512_DIGEST_SIZE: usize = 64;

/// A tree block must hold at least this many digests, or a level would be no
/// narrower than the one below it and the tree would never reach a root.
pub const MIN_DIGESTS_PER_BLOCK: u64 = 2;

/// Narrowest tree block the format admits. Smaller blocks would make the tree
/// unusably deep.
pub const MIN_LOG_BLOCKSIZE: u8 = 10;
/// Levels of tree this build will describe.
pub const MAX_LEVELS: u32 = 8;
