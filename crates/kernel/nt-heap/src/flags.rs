//! Heap and block flag bits shared by the ABI shim and the allocator.

/// Zero the returned body.
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
/// Refuse to move a block that cannot grow in place.
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;
/// Allocation carries a user value/flags record.
pub const HEAP_ADD_USER_INFO: u32 = 0x0000_0100;
/// User flag bits an allocation may carry.
pub const HEAP_USER_FLAGS_MASK: u32 = 0x0000_0f00;
/// The heap may reserve further regions.
pub const HEAP_GROWABLE: u32 = 0x0000_0002;

/// Block is on a free list.
pub const BLOCK_FLAG_FREE: u8 = 0x01;
/// Block owns its own reserved mapping.
pub const BLOCK_FLAG_LARGE: u8 = 0x04;

/// Header type byte of an allocated block.
pub const BLOCK_TYPE_USED: u8 = b'u';
/// Header type byte of a free block.
pub const BLOCK_TYPE_FREE: u8 = b'F';
/// Header type byte of a large block.
pub const BLOCK_TYPE_LARGE: u8 = b'L';
