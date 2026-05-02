// Shared types for the block layer + page cache per `17§2` / `17§4`.
//
// Errno values align with `crates/syscall::Errno` so the dispatch path
// can encode them directly.

extern crate alloc;

/// Block operation per `17§2`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockOp {
    Read,
    Write,
    Flush,
    Discard,
}

/// Block-layer + page-cache error type. Numeric reps Linux-aligned.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockError {
    Eio     = 5,
    Enxio   = 6,
    Enomem  = 12,
    Einval  = 22,
    Eopnotsupp = 95,
}

pub type KResult<T> = core::result::Result<T, BlockError>;

/// Cached page size (`17§4`). Always one PMM page.
pub const PAGE_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;

bitflags::bitflags! {
    /// Page-cache flag word per `17§4.1`. Stored Relaxed; transitions
    /// take the inode-side dirty/list locks where ordering matters.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PageFlags: u32 {
        const LOCKED     = 1 << 0;
        const DIRTY      = 1 << 1;
        const WRITEBACK  = 1 << 2;
        const REFERENCED = 1 << 3;
        const UPTODATE   = 1 << 4;
    }
}

/// Opaque per-cache inode identity. Real VFS inodes hand back their
/// `(superblock_id, ino)` packed into 64 bits; pseudo-FSes pick any
/// stable u64. The page cache treats `InodeId` as opaque so the FS
/// shape doesn't leak in.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InodeId(pub u64);
