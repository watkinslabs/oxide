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
    /// Linux `REQ_OP_WRITE_ZEROES`. `no_unmap` is the typed equivalent of
    /// `REQ_NOUNMAP`: zero data without allowing deallocation.
    WriteZeroes { no_unmap: bool },
    Flush,
    Discard,
}

/// Block-layer + page-cache error type. Numeric reps Linux-aligned.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockError {
    Eio     = 5,
    Enxio   = 6,
    Eagain  = 11,
    Enomem  = 12,
    Ebusy   = 16,
    Einval  = 22,
    Enospc  = 28,
    Erofs   = 30,
    /// A drive refused because it already holds its limit of ACTIVE zones.
    /// Not a media failure and not a permanent refusal: finishing or
    /// resetting a zone makes the same request succeed, which is why this
    /// stays distinct from `Eio`.
    Eoverflow = 75,
    Eopnotsupp = 95,
    /// A drive refused because it already holds its limit of OPEN zones.
    /// Closing a zone makes the same request succeed.
    Etoomanyrefs = 109,
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
        /// On the ACTIVE half of the two-list LRU (`17§4.4`). A page reaches
        /// it by being found again while already referenced on the inactive
        /// half, which is what makes the second reference — not the first —
        /// the thing that protects a page from reclaim.
        const ACTIVE     = 1 << 5;
    }
}

/// Opaque per-cache inode identity. Real VFS inodes hand back their
/// `(superblock_id, ino)` packed into 64 bits; pseudo-FSes pick any
/// stable u64. The page cache treats `InodeId` as opaque so the FS
/// shape doesn't leak in.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InodeId(pub u64);
