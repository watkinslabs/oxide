// Mount ownership split for the ext4 mount layer.
//
// Module manifest:
// - core: mount open path, cached state, metadata shadowing, and GDT access.
// - blocks: inode reads, extent walks, file-block I/O, and inode flag helpers.
// - dirs: directory mutation, directory lookup, and absolute path walk.
// - io: raw byte-range block-device helpers shared by sibling modules.
// - lifecycle: superblock state/mount-count/time writeback (mount = dirty,
//   unmount = clean), the Linux ext4_setup_super / ext4_put_super half.

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::BlockDevice;
use sync::{Guard, Spinlock, Superblock as SuperblockLockClass};

use crate::dir;
use crate::gdt::{GdtError, GroupDesc};
use crate::inode::InodeError;
use crate::superblock::{Superblock, SuperblockError};

mod blocks;
mod core;
mod dirs;
mod io;
mod lifecycle;

pub(crate) use io::{read_byte_range_pub, write_byte_range};

/// Errors at the Mount layer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MountError {
    BlockIo,
    Superblock(SuperblockError),
    Gdt(GdtError),
    Inode(InodeError),
    Dir(dir::DirError),
    /// Path component not found.
    NotFound,
    /// Path component was not a directory.
    NotDir,
    /// Directory had a non-extent layout (legacy ext2 indirect blocks).
    NotExtents,
    /// File extent tree depth > 0; v1 supports only inline extents.
    DepthUnsupported,
    /// No free block/inode found in any group.
    NoSpace,
    /// Caller passed a physical block outside any group.
    BadBlock,
    /// Caller asked to free a block whose bit was already clear.
    DoubleFree,
    /// Inline extent table is full and growth into an external
    /// node is not yet supported (v1 cap = 4 inline leaves).
    ExtentTreeFull,
    /// Directory block has no free slot for a new entry and
    /// dir-block growth is not yet wired (P7b-03 minimum).
    DirFull,
    /// Extent tree is malformed: root depth exceeds `EXT4_MAX_EXTENT_DEPTH`, or
    /// an interior node's depth did not strictly decrease toward its child (a
    /// cyclic / corrupt tree). Rejected instead of descended so a bad image
    /// cannot spin the walk forever. Linux `__ext4_ext_check`.
    CorruptExtentTree,
    /// metadata_csum verification failed on a read: the stored crc32c of a
    /// superblock / group descriptor / bitmap / inode / directory block /
    /// extent node does not match a recompute (Linux `EFSBADCRC`). The bytes
    /// are refused instead of silently accepted as valid. Surfaces as EIO.
    BadChecksum,
}

impl From<SuperblockError> for MountError { fn from(e: SuperblockError) -> Self { MountError::Superblock(e) } }
impl From<GdtError>        for MountError { fn from(e: GdtError)        -> Self { MountError::Gdt(e) } }
impl From<InodeError>      for MountError { fn from(e: InodeError)      -> Self { MountError::Inode(e) } }
impl From<dir::DirError>   for MountError { fn from(e: dir::DirError)   -> Self { MountError::Dir(e) } }

/// Mutable cached state — locked under `state` for any RW path.
pub struct MountState {
    /// Cached GDT bytes (mirrors disk; updated on every counter
    /// edit + flushed back to the device).
    pub(crate) gdt_buf: Vec<u8>,
    /// Live free-blocks counter; mirrors `s_free_blocks_count`.
    pub(crate) sb_free_blocks: u64,
    /// Live free-inodes counter; mirrors `s_free_inodes_count`.
    pub(crate) sb_free_inodes: u32,
    /// In-memory shadow buffer used during a `run_journaled`
    /// scope: keyed by target fs LBA, value = the new contents
    /// of that fs-block. `metadata_write` populates this; reads
    /// (`read_byte_range_pub`) consult it before going to disk
    /// so that staged-but-uncommitted bytes are visible to
    /// subsequent ops within the same scope. Drained at scope
    /// close + committed as one JBD2 transaction.
    pub(crate) shadow: Option<alloc::collections::BTreeMap<u64, Vec<u8>>>,
}

pub type MountStateGuard<'a> = Guard<'a, MountState, SuperblockLockClass>;

/// Mounted ext4 filesystem.
pub struct Mount {
    pub(crate) dev: Arc<dyn BlockDevice>,
    pub sb: Superblock,
    pub(crate) state: Spinlock<MountState, SuperblockLockClass>,
}
