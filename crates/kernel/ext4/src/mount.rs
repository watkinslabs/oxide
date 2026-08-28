// Mount ownership split for the ext4 mount layer.
//
// Module manifest:
// - core: mount open path, cached state, metadata shadowing, and GDT access.
// - csum_trace: one-shot debug origin record for a rejected metadata checksum.
// - blocks: inode reads, extent walks, file-block I/O, and inode flag helpers.
// - dirs: directory mutation, directory lookup, and absolute path walk.
// - errors: the volume's error history — recording an event, reading it back.
// - io: raw byte-range block-device helpers shared by sibling modules.
// - lifecycle: superblock state/mount-count/time writeback (mount = dirty,
//   unmount = clean), the Linux ext4_setup_super / ext4_put_super half.
// - quota: VFS quota backref and exact i_blocks delta charging.
// - validity: Linux system-block ownership and block-validity checks.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use block::BlockDevice;
use sync::{Guard, Spinlock, Superblock as SuperblockLockClass};

use crate::dir;
use crate::gdt::{GdtError, GroupDesc};
use crate::inode::InodeError;
use crate::superblock::{Superblock, SuperblockError};

mod blocks;
mod batch;
mod core;
mod csum_trace;
/// Register the current-context id source for the transaction gate (kernel).
#[cfg(target_os = "oxide-kernel")]
pub use core::set_ctx_id_hook;
pub(crate) use csum_trace::first_csum_failure;
mod dirs;
mod errors;
#[cfg(not(target_os = "oxide-kernel"))]
mod faults;
mod io;
mod lifecycle;
mod quota;
mod validity;

pub(crate) use io::{read_byte_range_pub, write_durable_block};
pub(crate) use io::write_byte_range as io_write_byte_range;

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
    /// The superblock advertises an INCOMPAT feature we don't implement, or a
    /// RO_COMPAT feature we can't safely write (and we have no RO-mount path):
    /// mounting would misinterpret the layout (bigalloc cluster bitmap, meta_bg,
    /// inline_data, encrypt, …). Refused at `Mount::open` (Linux
    /// `EXT4_FEATURE_*_SUPP` check). Surfaces as EINVAL.
    UnsupportedFeature,
    /// VFS quota layer rejected or failed accounting.
    Quota(vfs::VfsError),
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
    /// The one committed transaction retained until its filesystem home
    /// blocks are checkpointed. The journal superblock remains dirty while
    /// this is present, so recovery owns the same bytes if power is lost.
    pub(crate) pending_checkpoint: Option<crate::journal::PendingCheckpoint>,
    /// Clean metadata buffers keyed by filesystem LBA.  The VFS dcache avoids
    /// repeating name walks, but a cold dentry miss still needs the ext4 inode
    /// table and directory blocks.  Linux serves those from the buffer/page
    /// cache (`sb_bread`); bypassing it made every component issue synchronous
    /// device I/O again.  `shadow` remains authoritative for an open journal
    /// transaction, so this cache contains only clean on-disk bytes.
    pub(crate) metadata_cache: alloc::collections::BTreeMap<u64, alloc::sync::Arc<Vec<u8>>>,
    /// Publication order of `metadata_cache`, so a full cache evicts its
    /// oldest entries instead of dropping every buffer it holds. Clearing the
    /// whole cache on overflow threw away the inode table and the extent
    /// blocks the running workload was reading, and every reader then went
    /// back to the device; the reference retires buffers one at a time.
    pub(crate) metadata_order: alloc::collections::VecDeque<u64>,
    /// Validated block bitmaps retained for repeated mballoc group scans.
    /// Linux keeps bitmap/buddy state resident after a group is loaded; this
    /// map is the bitmap half of that ownership boundary.
    pub(crate) block_bitmap_cache: alloc::collections::BTreeMap<u64, Vec<u8>>,
    /// Largest free buddy order known for each group. A missing entry means
    /// that group has not yet had its bitmap scanned by this mount.
    pub(crate) group_free_order: alloc::collections::BTreeMap<u32, u8>,
    /// Linux's largest-free-order xarrays, represented by order-indexed sets.
    pub(crate) group_free_order_index: alloc::collections::BTreeMap<u8, alloc::collections::BTreeSet<u32>>,
    /// Average free-fragment order known for each loaded group. Linux uses
    /// this second index to avoid probing groups whose average fragment is
    /// smaller than a multiblock request.
    pub(crate) group_avg_fragment_order: alloc::collections::BTreeMap<u32, u8>,
    /// Linux's average-fragment xarrays, represented by order-indexed sets.
    pub(crate) group_avg_fragment_index: alloc::collections::BTreeMap<u8, alloc::collections::BTreeSet<u32>>,
    /// Reusable locality-group data preallocation tails. The blocks remain
    /// free on disk and are masked from every in-memory bitmap scan.
    pub(crate) group_prealloc: alloc::collections::BTreeMap<u32, Vec<crate::balloc::prealloc::GroupPrealloc>>,
    /// Per-inode data preallocation tails. The bitmap owns these blocks on
    /// disk, while this table owns their not-yet-mapped logical range.
    pub(crate) inode_prealloc: alloc::collections::BTreeMap<u32, Vec<crate::balloc::prealloc::InodePrealloc>>,
    /// Cross-operation batching (Linux jbd2 running-transaction model). When
    /// set, the `shadow` PERSISTS across `run_journaled` scopes: each op joins
    /// the running transaction instead of committing its own, and the batch is
    /// drained by `commit_batch` on a trigger (size threshold / fsync / sync /
    /// unmount). Committing per-op (the default) makes every fs-heavy service
    /// pay a full journal commit and checkpoint per operation — the systematic
    /// sysinit slowness. Opt-in per mount (rootfs enables it).
    pub(crate) batch: bool,
    /// Per-op undo stack (batch mode only). Each `run_journaled` op that joins
    /// the running transaction pushes a frame recording the pre-op shadow value
    /// of every LBA it stages; on op failure the frame is replayed to restore
    /// the shared shadow (so ONE op's failure never corrupts prior batched ops),
    /// on success it merges into the parent frame (or is dropped at top level).
    /// Keyed by LBA (BTreeMap) so recording is O(log n) per staged block and
    /// auto-dedups to the EARLIEST pre-op value — a Vec + linear dedup scan was
    /// O(n²) per op and stalled the state lock for seconds on a large writeback.
    pub(crate) undo: Vec<alloc::collections::BTreeMap<u64, Option<Vec<u8>>>>,
    pub(crate) next_generation: u64,
    pub(crate) running_generation: u64,
    pub(crate) committed_generation: u64,
    pub(crate) barrier_generation: u64,
    pub(crate) inode_generations: alloc::collections::BTreeMap<u32, (u64, u64)>,
}

pub type MountStateGuard<'a> = Guard<'a, MountState, SuperblockLockClass>;

/// Mounted ext4 filesystem.
pub struct Mount {
    pub(crate) dev: Arc<dyn BlockDevice>,
    pub sb: Superblock,
    pub(crate) system_zones: Vec<(u64, u64)>,
    pub(crate) state: Spinlock<MountState, SuperblockLockClass>,
    pub(crate) quota_sb: Spinlock<Weak<vfs::SuperBlock>, SuperblockLockClass>,
    /// This volume's error history, seeded at open from the superblock and
    /// extended by every filesystem error this mount finds. Lives on the mount
    /// rather than beside the reports that read it, because the recorder and
    /// the readers must not be able to disagree about it.
    /// # Lk: leaf — taken only to read or add one event.
    pub(crate) err: Spinlock<crate::errstat::ErrRecord, SuperblockLockClass>,
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) faults: faults::HostedFaults,
    /// Reentrant transaction gate — serializes EVERY top-level mutating op
    /// (create/write/unlink/truncate/alloc_block/…), not just creates, so
    /// concurrent tasks/CPUs cannot (a) read the same group bitmap and
    /// double-allocate one inode/block (Linux `ext4_lock_group`) nor (b) race
    /// the shared `MountState.shadow` transaction lifecycle. `run_journaled`
    /// acquires it at the OUTERMOST scope keyed on the current context
    /// (`ctx_id`); nested same-context calls bump `txn_depth` and join without
    /// re-locking; concurrent contexts wait until free. `txn_owner`==0 ⇒ free.
    /// # Lk: outermost (held across the whole `run_journaled` scope + commit).
    pub(crate) txn_owner: ::core::sync::atomic::AtomicU64,
    pub(crate) txn_depth: ::core::sync::atomic::AtomicU32,
    /// Sleep queue for contexts blocked behind [`Self::txn_owner`]. Release
    /// clears the owner before waking so every resumed waiter retries the same
    /// atomic claim predicate.
    pub(crate) txn_wait: sched::live::WaitList,
    /// True while `commit_batch_for` is ordering data and draining the
    /// metadata transaction. Dirty-data writeback can itself perform journaled
    /// writes; those writes must not recursively start another batch commit.
    /// Linux's ordered-data phase completes writeback before the metadata
    /// commit, so nested `maybe_commit_batch` calls defer to this owner.
    pub(crate) committing_batch: ::core::sync::atomic::AtomicBool,
    /// The running batch has grown past its block budget and wants a commit.
    /// Set by the operation that filled it and cleared by the commit; the
    /// operation does NOT commit on its own stack. Committing there put the
    /// journal write, the ordered-data flush and the block layer underneath
    /// whatever directory operation happened to be the one that tipped the
    /// batch over — which is how a `rename` came to be the kernel's deepest
    /// call path.
    pub(crate) batch_full: ::core::sync::atomic::AtomicBool,
    /// Waiters blocked by the running transaction's hard credit ceiling.
    /// The periodic committer wakes them after retiring the transaction.
    pub(crate) batch_wait: sched::live::WaitList,
    /// True while a create op holds `op_lock`. The size-triggered batch commit
    /// (`maybe_commit_batch` → `dev.flush`, which SLEEPS on the virtio
    /// completion) must NOT fire while `op_lock` is held: `op_lock` is a
    /// busy-wait spinlock, so a holder that yields for I/O while a contender
    /// spins the lock livelocks (hard hang). The commit is deferred to AFTER the
    /// creator releases `op_lock`; it still drains the shadow atomically under
    /// `state.lock`, so it stays serialized. # Lk: none (atomic).
    pub(crate) creating: ::core::sync::atomic::AtomicBool,
    /// The mount options in force. SOLE owner of this mount's option truth:
    /// Linux keeps them in the per-superblock info every ext4 function reaches
    /// through its inode's superblock, which is why every layer can read them.
    /// They live HERE and not one layer up because the consumers are here — the
    /// directory-growth ceiling, the discard on block free, the journal's I/O
    /// priority and its data-ordering mode are all decided below the VFS-facing
    /// state object, which could not see an option it owned itself.
    /// # Lk: leaf — takes nothing, and never taken while `state` is held.
    pub(crate) opts: Spinlock<crate::mount_opts::Ext4SbOpts, SuperblockLockClass>,
    /// Hosted-test override of the allocating context's credentials. There is
    /// no running task under `cargo test`, so without it every hosted
    /// allocation is the kernel's own and the reserve gate can only ever be
    /// exercised from the admitted side.
    /// # Lk: leaf.
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) test_cred: Spinlock<Option<crate::balloc::reserve::AllocCred>, SuperblockLockClass>,
}

impl Drop for Mount {
    fn drop(&mut self) {
        // Linux drops inode preallocation while the superblock is being put;
        // otherwise bitmap-reserved tails would outlive their in-memory owner.
        let _ = self.release_all_inode_prealloc();
        let _ = self.release_all_group_prealloc();
        let _ = self.commit_batch();
    }
}

impl Mount {
    /// Snapshot of the options in force on this mount. # C: O(MAXQUOTAS)
    pub fn opts(&self) -> crate::mount_opts::Ext4SbOpts { self.opts.lock().clone() }

    /// The behavioural half of those options. Copy-out, so a consumer holds no
    /// lock while acting on the answer. # C: O(1)
    pub fn behaviour(&self) -> crate::mount_opts::Ext4Behaviour { self.opts.lock().behaviour }

    /// Replace the option state wholesale. Only the option path calls this,
    /// and only with a context that has already been accepted in full.
    /// # C: O(MAXQUOTAS)
    pub(crate) fn set_opts(&self, next: crate::mount_opts::Ext4SbOpts) { *self.opts.lock() = next; }

    /// Credentials the next block allocation is charged to. # C: O(len(groups))
    pub(crate) fn alloc_cred(&self) -> crate::balloc::reserve::AllocCred {
        #[cfg(not(target_os = "oxide-kernel"))]
        if let Some(c) = self.test_cred.lock().clone() { return c; }
        crate::balloc::reserve::current_alloc_cred()
    }
}
