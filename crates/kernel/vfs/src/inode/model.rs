extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};
use sync::{Inode as InodeClass, RwLock};

use crate::file_ops::FileOps;
use crate::inode_ops::InodeOps;
use crate::mapping::AddressSpaceOps;
use crate::poll_subs::PollSubscribers;
use crate::timespec::Timespec64;
use crate::quota::InodeDquots;
use crate::superblock::SuperBlock;
use crate::types::Ino;

use super::flags::{FS_APPEND_FL, FS_CASEFOLD_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL, FS_SYNC_FL};
use super::file_lock::FileLockContext;

/// `struct inode` reference (Linux `struct inode *`). CONCRETE — one type for
/// every filesystem; behaviour comes from `i_op`/`i_fop`/`i_private`.
pub type InodeRef = Arc<Inode>;

/// memfd file-sealing store carrier.
pub trait SealCarrier: Send + Sync {
    /// The `F_*_SEALS` word (Linux `shmem_inode_info.seals`). # C: O(1)
    fn seal_word(&self) -> &AtomicU32;
}

/// Linux `F_SEAL_*` values (`include/uapi/linux/fcntl.h`).
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const F_SEAL_EXEC: u32 = 0x0020;
pub const F_ALL_SEALS: u32 = F_SEAL_SEAL
    | F_SEAL_SHRINK
    | F_SEAL_GROW
    | F_SEAL_WRITE
    | F_SEAL_FUTURE_WRITE
    | F_SEAL_EXEC;

/// Backend write-through for `chown(2)` on a SYNTHESIZED inode whose owner
/// lives in the backing store, not the in-core inode (Linux kernfs persists
/// chown to `kernfs_node->iattr` via `->setattr`; cgroupfs/sysfs re-create the
/// inode on every lookup, so a plain `i_uid`/`i_gid` store would be lost). When
/// present, [`Inode::set_owner`] invokes `persist_owner` so the new uid/gid is
/// recorded in the backend and re-applied on the next synthesis — the mechanism
/// that makes systemd cgroup delegation (chown of the delegated subtree to the
/// target uid) actually take effect. Absent (`None`) on every native-storage
/// inode, so their chown path is byte-for-byte unchanged.
pub trait OwnerPersist: Send + Sync {
    /// Record `(uid, gid)` in the backing store keyed by this inode's identity.
    /// # C: backend-dependent
    fn persist_owner(&self, uid: u32, gid: u32);
}

/// `struct inode` (`16§2`). One per in-core inode; shared by every dentry alias
/// (hardlinks) and every open `File` on it.
pub struct Inode {
    pub(super) i_ino:          Ino,
    pub(super) i_mode:         AtomicU32,
    pub(super) i_size:         AtomicU64,
    pub(super) i_blocks:       AtomicU64,
    pub(super) i_nlink:        AtomicU32,
    pub(super) i_uid:          AtomicU32,
    pub(super) i_gid:          AtomicU32,
    pub(super) i_projid:       AtomicU32,
    pub(super) i_flags:        AtomicU32,
    pub(super) i_rdev:         u32,
    pub(super) i_generation:   u32,
    // Linux `struct inode` splits each file time into a SIGNED `time64_t
    // i_atime_sec` plus an unsigned `u32 i_atime_nsec` (include/linux/fs.h) —
    // pre-1970 stamps are ordinary, and the pair spans the full `time64_t`
    // window a single ns scalar cannot. Linux's fields are plain (unlocked
    // readers may observe a half-updated pair); the Relaxed atomics here give
    // exactly that, no more.
    pub(super) i_atime_sec:    AtomicI64,
    pub(super) i_atime_nsec:   AtomicU32,
    pub(super) i_mtime_sec:    AtomicI64,
    pub(super) i_mtime_nsec:   AtomicU32,
    pub(super) i_ctime_sec:    AtomicI64,
    pub(super) i_ctime_nsec:   AtomicU32,
    /// Creation time, immutable after construction. `None` on a backend that
    /// stores none — NOT a zero sentinel, since the epoch second is itself a
    /// legal birth time.
    pub(super) i_btime:        Option<Timespec64>,
    /// Linux `i_writecount` (`include/linux/fs.h`): 0 idle, >0 = that many
    /// writers hold the file open, <0 = that many execs are running it.
    /// `get_write_access` is `atomic_inc_unless_negative`, `deny_write_access`
    /// is `atomic_dec_unless_positive` — the two directions are what make
    /// `ETXTBSY` mutual, so a running binary cannot be opened for write and a
    /// file open for write cannot be executed.
    pub(super) i_writecount:   AtomicI32,
    pub(super) i_state:        AtomicU32,
    /// Linux `inode->dirtied_time_when`: the wall-clock nanosecond at which
    /// `I_DIRTY_TIME` was first set on an otherwise-clean inode. The expiry
    /// clock for the lazy-timestamp deferral — a background writeback pass
    /// forces the stamp out once it is older than the expire interval. `0` =
    /// never dirtied-time (the epoch nanosecond is not a reachable stamp: the
    /// timestamp paths refuse to run before the wall clock is installed).
    pub(super) dirtied_time_when: AtomicU64,
    pub(super) i_count:        AtomicU32,
    pub(super) i_version:      AtomicU64,
    pub(super) i_fsid:         AtomicU64,
    /// Set when VFS instantiates this inode into an owning superblock.  Pseudo
    /// filesystems synthesize an inode before `fill_super` has allocated that
    /// instance, so construction alone cannot establish this association.
    pub(super) i_sb:           RwLock<Weak<SuperBlock>, InodeClass>,
    pub(super) i_mapping:      Option<Arc<dyn AddressSpaceOps>>,
    /// `mapping->wb_err` (Linux `struct address_space`): this inode's
    /// writeback-error latch, reported once per open description by
    /// `file_check_and_advance_wb_err`. Lives on the inode because our
    /// `i_mapping` is 1:1 with it and an address_space with no frame store
    /// still needs somewhere to record a failed flush.
    pub(super) i_wb_err:       crate::errseq::Errseq,
    /// Canonical `address_space->i_mmap` reverse-map owner. It is inode
    /// lifetime state, so separately opened file descriptors and forked VMAs
    /// cannot invent competing file-rmap objects for the same shared pages.
    pub(super) i_file_rmap:    Arc<vmm::FileRmap>,
    /// Linux `inode->i_fsnotify_marks` fast-path summary. One counter per
    /// event bit lets the notification owner answer "can this inode match?"
    /// without scanning every inotify/fanotify group in the system. Counts,
    /// rather than a lossy OR mask, make removal and mask replacement exact.
    pub(super) i_fsnotify_mask_counts: [AtomicU32; 32],
    pub(super) i_op:           Arc<dyn InodeOps>,
    pub(super) i_fop:          Arc<dyn FileOps>,
    pub(super) i_private:      Arc<dyn Any + Send + Sync>,
    pub(super) poll_subs:      Option<Arc<PollSubscribers>>,
    pub(super) seal_carrier:   Option<Arc<dyn SealCarrier>>,
    pub(super) owner_persist:  Option<Arc<dyn OwnerPersist>>,
    pub(super) i_link:         Option<Box<[u8]>>,
    pub(super) i_xattrs:       Option<crate::xattr::SimpleXattrs>,
    pub(crate) i_dquot:        InodeDquots,
    pub(super) i_rwsem:        super::rwsem::InodeRwsem,
    /// `inode->i_flctx`: single owner for BSD flock and POSIX/OFD records.
    pub(super) i_flctx:        FileLockContext,
}

impl Inode {
    /// Create this namespace object's distinct inode view for `sb`. Shared
    /// pseudo trees retain immutable operation/private state, while every
    /// superblock receives its own VFS metadata, locks, wait queues, and
    /// writeback state. # C: O(xattrs)
    pub(crate) fn clone_for_superblock(&self, sb: &Arc<SuperBlock>) -> InodeRef {
        let xattrs = self.i_xattrs.as_ref().map(|old| {
            let copy = crate::xattr::SimpleXattrs::new();
            copy.replace_all(&old.entries());
            copy
        });
        Arc::new(Inode {
            i_ino: self.i_ino,
            i_mode: AtomicU32::new(self.i_mode.load(Ordering::Relaxed)),
            i_size: AtomicU64::new(self.i_size.load(Ordering::Relaxed)),
            i_blocks: AtomicU64::new(self.i_blocks.load(Ordering::Relaxed)),
            i_nlink: AtomicU32::new(self.i_nlink.load(Ordering::Relaxed)),
            i_uid: AtomicU32::new(self.i_uid.load(Ordering::Relaxed)),
            i_gid: AtomicU32::new(self.i_gid.load(Ordering::Relaxed)),
            i_projid: AtomicU32::new(self.i_projid.load(Ordering::Relaxed)),
            i_flags: AtomicU32::new(self.i_flags.load(Ordering::Relaxed)),
            i_rdev: self.i_rdev,
            i_generation: sb.next_inode_generation(),
            i_atime_sec: AtomicI64::new(self.i_atime_sec.load(Ordering::Relaxed)),
            i_atime_nsec: AtomicU32::new(self.i_atime_nsec.load(Ordering::Relaxed)),
            i_mtime_sec: AtomicI64::new(self.i_mtime_sec.load(Ordering::Relaxed)),
            i_mtime_nsec: AtomicU32::new(self.i_mtime_nsec.load(Ordering::Relaxed)),
            i_ctime_sec: AtomicI64::new(self.i_ctime_sec.load(Ordering::Relaxed)),
            i_ctime_nsec: AtomicU32::new(self.i_ctime_nsec.load(Ordering::Relaxed)),
            i_btime: self.i_btime,
            i_writecount: AtomicI32::new(0),
            i_state: AtomicU32::new(0),
            dirtied_time_when: AtomicU64::new(0),
            i_count: AtomicU32::new(1),
            i_version: AtomicU64::new(self.i_version.load(Ordering::Relaxed)),
            i_fsid: AtomicU64::new(self.i_fsid.load(Ordering::Relaxed)),
            i_sb: RwLock::new(Arc::downgrade(sb)),
            i_mapping: self.i_mapping.clone(),
            i_wb_err: crate::errseq::Errseq::new(),
            i_file_rmap: vmm::FileRmap::new(),
            i_fsnotify_mask_counts: [const { AtomicU32::new(0) }; 32],
            i_op: Arc::clone(&self.i_op),
            i_fop: Arc::clone(&self.i_fop),
            i_private: Arc::clone(&self.i_private),
            poll_subs: self.poll_subs.as_ref().map(|_| Arc::new(PollSubscribers::new())),
            seal_carrier: self.seal_carrier.clone(),
            owner_persist: self.owner_persist.clone(),
            i_link: self.i_link.clone(),
            i_xattrs: xattrs,
            i_dquot: InodeDquots::new(),
            i_rwsem: super::rwsem::InodeRwsem::new(),
            i_flctx: FileLockContext::new(),
        })
    }
}

/// One physical extent reported by `Inode::fiemap` (Linux `struct
/// fiemap_extent`). Byte offsets/lengths, not blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FiemapExtent {
    pub logical:  u64,
    pub physical: u64,
    pub length:   u64,
    pub flags:    u32,
}

/// Inode attribute view shared by `fileattr_get`/`fileattr_set` (Linux `struct
/// fileattr`). Carries the legacy `FS_*_FL` word and Linux `fsxattr` fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileAttr {
    pub flags:          u32,
    pub fsx_xflags:     u32,
    pub fsx_extsize:    u32,
    pub fsx_nextents:   u32,
    pub fsx_projid:     u32,
    pub fsx_cowextsize: u32,
}

impl FileAttr {
    /// Translate the VFS `i_flags` (`S_*`) word into the `FS_*_FL` view. # C: O(1)
    pub fn from_i_flags(i_flags: u32) -> Self {
        let mut flags = 0;
        if i_flags & super::flags::S_IMMUTABLE != 0 { flags |= FS_IMMUTABLE_FL; }
        if i_flags & super::flags::S_APPEND    != 0 { flags |= FS_APPEND_FL; }
        if i_flags & super::flags::S_NOATIME   != 0 { flags |= FS_NOATIME_FL; }
        if i_flags & super::flags::S_SYNC      != 0 { flags |= FS_SYNC_FL; }
        if i_flags & super::flags::S_CASEFOLD  != 0 { flags |= FS_CASEFOLD_FL; }
        if i_flags & super::flags::S_NODUMP    != 0 { flags |= FS_NODUMP_FL; }
        FileAttr { flags, ..Default::default() }
    }
}
