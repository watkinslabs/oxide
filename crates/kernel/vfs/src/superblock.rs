// `struct super_block` per `16§2` — ONE per mounted filesystem instance.
//
// Linux object model (include/linux/fs.h): a superblock owns the root
// DENTRY (`s_root`), the super_operations vtable (`s_op`), the
// file_system_type backref (`s_type`), the on-disk identity
// (`s_magic`/`s_dev`/`s_blocksize`/`s_id`), backend-private state
// (`s_fs_info`), and the per-instance inode cache (iget/ilookup/iput).
//
// CYCLE NOTE: `s_root: Arc<Dentry>` is a STRONG owning ref; `Dentry::sb`
// is `Weak<SuperBlock>` (Linux `d_sb` is non-owning). The mount table
// owns the `Arc<SuperBlock>` strong ref. Umount = `put_super()` then
// clear `s_root` → the dentry tree drops, breaking what would otherwise
// be an Arc cycle.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{RwLock, Spinlock, Superblock as SbClass};

use crate::dentry::Dentry;
use crate::fs::FileSystem;
use crate::inode::{Inode, InodeRef, I_CLEAR, I_DIRTY, I_FREEING, I_NEW, I_WILL_FREE};
use crate::types::{Ino, KResult};

/// `get_anon_bdev` (Linux `fs/super.c`) — per-instance anonymous block-dev
/// id source for filesystems with no real backing device. Each mounted
/// instance gets a distinct `s_dev` so two `mount -t tmpfs` report
/// different `st_dev` (the thing a per-fs-type constant cannot express).
/// Starts above the legacy `dev_t` minor range to avoid colliding with a
/// real block device's packed `(major<<20)|minor`. # C: O(1)
static NEXT_ANON_DEV: AtomicU64 = AtomicU64::new(0x0000_0001_0000_0000);

/// Allocate a fresh anonymous device id (`get_anon_bdev`). # C: O(1)
pub fn next_anon_dev() -> u64 { NEXT_ANON_DEV.fetch_add(1, Ordering::Relaxed) }

// `s_flags` bits (Linux include/linux/fs.h). User-visible mount RO/option
// flags in the low range; lifecycle bits (`SB_BORN`/`SB_ACTIVE`) in the high
// range. `MS_*` (mount syscall) flags map onto these one-to-one in the low bits.
pub const SB_RDONLY:      u64 = 1;
pub const SB_NOSUID:      u64 = 1 << 1;
pub const SB_NODEV:       u64 = 1 << 2;
pub const SB_NOEXEC:      u64 = 1 << 3;
pub const SB_SYNCHRONOUS: u64 = 1 << 4;
pub const SB_MANDLOCK:    u64 = 1 << 6;
pub const SB_DIRSYNC:     u64 = 1 << 7;
pub const SB_NOATIME:     u64 = 1 << 10;
pub const SB_NODIRATIME:  u64 = 1 << 11;
pub const SB_SILENT:      u64 = 1 << 15;
pub const SB_POSIXACL:    u64 = 1 << 16;
pub const SB_KERNMOUNT:   u64 = 1 << 22;
pub const SB_I_VERSION:   u64 = 1 << 23;
pub const SB_LAZYTIME:    u64 = 1 << 25;
/// Internal lifecycle bits: `SB_BORN` (fill_super done), `SB_ACTIVE` (mounted).
pub const SB_BORN:   u64 = 1 << 29;
pub const SB_ACTIVE: u64 = 1 << 30;

// `s_writers.frozen` freeze levels (Linux include/linux/fs.h). `freeze_super`
// ratchets UNFROZEN → WRITE (block new write(2)) → PAGEFAULT (block mmap
// faults) → FS (on-disk `freeze_fs`) → COMPLETE; `thaw_super` resets to
// UNFROZEN. `sb_start_write` admits a writer only at UNFROZEN. Drives FIFREEZE
// + consistent-snapshot quiesce.
pub const SB_UNFROZEN:         u32 = 0;
pub const SB_FREEZE_WRITE:     u32 = 1;
pub const SB_FREEZE_PAGEFAULT: u32 = 2;
pub const SB_FREEZE_FS:        u32 = 3;
pub const SB_FREEZE_COMPLETE:  u32 = 4;

/// `MAX_LFS_FILESIZE` on a 64-bit kernel (Linux include/linux/fs.h) — the
/// default `s_maxbytes` a large-file backend reports. # C: O(1)
pub const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// `NSEC_PER_SEC` (Linux include/vdso/time64.h) — nanoseconds in one second,
/// the per-second denominator [`SuperBlock::timestamp_truncate`] floors the
/// sub-second field against. # C: O(1)
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Placeholder backend for an `s_fs`-less superblock built via
/// [`SuperBlock::new`] (the object-model unit tests). Production superblocks
/// are built via [`SuperBlock::for_backend`] and carry their real backend.
struct NullFs;
impl FileSystem for NullFs {
    fn name(&self) -> &str { "none" }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `super_operations`
/// (`s_op`). `statfs` reports the backend `magic` as `f_type`; the inode
/// `SuperBlock::statfs` then defaults `f_bsize` from `s_blocksize`. This is
/// the generic `fill_super` glue so every backend gets a working superblock
/// without a per-fs `SuperOps` impl (richer per-fs `SuperOps` layer on top).
struct FsBackedSuperOps { fs: Arc<dyn FileSystem> }
impl SuperOps for FsBackedSuperOps {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: self.fs.magic(), f_bsize: self.fs.block_size(), ..Default::default() })
    }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `file_system_type`
/// (`s_type`). `mount` is `fill_super`: build a fresh superblock over the
/// backend's root inode.
struct FsBackedType { fs: Arc<dyn FileSystem> }
impl FileSystemType for FsBackedType {
    fn name(&self) -> &str { self.fs.name() }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(self.fs.clone(), self.fs.root(),
            next_anon_dev(), String::from(self.fs.name())))
    }
}

/// `statfs(2)` payload a superblock reports (Linux `struct kstatfs`
/// subset). `f_type` mirrors `s_magic`.
#[derive(Clone, Copy, Default)]
pub struct SbStatFs {
    pub f_type:   u64,
    pub f_bsize:  u32,
    pub f_blocks: u64,
    pub f_bfree:  u64,
    pub f_bavail: u64,
    pub f_files:  u64,
    pub f_ffree:  u64,
    /// `f_fsid` — the filesystem identity (Linux packs `s_dev` here). `0` ⇒
    /// `SuperBlock::statfs` defaults it from `s_dev`.
    pub f_fsid:   u64,
    /// `f_flags` — statvfs(3) `ST_*` mount flags. Per-MOUNT, not an
    /// `s_op->statfs` output (Linux `calculate_f_flags`, fs/statfs.c): left `0`
    /// by `SuperBlock::statfs`, filled at the syscall layer where the owning
    /// mount is in hand.
    pub f_flags:  u64,
}

/// `super_operations` (Linux `struct super_operations`) — the per-SB
/// vtable. `alloc_inode`/`destroy_inode` are handled by the backend's
/// `iget` builder + the icache `Weak` reclaim, so the trait carries the
/// remaining lifecycle ops.
pub trait SuperOps: Send + Sync {
    /// `statfs`/`fstatfs` backend. # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs>;
    /// `sync_fs` — flush dirty state. Default no-op (pseudo-fs). # C: FS-dependent
    fn sync_fs(&self, _wait: bool) -> KResult<()> { Ok(()) }
    /// `freeze_fs` — quiesce on-disk state for a consistent snapshot (FIFREEZE).
    /// Called once writers are blocked and dirty state synced. Default no-op
    /// (pseudo-fs with no backing store). # C: FS-dependent
    fn freeze_fs(&self) -> KResult<()> { Ok(()) }
    /// `unfreeze_fs`/`thaw_fs` — resume after a freeze (FITHAW). Default no-op.
    /// # C: FS-dependent
    fn thaw_fs(&self) -> KResult<()> { Ok(()) }
    /// `put_super` — last-umount teardown. Default no-op. # C: O(1)
    fn put_super(&self) {}
}

/// `file_system_type` (Linux `struct file_system_type`) — the registry
/// entry split out of today's monolithic `FileSystem` trait. `mount`
/// is `fill_super`: it builds a fresh `SuperBlock` instance.
pub trait FileSystemType: Send + Sync {
    /// FS-type name: `"ext4"`, `"tmpfs"`. # C: O(1)
    fn name(&self) -> &str;
    /// Build a superblock instance (`fill_super`). # C: FS-dependent
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>>;
}

/// `struct super_block`. One per mounted fs instance (`16§2` inv 3).
pub struct SuperBlock {
    /// `s_op` — super_operations vtable.
    pub s_op: Arc<dyn SuperOps>,
    /// `s_type` — file_system_type backref.
    pub s_type: Arc<dyn FileSystemType>,
    /// `s_magic` (linux/magic.h) reported by statfs `f_type`.
    pub s_magic: u64,
    /// `s_dev` — the `st_dev` every inode on this SB reports.
    pub s_dev: u64,
    /// `s_blocksize`.
    pub s_blocksize: u32,
    /// `s_flags` — mount RO/option bits + lifecycle (`SB_BORN`/`SB_ACTIVE`).
    /// Atomic so a future sb-level remount (`remount_fs`) flips `SB_RDONLY`
    /// without rebuilding the SB. # consumers: D16 remount.
    s_flags: AtomicU64,
    /// `s_active` — active reference count (Linux `super_block.s_active`). A
    /// freshly filled+mounted SB starts at 1; each extra live mount sharing this
    /// instance (sget reuse / bind clone) grabs one via [`SuperBlock::grab_active`]
    /// (`atomic_inc_not_zero`). [`SuperBlock::deactivate_super`] drops one, and
    /// the LAST drop (1→0) runs `generic_shutdown_super` (sync + `put_super`).
    /// This is the refcount the mount table's O(N) `Arc::ptr_eq` scan stands in
    /// for (mount.rs D6). # consumers: D6 last-umount teardown, sget sb sharing.
    s_active: AtomicU32,
    /// `s_maxbytes` — largest file size this fs can represent (write-path cap).
    pub s_maxbytes: u64,
    /// `s_time_gran` — timestamp granularity in ns (Linux `sb->s_time_gran`),
    /// set at `fill_super` ([`SuperBlock::set_time_gran`]) and consulted by
    /// [`SuperBlock::timestamp_truncate`] to floor inode atime/mtime/ctime to
    /// what the backend can persist (ext4 1ns, ext2/FAT 1s/2s). Atomic to match
    /// this struct's other mount-time-mutable fields and allow a remount/fill to
    /// publish it without rebuilding the SB. # consumers: inode setattr rounding.
    s_time_gran: AtomicU32,
    /// `s_writers.frozen` — current freeze level (`SB_UNFROZEN`..`SB_FREEZE_COMPLETE`).
    /// `freeze_super`/`thaw_super` ratchet it; `sb_start_write` gates on it.
    s_writers_frozen: AtomicU32,
    /// In-flight `sb_start_write` holders (write/pagefault). `freeze_super`
    /// blocks NEW writers via the level then drains these (Linux percpu_rwsem
    /// write-side); a future blocking layer waits on it. # consumers: freeze drain.
    s_writers_count: AtomicU32,
    /// `s_id` — `"/dev/vda1"`, `"tmpfs"`; `/proc/mounts` source column.
    pub s_id: String,
    /// `s_uuid` (Linux `super_block.s_uuid`, a `uuid_t`) + `s_uuid_len` — the
    /// on-disk filesystem UUID a backend reads from its superblock at
    /// `fill_super` ([`SuperBlock::set_uuid`]). All-zero / `len == 0` ⇒ the fs
    /// has no UUID (the `for_backend` default). Consumed by `name_to_handle_at`
    /// FID generation and the `STATX_ATTR`/`/proc` UUID display. Locked because
    /// it is set after construction (like `s_root`) without rebuilding the SB.
    s_uuid: Spinlock<([u8; 16], u8), SbClass>,
    /// `s_root` — the ROOT DENTRY (strong; see CYCLE NOTE).
    s_root: RwLock<Option<Arc<Dentry>>, SbClass>,
    /// `s_fs_info` — backend-private state (ext4 sb / tmpfs arena).
    s_fs_info: Arc<dyn Any + Send + Sync>,
    /// The legacy `Arc<dyn FileSystem>` backend carrying the write/inode ops
    /// (`create`/`unlink`/`link`/`rename`/`root`/`mounts_line`) that
    /// `SuperOps`/`FileSystemType` do not. The mount table reaches the
    /// backend through `sb.fs()`. `NullFs` for an `s_fs`-less test SB.
    s_fs: Arc<dyn FileSystem>,
    /// Per-instance inode cache (`iget`/`ilookup`/`iput`) keyed by `ino`.
    /// Each slot is an [`IcacheEntry`] carrying a `Weak` to the inode (so it
    /// reclaims when its last `Arc` drops), the inode's `i_dentry` ALIAS list
    /// (the dentries pointing at this inode, Linux `inode->i_dentry`), and
    /// the `i_state` lifecycle bits — all kept icache-side so the trait-object
    /// inodes need no shared state block.
    icache: Spinlock<BTreeMap<Ino, IcacheEntry>, SbClass>,
}

/// One inode-cache slot. `Weak` everywhere so the cache never keeps an inode
/// or dentry alive past its last strong ref (Linux dcache/icache are weak
/// w.r.t. their objects). A stale slot (dead inode + no live aliases) is
/// reclaimed on the next touch.
struct IcacheEntry {
    /// The cached inode (Linux `struct inode`). `Weak` → reclaim on last drop.
    inode:   Weak<dyn Inode>,
    /// `i_dentry` — the dentry aliases for this inode (hardlinks share one
    /// inode, many dentries). `Weak` so `d_drop` / dentry teardown reclaims.
    aliases: Vec<Weak<Dentry>>,
    /// `i_state` (`I_NEW`/`I_DIRTY`/`I_FREEING`).
    state:   u32,
    /// `i_nlink` (Linux `inode->__i_nlink`) — the inode's authoritative hard-link
    /// count. The trait-object inode carries no shared count field, so the live
    /// link count lives icache-side here, seeded from `Inode::nlink()` when the
    /// slot is built and thereafter maintained by `set_nlink`/`inc_nlink`/
    /// `drop_nlink`. A drop to `0` is the Linux "no names left → evict on last
    /// `iput`" predicate (`i_nlink == 0`).
    nlink:   u32,
}

impl SuperBlock {
    /// Construct a superblock with no root yet. The backend then builds
    /// the root inode (with `i_sb = sb`) and calls `dcache::d_make_root`,
    /// which installs `s_root`.
    /// # C: O(1)
    pub fn new(
        s_type: Arc<dyn FileSystemType>,
        s_op: Arc<dyn SuperOps>,
        s_magic: u64,
        s_dev: u64,
        s_blocksize: u32,
        s_id: String,
        s_fs_info: Arc<dyn Any + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize,
            s_flags: AtomicU64::new(SB_ACTIVE | SB_BORN),
            s_active: AtomicU32::new(1),
            s_maxbytes: MAX_LFS_FILESIZE,
            s_time_gran: AtomicU32::new(1),
            s_writers_frozen: AtomicU32::new(SB_UNFROZEN),
            s_writers_count: AtomicU32::new(0),
            s_id,
            s_uuid: Spinlock::new(([0u8; 16], 0)),
            s_root: RwLock::new(None),
            s_fs_info,
            s_fs: Arc::new(NullFs),
            icache: Spinlock::new(BTreeMap::new()),
        })
    }

    /// `fill_super` for a legacy `Arc<dyn FileSystem>` backend: build a fresh
    /// superblock whose `s_op`/`s_type` adapt the backend, `s_magic` is
    /// `fs.magic()`, `s_dev` is the per-instance anon dev, and whose `s_root`
    /// dentry is installed over `root_inode` (the bind/whole-fs root). Every
    /// production mount is allocated here (Linux `mount_bdev`/`mount_nodev`).
    /// # C: O(1)
    pub fn for_backend(
        fs: Arc<dyn FileSystem>,
        root_inode: Option<InodeRef>,
        s_dev: u64,
        s_id: String,
    ) -> Arc<Self> {
        // `fill_super` installs the backend's own `super_operations` when it
        // publishes one (ext4 → live on-disk block/inode accounting); else the
        // generic adapter reporting `f_type`/`f_bsize` only.
        let s_op: Arc<dyn SuperOps> = fs.super_ops()
            .unwrap_or_else(|| Arc::new(FsBackedSuperOps { fs: fs.clone() }));
        let s_type: Arc<dyn FileSystemType> = Arc::new(FsBackedType { fs: fs.clone() });
        let s_magic = fs.magic();
        let s_blocksize = fs.block_size();
        let sb = Arc::new(Self {
            s_op, s_type, s_magic, s_dev, s_blocksize,
            s_flags: AtomicU64::new(SB_ACTIVE | SB_BORN),
            s_active: AtomicU32::new(1),
            s_maxbytes: MAX_LFS_FILESIZE,
            s_time_gran: AtomicU32::new(1),
            s_writers_frozen: AtomicU32::new(SB_UNFROZEN),
            s_writers_count: AtomicU32::new(0),
            s_id,
            s_uuid: Spinlock::new(([0u8; 16], 0)),
            s_root: RwLock::new(None),
            s_fs_info: Arc::new(()),
            s_fs: fs,
            icache: Spinlock::new(BTreeMap::new()),
        });
        // `fill_super`: back-stamp the SB into the backend's per-mount state
        // BEFORE building the root dentry, so the root inode's `i_sb()` (and
        // every inode the backend builds afterwards) resolves to this SB.
        sb.s_fs.set_sb(Arc::downgrade(&sb));
        if let Some(i) = root_inode { crate::dcache::d_make_root(i, &sb); }
        sb
    }

    /// The backend (Linux: the SB's write/inode-op carrier). # C: O(1)
    pub fn fs(&self) -> &Arc<dyn FileSystem> { &self.s_fs }

    /// The root dentry of this instance (Linux `sb->s_root`). # C: O(1)
    pub fn s_root(&self) -> Option<Arc<Dentry>> { self.s_root.read().clone() }

    /// Root inode behind `s_root` (Linux `sb->s_root->d_inode`). # C: O(1)
    pub fn s_root_inode(&self) -> Option<InodeRef> {
        self.s_root().and_then(|d| d.inode())
    }

    /// Install `s_root` (called by `d_make_root`). # C: O(1)
    pub fn set_s_root(&self, root: Arc<Dentry>) { *self.s_root.write() = Some(root); }

    /// Backend-private state downcast. # C: O(1)
    pub fn fs_info(&self) -> &Arc<dyn Any + Send + Sync> { &self.s_fs_info }

    /// `ilookup` — hit the inode cache. `None` if absent, reclaimed, OR dying
    /// (`I_FREEING`/`I_WILL_FREE`): Linux `find_inode_fast` skips a dying inode
    /// and waits for it to leave the cache rather than handing back a
    /// half-evicted object, so a freeing slot reads as a miss here too.
    /// # C: O(log N_ino)
    pub fn ilookup(&self, ino: Ino) -> Option<InodeRef> {
        let c = self.icache.lock();
        let e = c.get(&ino)?;
        if e.state & (I_FREEING | I_WILL_FREE) != 0 { return None; }
        e.inode.upgrade()
    }

    /// `iget` — cache hit (SAME `Arc` → shared inode identity), else build via
    /// the backend closure and cache a `Weak`. The build-miss slot is created
    /// with `I_NEW` then immediately cleared (Linux `unlock_new_inode`); a
    /// concurrent `ilookup` upgrades the fully-built `Arc` and wins. A slot
    /// whose `Weak` went stale (existing aliases all dead too) is replaced.
    /// # C: O(log N_ino)
    pub fn iget(&self, ino: Ino, build: impl FnOnce() -> InodeRef) -> InodeRef {
        if let Some(i) = self.ilookup(ino) { return i; }
        let inode = build();
        let mut c = self.icache.lock();
        if let Some(e) = c.get(&ino) {
            // A dying slot (`I_FREEING`/`I_WILL_FREE`) is past resurrection
            // (Linux `find_inode_fast` skips it); rebuild over it instead of
            // handing back the half-evicted inode.
            if e.state & (I_FREEING | I_WILL_FREE) == 0 {
                if let Some(existing) = e.inode.upgrade() { return existing; }
            }
        }
        // Preserve any still-live aliases recorded against this ino while the
        // inode was momentarily un-cached; they re-bind to the rebuilt inode.
        let aliases = c.get(&ino).map(|e| {
            e.aliases.iter().filter(|w| w.upgrade().is_some()).cloned().collect::<Vec<_>>()
        }).unwrap_or_default();
        c.insert(ino, IcacheEntry {
            inode: Arc::downgrade(&inode), aliases, state: I_NEW, nlink: inode.nlink(),
        });
        if let Some(e) = c.get_mut(&ino) { e.state &= !I_NEW; } // unlock_new_inode
        inode
    }

    /// `iput`/reclaim hook — drop a cache slot whose inode is gone.
    /// # C: O(log N_ino)
    pub fn iforget(&self, ino: Ino) { self.icache.lock().remove(&ino); }

    /// `s_inodes` (Linux `super_block.s_inodes`) — every LIVE inode resident on
    /// this superblock, in `ino` order (the icache is an `ino`-keyed `BTreeMap`,
    /// so iteration is naturally ordered). Slots whose `Weak` no longer upgrades
    /// (the inode's last `Arc` already dropped) are skipped — Linux's list holds
    /// only resident inodes. This is the set the per-sb sweeps walk
    /// ([`Self::evict_inodes`], [`Self::drop_caches`], writeback, quota,
    /// fsnotify). # C: O(N_ino)
    pub fn s_inodes(&self) -> Vec<InodeRef> {
        self.icache.lock().values().filter_map(|e| e.inode.upgrade()).collect()
    }

    /// Cached inode-slot count on this superblock (Linux per-sb `nr_inodes`).
    /// Counts every slot including a stale `Weak` not yet reclaimed, so it is the
    /// icache occupancy, not the live-inode count ([`Self::s_inodes`]`.len()`).
    /// # C: O(1)
    pub fn nr_cached_inodes(&self) -> usize { self.icache.lock().len() }

    /// Walk the `s_inodes` list applying `f` to every LIVE inode in `ino` order
    /// (Linux `inode_sb_list` walk behind quota/fsnotify/`sync` sweeps). Snapshots
    /// the live set FIRST and releases the icache lock before invoking `f`, so a
    /// callback may safely re-enter the SB (`iget`/`ilookup`) without
    /// self-deadlock — Linux's equivalent `igrab`s then drops `s_inode_list_lock`
    /// across the body. # C: O(N_ino)
    pub fn for_each_inode(&self, mut f: impl FnMut(&InodeRef)) {
        for i in self.s_inodes() { f(&i); }
    }

    /// `i_state` bits for `ino` (`I_NEW`/`I_DIRTY`/`I_FREEING`); `0` if not
    /// cached. # C: O(log N_ino)
    pub fn i_state(&self, ino: Ino) -> u32 {
        self.icache.lock().get(&ino).map(|e| e.state).unwrap_or(0)
    }

    /// Set/clear `i_state` bits for `ino` (no-op if uncached). # C: O(log N_ino)
    pub fn i_set_state(&self, ino: Ino, set: u32, clear: u32) {
        if let Some(e) = self.icache.lock().get_mut(&ino) {
            e.state = (e.state & !clear) | set;
        }
    }

    /// True iff `ino` is being evicted — Linux's pervasive
    /// `(i_state & (I_FREEING | I_WILL_FREE))` dying-inode predicate
    /// (`find_inode_fast`, `iput`, `evict`). A slot in this state is past
    /// resurrection: `ilookup` reports it as a miss and `iget` rebuilds over it.
    /// `false` for an uncached ino (`i_state` reads `0`). # C: O(log N_ino)
    pub fn i_is_freeing(&self, ino: Ino) -> bool {
        self.i_state(ino) & (I_FREEING | I_WILL_FREE) != 0
    }

    /// `inode->i_nlink` — the cached hard-link count for `ino`. `None` if the
    /// inode is not cached. The slot is seeded from `Inode::nlink()` when built,
    /// then maintained by [`Self::set_nlink`]/[`Self::inc_nlink`]/
    /// [`Self::drop_nlink`]. A `Some(0)` result is the Linux evict predicate
    /// (`i_nlink == 0`): the inode has no remaining names and is freed on its
    /// last `iput`. # C: O(log N_ino)
    pub fn i_nlink(&self, ino: Ino) -> Option<u32> {
        self.icache.lock().get(&ino).map(|e| e.nlink)
    }

    /// True iff `ino` is an eviction candidate — cached with `i_nlink == 0`
    /// (Linux `iput_final` drops/evicts an inode whose last reference goes while
    /// `i_nlink == 0`). `false` for an uncached ino. # C: O(log N_ino)
    pub fn i_nlink_zero(&self, ino: Ino) -> bool {
        self.i_nlink(ino) == Some(0)
    }

    /// `set_nlink` (Linux fs/inode.c): set `ino`'s stored link count to `nlink`.
    /// `0` clears it to the dead state (Linux `clear_nlink`); a nonzero value
    /// directly installs the count, including the legitimate `0 → 1` revival some
    /// filesystems perform. No-op if uncached. # C: O(log N_ino)
    pub fn set_nlink(&self, ino: Ino, nlink: u32) {
        if let Some(e) = self.icache.lock().get_mut(&ino) { e.nlink = nlink; }
    }

    /// `inc_nlink` (Linux fs/inode.c): add one hard link to `ino`'s stored count,
    /// reviving a `0`-count inode (the O_TMPFILE `linkat` `I_LINKABLE` case). The
    /// count saturates rather than wrapping. No-op if uncached. # C: O(log N_ino)
    pub fn inc_nlink(&self, ino: Ino) {
        if let Some(e) = self.icache.lock().get_mut(&ino) { e.nlink = e.nlink.saturating_add(1); }
    }

    /// `drop_nlink` (Linux fs/inode.c): remove one hard link from `ino`'s stored
    /// count. Reaching `0` makes the inode an eviction candidate (observable via
    /// [`Self::i_nlink_zero`] / [`Self::i_nlink`]). Saturates at `0` rather than
    /// underflowing (Linux WARNs on a drop below zero; the count never wraps).
    /// No-op if uncached. # C: O(log N_ino)
    pub fn drop_nlink(&self, ino: Ino) {
        if let Some(e) = self.icache.lock().get_mut(&ino) { e.nlink = e.nlink.saturating_sub(1); }
    }

    /// `mark_inode_dirty` (Linux `__mark_inode_dirty`): OR the requested
    /// `I_DIRTY_*` bits into `ino`'s state. `flags` is masked to `I_DIRTY` so a
    /// caller cannot smuggle a lifecycle bit (`I_NEW`/`I_FREEING`/…) through the
    /// dirtying path. No-op if uncached. # C: O(log N_ino)
    pub fn mark_inode_dirty(&self, ino: Ino, flags: u32) {
        self.i_set_state(ino, flags & I_DIRTY, 0);
    }

    /// `clear_inode` (Linux fs/inode.c): the terminal eviction state. Sets
    /// `I_FREEING | I_CLEAR` and drops every dirty bit — the inode's metadata is
    /// gone and no writeback will follow. # C: O(log N_ino)
    pub fn clear_inode(&self, ino: Ino) {
        self.i_set_state(ino, I_FREEING | I_CLEAR, I_DIRTY);
    }

    /// Record `d` as an alias of `inode` (Linux `d_instantiate` →
    /// `inode->i_dentry`). Creates/refreshes the icache slot if needed so an
    /// inode that was built ad-hoc (not via `iget`) still tracks its dentries.
    /// Idempotent: an already-listed live alias is not duplicated; dead alias
    /// `Weak`s are pruned on touch. # C: O(N_aliases)
    pub fn i_add_alias(&self, inode: &InodeRef, d: &Arc<Dentry>) {
        let ino = inode.ino();
        let mut c = self.icache.lock();
        let e = c.entry(ino).or_insert_with(|| IcacheEntry {
            inode: Arc::downgrade(inode), aliases: Vec::new(), state: 0, nlink: inode.nlink(),
        });
        if e.inode.upgrade().is_none() { e.inode = Arc::downgrade(inode); }
        e.aliases.retain(|w| match w.upgrade() { Some(a) => !Arc::ptr_eq(&a, d), None => false });
        e.aliases.push(Arc::downgrade(d));
    }

    /// Drop `d` from `ino`'s alias list (Linux `d_drop`/dentry teardown). If
    /// the slot is then empty AND the inode is gone, reclaim it.
    /// # C: O(N_aliases)
    pub fn i_drop_alias(&self, ino: Ino, d: &Arc<Dentry>) {
        let mut c = self.icache.lock();
        let gone = if let Some(e) = c.get_mut(&ino) {
            e.aliases.retain(|w| match w.upgrade() { Some(a) => !Arc::ptr_eq(&a, d), None => false });
            e.aliases.is_empty() && e.inode.upgrade().is_none()
        } else { false };
        if gone { c.remove(&ino); }
    }

    /// Live dentry aliases of `ino` (Linux walk of `inode->i_dentry`).
    /// # C: O(N_aliases)
    pub fn i_aliases(&self, ino: Ino) -> Vec<Arc<Dentry>> {
        self.icache.lock().get(&ino)
            .map(|e| e.aliases.iter().filter_map(Weak::upgrade).collect())
            .unwrap_or_default()
    }

    /// `evict_inodes` (Linux fs/inode.c, run from `generic_shutdown_super`):
    /// sweep the per-SB inode cache evicting every inode with no remaining
    /// reference. In this `Weak`-keyed icache a referenceless inode is one whose
    /// `Weak::upgrade` already fails (Linux `i_count == 0`); its slot — and any
    /// dead alias `Weak`s — are dropped. Returns the count of BUSY inodes:
    /// slots whose inode still upgrades, i.e. a live reference outlived the
    /// unmount (Linux's "VFS: Busy inodes after unmount" WARN). A clean unmount
    /// returns `0`. Busy slots are retained, not force-freed: their owners drop
    /// them on their own ref release. # C: O(N_ino)
    pub fn evict_inodes(&self) -> u32 {
        let mut busy = 0u32;
        self.icache.lock().retain(|_, e| {
            if e.inode.upgrade().is_some() { busy += 1; true } else { false }
        });
        busy
    }

    /// statfs via `s_op`, defaulting `f_type`/`f_bsize` from the SB.
    /// # C: O(1)
    pub fn statfs(&self) -> KResult<SbStatFs> {
        let mut st = self.s_op.statfs()?;
        if st.f_type == 0 { st.f_type = self.s_magic; }
        if st.f_bsize == 0 { st.f_bsize = self.s_blocksize; }
        if st.f_fsid == 0 { st.f_fsid = self.s_dev; }
        Ok(st)
    }

    /// `s_flags` snapshot (Linux `sb->s_flags`). # C: O(1)
    pub fn s_flags(&self) -> u64 { self.s_flags.load(Ordering::Acquire) }

    /// Set/clear `s_flags` bits (sb-level remount; `SB_RDONLY` toggle). # C: O(1)
    pub fn set_s_flags(&self, set: u64, clear: u64) {
        let mut cur = self.s_flags.load(Ordering::Acquire);
        loop {
            let new = (cur & !clear) | set;
            match self.s_flags.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break, Err(v) => cur = v,
            }
        }
    }

    /// True iff this superblock is mounted read-only (`SB_RDONLY`). # C: O(1)
    pub fn is_readonly(&self) -> bool { (self.s_flags() & SB_RDONLY) != 0 }

    /// `sb_rdonly` (Linux include/linux/fs.h) — explicit-name alias of
    /// [`Self::is_readonly`] for call sites that read better as the kernel
    /// predicate. # C: O(1)
    pub fn sb_rdonly(&self) -> bool { self.is_readonly() }

    /// True iff `flag` (any `SB_*` bit, e.g. `SB_NOSUID`) is set in `s_flags`.
    /// The generic form behind the named `is_*` predicates. # C: O(1)
    pub fn sb_has_flag(&self, flag: u64) -> bool { (self.s_flags() & flag) != 0 }

    /// `SB_NOSUID` — setuid/setgid bits ignored on this mount (Linux `IS_NOSUID`,
    /// consulted by exec credential elevation). # C: O(1)
    pub fn is_nosuid(&self) -> bool { self.sb_has_flag(SB_NOSUID) }

    /// `SB_NODEV` — device-special files do not function on this mount
    /// (Linux `may_open` rejects opening a dev node). # C: O(1)
    pub fn is_nodev(&self) -> bool { self.sb_has_flag(SB_NODEV) }

    /// `SB_NOEXEC` — no `execve` from this mount (Linux `path_noexec`). # C: O(1)
    pub fn is_noexec(&self) -> bool { self.sb_has_flag(SB_NOEXEC) }

    /// `SB_SYNCHRONOUS` — writes commit synchronously (Linux `IS_SYNC`). # C: O(1)
    pub fn is_synchronous(&self) -> bool { self.sb_has_flag(SB_SYNCHRONOUS) }

    /// `SB_MANDLOCK` — mandatory locking permitted (Linux `IS_MANDLOCK`). # C: O(1)
    pub fn is_mandlock(&self) -> bool { self.sb_has_flag(SB_MANDLOCK) }

    /// `SB_DIRSYNC` — directory updates commit synchronously (Linux `IS_DIRSYNC`).
    /// # C: O(1)
    pub fn is_dirsync(&self) -> bool { self.sb_has_flag(SB_DIRSYNC) }

    /// `SB_NOATIME` — never update access times on this mount (Linux the
    /// `MNT_NOATIME`/`SB_NOATIME` half of `atime_needs_update`). # C: O(1)
    pub fn is_noatime(&self) -> bool { self.sb_has_flag(SB_NOATIME) }

    /// `SB_NODIRATIME` — never update directory access times. # C: O(1)
    pub fn is_nodiratime(&self) -> bool { self.sb_has_flag(SB_NODIRATIME) }

    /// `SB_POSIXACL` — backend honours POSIX ACLs (Linux `IS_POSIXACL`, gates
    /// the `acl`-aware permission path). # C: O(1)
    pub fn is_posixacl(&self) -> bool { self.sb_has_flag(SB_POSIXACL) }

    /// `SB_I_VERSION` — auto-maintain the inode change cookie (Linux
    /// `IS_I_VERSION`, gates `inode_maybe_inc_iversion`). # C: O(1)
    pub fn is_i_version(&self) -> bool { self.sb_has_flag(SB_I_VERSION) }

    /// `SB_LAZYTIME` — defer on-disk timestamp writeback (Linux `IS_LAZYTIME`).
    /// # C: O(1)
    pub fn is_lazytime(&self) -> bool { self.sb_has_flag(SB_LAZYTIME) }

    /// `SB_KERNMOUNT` — internal kernel mount, not user-initiated (Linux
    /// `kern_mount`); excluded from user umount accounting. # C: O(1)
    pub fn is_kernmount(&self) -> bool { self.sb_has_flag(SB_KERNMOUNT) }

    /// `SB_BORN` — `fill_super` has completed; the instance is fully built and
    /// safe to publish (Linux `super_block.SB_BORN`). # C: O(1)
    pub fn is_born(&self) -> bool { self.sb_has_flag(SB_BORN) }

    /// `SB_ACTIVE` — the instance is mounted/live; cleared by
    /// `generic_shutdown_super` at last-umount so no operation treats a tearing-
    /// down SB as mounted (Linux `super_block.SB_ACTIVE`). Distinct from the
    /// `s_active` REFCOUNT ([`Self::s_active`]): this is the published mounted
    /// FLAG. # C: O(1)
    pub fn is_mounted(&self) -> bool { self.sb_has_flag(SB_ACTIVE) }

    /// Flip the `SB_RDONLY` bit (sb-level `remount` RO↔RW toggle, Linux
    /// `reconfigure_super` rewriting `sb->s_flags`). Once set, [`sb_start_write`]
    /// refuses every new writer so a write(2)/page-fault path cannot dirty a
    /// read-only mount. # C: O(1)
    pub fn set_readonly(&self, ro: bool) {
        if ro { self.set_s_flags(SB_RDONLY, 0); } else { self.set_s_flags(0, SB_RDONLY); }
    }

    /// `s_active` snapshot — live active references (Linux `s->s_active`).
    /// `0` ⇒ the SB is being / has been torn down. # C: O(1)
    pub fn s_active(&self) -> u32 { self.s_active.load(Ordering::Acquire) }

    /// `grab_super` (Linux `atomic_inc_not_zero(&s->s_active)`): take one extra
    /// active reference IFF the SB is still live (count != 0). Returns `false`
    /// once teardown has begun so an sget-style lookup never resurrects a dying
    /// instance and bind/sharing callers fall through to a fresh `for_backend`.
    /// Each `true` MUST be paired with a [`SuperBlock::deactivate_super`].
    /// # C: O(1)
    pub fn grab_active(&self) -> bool {
        let mut cur = self.s_active.load(Ordering::Acquire);
        loop {
            if cur == 0 { return false; }
            match self.s_active.compare_exchange_weak(
                cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true, Err(v) => cur = v,
            }
        }
    }

    /// `deactivate_super` (Linux `atomic_dec_and_test(&s->s_active)`): drop one
    /// active reference. The LAST drop (1 → 0) runs `generic_shutdown_super`
    /// (`sync_filesystem` then `put_super`, clearing `s_root`+icache) and returns
    /// `true`; a non-last drop returns `false`. Idempotent at 0 (a redundant
    /// deactivate is a no-op returning `false`, never an unsigned underflow), so
    /// the teardown body fires exactly once. # C: O(tree) on last, else O(1)
    pub fn deactivate_super(&self) -> bool {
        let mut cur = self.s_active.load(Ordering::Acquire);
        loop {
            if cur == 0 { return false; }
            match self.s_active.compare_exchange_weak(
                cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break, Err(v) => cur = v,
            }
        }
        if cur == 1 { let _ = self.generic_shutdown_super(); true } else { false }
    }

    /// `s_maxbytes` — largest representable file size. # C: O(1)
    pub fn s_maxbytes(&self) -> u64 { self.s_maxbytes }

    /// `generic_write_check_limits` (Linux fs/read_write.c), the `s_maxbytes`
    /// half: bound a write of `count` bytes starting at byte offset `pos`
    /// against the largest file size this filesystem can represent.
    /// - `Some(n)` ⇒ the write is admissible; `n` is `count` CLAMPED so
    ///   `pos + n <= s_maxbytes` (a write that would straddle the cap is
    ///   shortened, exactly like Linux clamps `iov_iter` to `max_size - pos`).
    /// - `None` ⇒ `pos >= s_maxbytes`: there is no room at or beyond the cap,
    ///   which the write(2) shim maps to `EFBIG` (+ `SIGXFSZ`). A zero-length
    ///   write short-circuits to `Some(0)` (Linux returns `0` before the cap
    ///   check), so an empty write at the cap is not spuriously rejected.
    /// The per-task `RLIMIT_FSIZE` half of `generic_write_check_limits` lives at
    /// the syscall layer (it needs the caller's rlimits); this is the SB-level
    /// physical-size cap only. # C: O(1)
    pub fn generic_write_check_limits(&self, pos: u64, count: usize) -> Option<usize> {
        if count == 0 { return Some(0); }
        let max = self.s_maxbytes;
        if pos >= max { return None; }
        let room = max - pos; // > 0
        Some(core::cmp::min(count as u64, room) as usize)
    }

    /// True iff a write STARTING at byte offset `pos` must fail `EFBIG` —
    /// `pos >= s_maxbytes`, no representable room remains (Linux the
    /// `pos >= max_size` arm of `generic_write_check_limits`). # C: O(1)
    pub fn write_exceeds_maxbytes(&self, pos: u64) -> bool { pos >= self.s_maxbytes }

    /// `s_uuid` snapshot (Linux `super_block.s_uuid`). All-zero when the fs has
    /// no UUID; pair with [`Self::has_uuid`] to distinguish "no UUID" from the
    /// (legitimate but vanishingly rare) all-zero UUID. # C: O(1)
    pub fn s_uuid(&self) -> [u8; 16] { self.s_uuid.lock().0 }

    /// `s_uuid_len` — the significant byte length of `s_uuid` (`16` for a v4
    /// UUID, `0` when unset). Linux `super_block.s_uuid_len`. # C: O(1)
    pub fn s_uuid_len(&self) -> u8 { self.s_uuid.lock().1 }

    /// True iff a non-empty UUID has been published (`s_uuid_len != 0`). # C: O(1)
    pub fn has_uuid(&self) -> bool { self.s_uuid.lock().1 != 0 }

    /// Publish the filesystem UUID (Linux `super_set_uuid` / a `fill_super`
    /// writing `sb->s_uuid` from the on-disk superblock). `len` is clamped to
    /// the 16-byte `uuid_t` width; the unused tail is zero-filled so a short
    /// UUID never leaks stale bytes. # C: O(1)
    pub fn set_uuid(&self, uuid: [u8; 16], len: u8) {
        let len = if len > 16 { 16 } else { len };
        let mut g = self.s_uuid.lock();
        g.0 = [0u8; 16];
        g.0[..len as usize].copy_from_slice(&uuid[..len as usize]);
        g.1 = len;
    }

    /// `s_time_gran` — timestamp granularity (ns). # C: O(1)
    pub fn s_time_gran(&self) -> u32 { self.s_time_gran.load(Ordering::Acquire) }

    /// Publish the fs timestamp granularity (Linux `fill_super` writing
    /// `sb->s_time_gran`). A backend that persists coarser-than-ns times calls
    /// this once after [`SuperBlock::for_backend`] so [`Self::timestamp_truncate`]
    /// floors to it. `0` is normalized to `1` (ns precision) so the truncation
    /// math never divides by zero. # C: O(1)
    pub fn set_time_gran(&self, gran: u32) {
        self.s_time_gran.store(if gran == 0 { 1 } else { gran }, Ordering::Release);
    }

    /// `timestamp_truncate` (Linux fs/inode.c): round a wall-clock timestamp
    /// (`t_ns`, nanoseconds since the epoch — the inode atime/mtime/ctime
    /// representation) DOWN to this superblock's `s_time_gran`, so a setattr
    /// never records sub-granularity precision the backend cannot persist.
    /// `gran <= 1` is the identity (full ns); `gran >= NSEC_PER_SEC` floors to a
    /// whole second; an in-between granularity truncates the sub-second
    /// remainder to a `gran` multiple. Truncation is confined to the sub-second
    /// field (Linux truncates `tv_nsec` only), so a coarse `gran` whose value is
    /// not a divisor of `NSEC_PER_SEC` never perturbs the seconds count.
    /// # C: O(1)
    pub fn timestamp_truncate(&self, t_ns: u64) -> u64 {
        let gran = self.s_time_gran() as u64;
        if gran <= 1 { return t_ns; }
        let sec = t_ns / NSEC_PER_SEC;
        let nsec = t_ns % NSEC_PER_SEC;
        let nsec = if gran >= NSEC_PER_SEC { 0 } else { nsec - nsec % gran };
        sec * NSEC_PER_SEC + nsec
    }

    /// `s_op->sync_fs` one pass (Linux `__sync_filesystem` inner call). The
    /// two-phase [`Self::sync_filesystem`] wrapper drives the async-then-wait
    /// sequence; the freeze path issues the wait pass directly. # C: O(dirty)
    pub fn sync_fs(&self, wait: bool) -> KResult<()> { self.s_op.sync_fs(wait) }

    /// `sync_filesystem` (Linux fs/sync.c): flush this superblock's dirty state
    /// to the backend in the canonical two-phase order — an async kick
    /// (`sync_fs(wait=0)`, Linux `writeback_inodes_sb` + `sync_fs(0)`) followed by
    /// the blocking pass (`sync_fs(wait=1)`, Linux `sync_inodes_sb` + `sync_fs(1)`)
    /// that waits for the queued writeback to reach stable storage. A read-only
    /// superblock has nothing to flush (Linux `if (sb_rdonly(sb)) return 0`), so
    /// the call short-circuits `Ok`. An async-pass error aborts before the wait
    /// pass (Linux returns the first error). Run by `generic_shutdown_super`
    /// before `put_super` and by `freeze_super`/`sync(2)`. # C: O(dirty)
    pub fn sync_filesystem(&self) -> KResult<()> {
        if self.is_readonly() { return Ok(()); }
        self.sync_fs(false)?;
        self.sync_fs(true)
    }

    /// `invalidate_inodes` / per-sb `drop_caches` (Linux fs/inode.c
    /// `invalidate_inodes`, fs/drop_caches.c): sweep the inode cache dropping
    /// every CLEAN, UNREFERENCED slot so a `drop_caches`/remount reclaim shrinks
    /// the icache without touching live or dirty state. A slot is reclaimable
    /// only when its inode is UNUSED — in this `Weak`-keyed cache that is a slot
    /// whose `Weak::upgrade` already fails (Linux `i_count == 0`, no dentry alias
    /// pinning it) — AND it carries no `I_DIRTY`/`I_NEW`/`I_FREEING`/`I_WILL_FREE`
    /// bit (Linux skips dirty and in-flight inodes: writeback or an in-progress
    /// evict still owns them). Busy and dirty slots are RETAINED. Dead alias
    /// `Weak`s are pruned from every surviving slot on the way past. Returns the
    /// count of slots dropped. # C: O(N_ino)
    pub fn drop_caches(&self) -> u32 {
        let mut dropped = 0u32;
        self.icache.lock().retain(|_, e| {
            e.aliases.retain(|w| w.upgrade().is_some());
            let busy = e.inode.upgrade().is_some();
            let pinned = e.state & (I_DIRTY | I_NEW | I_FREEING | I_WILL_FREE) != 0;
            if busy || pinned { true } else { dropped += 1; false }
        });
        dropped
    }

    /// Current `s_writers.frozen` level (`SB_UNFROZEN`..`SB_FREEZE_COMPLETE`).
    /// # C: O(1)
    pub fn sb_freeze_level(&self) -> u32 { self.s_writers_frozen.load(Ordering::Acquire) }

    /// True iff a freeze is in progress or complete (no writers admitted).
    /// # C: O(1)
    pub fn is_frozen(&self) -> bool { self.sb_freeze_level() != SB_UNFROZEN }

    /// `sb_start_write` (trylock variant, Linux `__sb_start_write_trylock`):
    /// admit a write(2)/page-fault writer iff the sb is both writable and
    /// unfrozen. On success the caller MUST pair with [`sb_end_write`]. Returns
    /// `false` if `SB_RDONLY` (Linux `mnt_want_write` → `-EROFS`) or frozen so
    /// the syscall layer can fail `EROFS`/block-retry. The post-increment
    /// re-check mirrors the percpu_rwsem reader/writer barrier: a freeze racing
    /// in between backs the writer out so `freeze_super` never proceeds with a
    /// leaked writer. # C: O(1)
    pub fn sb_start_write(&self) -> bool {
        if self.is_readonly() { return false; }
        if self.is_frozen() { return false; }
        self.s_writers_count.fetch_add(1, Ordering::AcqRel);
        if self.is_frozen() {
            self.s_writers_count.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// `sb_end_write`: release a writer admitted by [`sb_start_write`].
    /// # C: O(1)
    pub fn sb_end_write(&self) { self.s_writers_count.fetch_sub(1, Ordering::AcqRel); }

    /// Live `sb_start_write` holder count (the freeze drain target). # C: O(1)
    pub fn sb_writers(&self) -> u32 { self.s_writers_count.load(Ordering::Acquire) }

    /// `freeze_super` (Linux fs/super.c): quiesce the fs for a consistent
    /// snapshot. Ratchets UNFROZEN → WRITE (block new writers) → sync → FS
    /// (`s_op->freeze_fs`) → COMPLETE. `Ebusy` if already frozen. On a
    /// `freeze_fs` error the level is unwound to UNFROZEN (writers resume).
    /// The caller is responsible for draining in-flight writers (the level
    /// gate stops NEW ones; existing holders drop on their syscall return).
    /// # C: O(dirty)
    pub fn freeze_super(&self) -> KResult<()> {
        if self.s_writers_frozen.compare_exchange(
            SB_UNFROZEN, SB_FREEZE_WRITE, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(crate::types::VfsError::Ebusy);
        }
        // New writers now rejected; flush dirty state before sealing on-disk.
        self.s_writers_frozen.store(SB_FREEZE_PAGEFAULT, Ordering::Release);
        if let Err(e) = self.sync_fs(true) {
            self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release);
            return Err(e);
        }
        self.s_writers_frozen.store(SB_FREEZE_FS, Ordering::Release);
        match self.s_op.freeze_fs() {
            Ok(()) => { self.s_writers_frozen.store(SB_FREEZE_COMPLETE, Ordering::Release); Ok(()) }
            Err(e) => { self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release); Err(e) }
        }
    }

    /// `thaw_super` (Linux fs/super.c): resume after a freeze. `s_op->thaw_fs`
    /// then drop the level back to UNFROZEN (writers re-admitted). `Einval` if
    /// not frozen. # C: O(1)
    pub fn thaw_super(&self) -> KResult<()> {
        if !self.is_frozen() { return Err(crate::types::VfsError::Einval); }
        self.s_op.thaw_fs()?;
        self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release);
        Ok(())
    }

    /// `generic_shutdown_super` (Linux fs/super.c): the last-`s_active`-drop
    /// teardown sequence. Flush dirty state (`sync_filesystem`), clear the live
    /// `SB_ACTIVE` flag bit so no operation treats the instance as mounted from
    /// here on (Linux `sb->s_flags &= ~SB_ACTIVE`), `evict_inodes` the now-idle
    /// inode cache, then run `put_super` (backend teardown + drop root dentry +
    /// clear icache). Returns the busy-inode count `evict_inodes` found — `0` on
    /// a clean unmount, nonzero is the "Busy inodes after unmount" leak the
    /// caller may WARN on. Invoked once by the final [`Self::deactivate_super`].
    /// # C: O(tree + N_ino)
    pub fn generic_shutdown_super(&self) -> u32 {
        let _ = self.sync_filesystem();
        self.set_s_flags(0, SB_ACTIVE);
        let busy = self.evict_inodes();
        self.put_super();
        busy
    }

    /// Umount teardown: `put_super` then drop the dentry tree. # C: O(tree)
    pub fn put_super(&self) {
        self.s_op.put_super();
        *self.s_root.write() = None;
        self.icache.lock().clear();
    }
}
