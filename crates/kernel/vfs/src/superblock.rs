// `struct super_block` per `16§2` — one per mounted filesystem instance.
//
// Module manifest:
// - `registry`: anon device allocation and global superblock registry.
// - `flags`: Linux `SB_*`, freeze, max-size, and timestamp constants.
// - `ops`: `SuperOps`, `FileSystemType`, statfs payload, and legacy fs adapters.
// - `model`: constructors and core superblock fields/accessors.
// - `icache`: inode-cache, alias, nlink, dirty-state, and eviction helpers.
// - `stat`: statfs and `/proc` display hook pass-throughs.
// - `attrs`: flags, active refs, write limits, UUID, and timestamp attributes.
// - `lifecycle`: sync, freeze/thaw, shutdown, and `put_super`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};
use sync::{RwLock, Spinlock, Superblock as SbClass};

use crate::dentry::Dentry;
use crate::fs::FileSystem;
use crate::inode::{Inode, InodeRef};
use crate::types::Ino;

mod attrs;
mod flags;
mod icache;
mod lifecycle;
mod model;
mod ops;
mod registry;
mod stat;

pub use flags::{MAX_LFS_FILESIZE, NSEC_PER_SEC, SB_ACTIVE, SB_BORN, SB_DIRSYNC, SB_FREEZE_COMPLETE, SB_FREEZE_FS, SB_FREEZE_PAGEFAULT, SB_FREEZE_WRITE, SB_I_VERSION, SB_KERNMOUNT, SB_LAZYTIME, SB_MANDLOCK, SB_NOATIME, SB_NODEV, SB_NODIRATIME, SB_NOEXEC, SB_NOSUID, SB_POSIXACL, SB_RDONLY, SB_SILENT, SB_SYNCHRONOUS, SB_UNFROZEN, TIME64_MAX, TIME64_MIN};
pub use ops::{FileSystemType, SbStatFs, SuperOps};
pub use registry::{fs_supers, next_anon_dev, register_super, sget};
pub(crate) use registry::alloc_anon_minor;
pub(crate) use ops::{FsBackedSuperOps, FsBackedType, NullFs};

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
    /// `s_count` — the existence/lookup refcount (Linux `super_block.s_count`),
    /// distinct from `s_active`: it counts references that merely keep the SB
    /// OBJECT alive (an [`sget`] lookup walking `fs_supers`, a `grab_super`
    /// retry), whereas `s_active` counts live mounts. Born at 1; an `sget` hit
    /// bumps it ([`SuperBlock::s_count_inc`]). # consumers: D6 sget sb sharing.
    s_count: AtomicU32,
    /// `s_maxbytes` — largest file size this fs can represent (write-path cap).
    pub s_maxbytes: u64,
    /// `s_time_gran` — timestamp granularity in ns (Linux `sb->s_time_gran`),
    /// set at `fill_super` ([`SuperBlock::set_time_gran`]) and consulted by
    /// [`SuperBlock::timestamp_truncate`] to floor inode atime/mtime/ctime to
    /// what the backend can persist (ext4 1ns, ext2/FAT 1s/2s). Atomic to match
    /// this struct's other mount-time-mutable fields and allow a remount/fill to
    /// publish it without rebuilding the SB. # consumers: inode setattr rounding.
    s_time_gran: AtomicU32,
    /// `s_time_min` — earliest seconds-since-epoch this fs can store (Linux
    /// `sb->s_time_min`). A backend whose on-disk timestamp field is narrower
    /// than `time64_t` (ext4 = -0x80000000 ≈ year 1901) publishes it at
    /// `fill_super` ([`SuperBlock::set_time_range`]); [`Self::timestamp_truncate`]
    /// CLAMPS a setattr time up to it so an out-of-range timestamp is pinned to
    /// the representable floor rather than wrapping on disk. Default
    /// [`TIME64_MIN`] (no clamp). # consumers: inode setattr clamping.
    s_time_min: AtomicI64,
    /// `s_time_max` — latest seconds-since-epoch this fs can store (Linux
    /// `sb->s_time_max`; ext4 32-bit = 0x37fffffff ≈ year 2446). The upper
    /// counterpart to [`Self::s_time_min`]: [`Self::timestamp_truncate`] clamps a
    /// future-dated setattr DOWN to it. Default [`TIME64_MAX`] (no clamp).
    /// # consumers: inode setattr clamping.
    s_time_max: AtomicI64,
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
    /// `s_fs_info` — backend-private state slot (Linux `super_block.s_fs_info`):
    /// the ext4 on-disk-sb struct / tmpfs arena / pseudo-fs context a backend
    /// hangs off its instance. Typed `Arc<dyn Any>` like `inode.i_private`;
    /// `fill_super` installs the concrete state via [`Self::set_fs_info`] and a
    /// backend reads it back through the downcasting [`Self::fs_info_as`]. Locked
    /// because Linux sets it AFTER `alloc_super` (post-construction), so the slot
    /// is replaceable without rebuilding the SB. # consumers: per-fs state.
    s_fs_info: Spinlock<Arc<dyn Any + Send + Sync>, SbClass>,
    /// The legacy `Arc<dyn FileSystem>` backend carrying the write/inode ops
    /// (`create`/`unlink`/`link`/`rename`/`root`/`mounts_line`) that
    /// `SuperOps`/`FileSystemType` do not. The mount table reaches the
    /// backend through `sb.fs()`. `NullFs` for an `s_fs`-less test SB.
    s_fs: Arc<dyn FileSystem>,
    /// Per-instance inode cache (`iget`/`ilookup`/`iput`) keyed by `ino`. Each
    /// [`IcacheEntry`] is a `Weak<Inode>` + the inode's `i_dentry` ALIAS list;
    /// the lifecycle state (`i_state`/`i_count`/`__i_nlink`) lives on the
    /// concrete inode itself (post-KEYSTONE), not in the slot.
    pub(crate) icache: Spinlock<BTreeMap<Ino, IcacheEntry>, SbClass>,
    /// `s_inodes_wb` — STRONG-pin list of every inode carrying an `I_DIRTY` bit
    /// (Linux's per-bdi/`sb` writeback list holds a reference until writeback
    /// cleans it, so a dirty inode is NOT freed before its metadata hits the
    /// backend). Keyed by `ino`; the `Arc` here is the writeback ref, not any
    /// caller's. `mark_inode_dirty` (clean→dirty) inserts, writeback /
    /// `clear_inode` / `iput` (dirty→clean) removes. Driven from `superblock_wb.rs`.
    pub(crate) s_wb: Spinlock<BTreeMap<Ino, InodeRef>, SbClass>,
}

/// One inode-cache slot. `Weak` everywhere so the cache never keeps an inode or
/// dentry alive past its last strong ref. The lifecycle state Linux keeps on
/// `struct inode` (`i_state`/`__i_nlink`/`i_count`) now lives IN the concrete
/// [`crate::inode::Inode`] — this slot is a pure `Weak<Inode>` + alias list.
pub(crate) struct IcacheEntry {
    /// The cached inode (Linux `struct inode`). `Weak` → reclaim on last drop.
    pub(crate) inode:   Weak<Inode>,
    /// `i_dentry` — the dentry aliases (hardlinks: one inode, many dentries).
    pub(crate) aliases: Vec<Weak<Dentry>>,
}
