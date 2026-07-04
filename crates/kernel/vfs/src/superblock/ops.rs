extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use crate::file_ops::FileOps;
use crate::fs::{FileSystem, FsFlags};
use crate::fs::fs_context::FsContextOps;
use crate::inode::{Inode, InodeBuilder, InodeRef, I_CLEAR, I_DIRTY, I_FREEING};
use crate::inode_ops::InodeOps;
use crate::types::{Ino, KResult};
use super::{next_anon_dev, SuperBlock};

/// Placeholder backend for an `s_fs`-less superblock built via
/// [`SuperBlock::new`] (the object-model unit tests). Production superblocks
/// are built via [`SuperBlock::for_backend`] and carry their real backend.
pub(crate) struct NullFs;
impl FileSystem for NullFs {
    fn name(&self) -> &str { "none" }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `super_operations`
/// (`s_op`). `statfs` reports the backend `magic` as `f_type`; the inode
/// `SuperBlock::statfs` then defaults `f_bsize` from `s_blocksize`. This is
/// the generic `fill_super` glue so every backend gets a working superblock
/// without a per-fs `SuperOps` impl (richer per-fs `SuperOps` layer on top).
pub(crate) struct FsBackedSuperOps { pub(crate) fs: Arc<dyn FileSystem> }
impl SuperOps for FsBackedSuperOps {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_type: self.fs.magic(), f_bsize: self.fs.block_size(), ..Default::default() })
    }
}

/// Adapter exposing a legacy `Arc<dyn FileSystem>` as `file_system_type`
/// (`s_type`). `mount` is `fill_super`: build a fresh superblock over the
/// backend's root inode.
pub(crate) struct FsBackedType { pub(crate) fs: Arc<dyn FileSystem> }
impl FileSystemType for FsBackedType {
    fn name(&self) -> &str { self.fs.name() }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(self.fs.clone(), self.fs.root(),
            next_anon_dev(), String::from(self.fs.name())))
    }
    fn fs_flags(&self) -> FsFlags { self.fs.fs_flags() }
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
    /// `remount_fs` (Linux classic `super_operations.remount_fs`) — apply a
    /// filesystem-level reconfigure (RO↔RW, on-disk journal mode, mount options)
    /// to a LIVE superblock. `sb_flags` is the PROPOSED post-remount `s_flags`
    /// the backend may validate (e.g. refuse RW on a fs with un-replayed
    /// journal). Driven by [`SuperBlock::reconfigure_super`]; default Ok (a
    /// pseudo-fs flag-only remount needs no backend work). Returning Err aborts
    /// the remount with `s_flags` UNCHANGED. The new mount API's richer
    /// `fs_context_operations.reconfigure` supersedes this for converted
    /// filesystems; this is the classic hook for the rest. # C: FS-dependent
    fn remount_fs(&self, _sb_flags: u64) -> KResult<()> { Ok(()) }
    /// `put_super` — last-umount teardown. Default no-op. # C: O(1)
    fn put_super(&self) {}

    /// `s_op->write_inode` (Linux `super_operations.write_inode`) — flush this
    /// inode's dirty metadata to the backend. `wait` requests a synchronous
    /// commit. Default `Ok` (a pseudo-fs with no backing store has nothing to
    /// write). Called by [`SuperBlock::iput`] on the last-ref pre-evict window.
    /// # C: FS-dependent
    fn write_inode(&self, _inode: &Inode, _wait: bool) -> KResult<()> { Ok(()) }

    /// `s_op->drop_inode` (Linux `super_operations.drop_inode`) — decide, when an
    /// inode's last reference drops (`i_count` reached 0), whether to EVICT it now
    /// rather than retain it cached for reuse. Default = `generic_drop_inode`:
    /// evict iff the inode has no remaining links AND no references
    /// (`i_nlink == 0 && i_count == 0`). A backend may override to e.g. always
    /// evict (`generic_delete_inode`). # C: O(1)
    fn drop_inode(&self, inode: &Inode) -> bool {
        inode.nlink() == 0 && inode.i_count() == 0
    }

    /// `s_op->evict_inode` (Linux `super_operations.evict_inode`) — the terminal
    /// per-inode teardown: drop the inode's data/blocks and clear it. Default =
    /// `clear_inode` (mark `I_FREEING | I_CLEAR`, drop every dirty bit). A backend
    /// (ext4) overrides to free on-disk blocks first. Run by [`SuperBlock::iput`]
    /// after `drop_inode` returns true. # C: FS-dependent
    fn evict_inode(&self, inode: &Inode) {
        inode.set_state(I_FREEING | I_CLEAR, I_DIRTY);
    }

    /// `s_op->alloc_inode` (Linux `super_operations.alloc_inode`) — allocate a
    /// fresh in-core inode. Default funnels through [`InodeBuilder`] (the one
    /// constructor every `make_*_inode`/iget-build closure uses), born with
    /// `i_count == 1`. A backend overrides to embed the inode in its own
    /// per-inode container (`ext4_inode_info`); the generic path keeps the
    /// builder funnel. # C: O(1)
    fn alloc_inode(&self, ino: Ino, mode: u32,
                   i_op: Arc<dyn InodeOps>, i_fop: Arc<dyn FileOps>) -> InodeRef {
        InodeBuilder::new(ino, mode, i_op, i_fop).build()
    }

    /// `s_op->free_inode` (Linux `super_operations.free_inode`) — the RCU
    /// free callback releasing the in-core inode allocation. Default = drop
    /// (the moved-in `Arc` releases when this returns). # C: O(1)
    fn free_inode(&self, _inode: InodeRef) {}

    /// `s_op->destroy_inode` (Linux `super_operations.destroy_inode`) — tear down
    /// a no-longer-referenced in-core inode (schedules the RCU `free_inode`).
    /// Default = drop. # C: O(1)
    fn destroy_inode(&self, _inode: InodeRef) {}

    /// `s_op->show_options` (Linux `super_operations.show_options`) — APPEND the
    /// backend's own mount options to the `/proc/<pid>/mounts` /
    /// `/proc/self/mountinfo` per-mount line. The VFS renders the generic flags
    /// first (`rw`/`ro`, `relatime`, …); this hook then appends the fs-specific
    /// tail — tmpfs `size=`/`nr_inodes=`/`mode=`, ext4 `data=ordered`, a cgroup2
    /// controller list. Each option carries its OWN leading comma (Linux emits
    /// them via `seq_puts(m, ",size=…")`), so the result concatenates directly
    /// after the generic flags with no separator fixup. Default `""` = no
    /// fs-specific options (a plain pseudo-fs). Mirrors [`crate::fs::FileSystem::show_options`]
    /// at the `s_op` layer; the SB-level accessor is [`SuperBlock::show_options`].
    /// # C: O(len opts)
    fn show_options(&self) -> String { String::new() }

    /// `s_op->show_devname` (Linux `super_operations.show_devname`) — override the
    /// SOURCE-device column rendered in `/proc/self/mountinfo` for a fs whose
    /// backing-store name is not its `s_id` (`nfs` server:/export, `overlay`
    /// `overlay`, a `bind` source path). `None` (the default) ⇒ the VFS uses the
    /// generic `s_id`/fs-name source column. # C: O(len name)
    fn show_devname(&self) -> Option<String> { None }

    /// `s_op->show_path` (Linux `super_operations.show_path`) — override the
    /// mount-point PATH column rendered in `/proc/self/mountinfo` for a fs that
    /// presents a synthetic root path different from the dentry path (Linux uses
    /// this for e.g. the `gadgetfs`/anon-inode style roots). `None` (the default)
    /// ⇒ the VFS uses the generic resolved mount path. # C: O(len path)
    fn show_path(&self) -> Option<String> { None }

    /// `s_op->show_stats` (Linux `super_operations.show_stats`) — emit the
    /// backend's extra per-mount statistics line for `/proc/self/mountstats`
    /// (Linux: `nfs` round-trip/RPC counters). `None` (the default) ⇒ the fs
    /// contributes no `mountstats` body beyond the generic device line. # C: O(len stats)
    fn show_stats(&self) -> Option<String> { None }

    /// `s_op->dirty_inode` (Linux `super_operations.dirty_inode`) — the hook
    /// `__mark_inode_dirty` calls so the backend records that `inode`'s metadata
    /// changed (ext4 starts a journal handle and dirties its on-disk inode here).
    /// `flags` is the `I_DIRTY_*` set being applied. Default = the generic
    /// in-core dirtying: OR the requested `I_DIRTY` bits into the inode's
    /// `i_state` (a journal-less / pseudo-fs has no extra per-fs work). `flags`
    /// is masked to `I_DIRTY` so a caller cannot smuggle a lifecycle bit
    /// (`I_NEW`/`I_FREEING`/…) through the dirtying path, matching
    /// [`SuperBlock::mark_inode_dirty`]. # C: O(1)
    fn dirty_inode(&self, inode: &Inode, flags: u32) {
        inode.set_state(flags & I_DIRTY, 0);
    }
}

/// `file_system_type` (Linux `struct file_system_type`) — the registry
/// entry split out of today's monolithic `FileSystem` trait. `mount`
/// is `fill_super`: it builds a fresh `SuperBlock` instance.
pub trait FileSystemType: Send + Sync {
    /// FS-type name: `"ext4"`, `"tmpfs"`. # C: O(1)
    fn name(&self) -> &str;
    /// Build a superblock instance (`fill_super`). # C: FS-dependent
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>>;
    /// `file_system_type::fs_flags` (Linux `include/linux/fs.h`) — the
    /// type-level classification the new-mount-API `vfs_get_tree` consults for
    /// the `FS_REQUIRES_DEV` source check (D23). Default `empty()` = a pseudo /
    /// in-memory fs; block-device backends override with `FS_REQUIRES_DEV`.
    /// # C: O(1)
    fn fs_flags(&self) -> FsFlags { FsFlags::empty() }
    /// `file_system_type::init_fs_context` (Linux) — install a backend-specific
    /// `fs_context_operations` for the new mount API. `None` (the default) ⇒ the
    /// legacy adapter ([`crate::fs::fs_context::LegacyFsContextOps`]) replays the
    /// accumulated options to [`FileSystemType::mount`] at `get_tree`. # C: O(1)
    fn init_fs_context(&self) -> Option<Arc<dyn FsContextOps>> { None }
}
