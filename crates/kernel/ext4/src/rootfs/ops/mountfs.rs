use alloc::string::String;
use alloc::sync::Arc;
use vfs::superblock::SB_RDONLY;

use super::RootfsState;

/// `super_operations` for an ext4 mount (Linux `ext4_statfs`): live on-disk
/// block/inode accounting read from the per-mount `RootfsState`. Installed as
/// the SB's `s_op` by `FileSystem::super_ops`, replacing the generic
/// generic fill-super statfs snapshot (which reported only `f_type`/`f_bsize`).
pub struct Ext4SuperOps {
    st: Arc<RootfsState>,
}

impl Ext4SuperOps {
    pub fn new(st: Arc<RootfsState>) -> Self {
        Self { st }
    }
}

/// Whether a `sync_fs` pass owes the backing device a durability barrier.
///
/// Only the WAITING pass does. The non-waiting pass exists to start work, not to
/// finish it: a barrier there orders writes nobody has waited for, while still
/// costing a full device flush — and since the sync path issues BOTH passes,
/// answering `true` for both doubles every whole-filesystem sync's device
/// flushes.
///
/// `-o nobarrier` removes the flush entirely: the mount has told us its device
/// either does not need one or is lying about it. That option had no effect at
/// all before this, so a mount that asked to trade durability for speed paid
/// for the durability anyway. # C: O(1)
fn sync_fs_needs_barrier(wait: bool, barrier: bool) -> bool { wait && barrier }

impl vfs::SuperOps for Ext4SuperOps {
    /// Linux `ext4_statfs`. `f_blocks` merges
    /// `s_blocks_count_hi` so a >16 TiB filesystem is not truncated to its low
    /// 32 bits; `f_bavail` subtracts `s_r_blocks_count` (the super-user reserve)
    /// from `f_bfree` and clamps at zero, so an unprivileged writer is told the
    /// space it may actually consume; `f_fsid` is the folded 16-byte on-disk
    /// UUID (`uuid_to_fsid`), the stable identity NFS and `df` key on, not the
    /// ephemeral `s_dev`.
    /// # C: O(1)
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> {
        let m = &self.st.mount;
        let free_blocks = m.state_free_blocks();
        let reserved = m.sb.r_blocks_count;
        Ok(vfs::SbStatFs {
            f_type: crate::EXT4_SUPER_MAGIC as u64,
            f_bsize: m.sb.block_size,
            f_blocks: m.sb.blocks_count(),
            f_bfree: free_blocks,
            f_bavail: free_blocks.saturating_sub(reserved),
            f_files: m.sb.inodes_count as u64,
            f_ffree: m.state_free_inodes() as u64,
            f_fsid: crate::superblock::uuid_to_fsid(&m.sb.uuid),
            f_flags: 0,
            f_namelen: crate::superblock::EXT4_NAME_LEN,
            f_frsize: m.sb.block_size,
        })
    }

    /// Linux `ext4_drop_inode` → `generic_drop_inode`: evict as soon as the
    /// last reference goes if the inode has no remaining links. The generic
    /// default additionally requires `i_count == 0`, which `iput` has already
    /// established by the time it asks; keeping only the link test makes this
    /// the exact `!inode->i_nlink` predicate and is what turns the last close
    /// of an unlinked file into an eviction.
    /// # C: O(1)
    fn drop_inode(&self, inode: &vfs::Inode) -> bool { inode.nlink() == 0 }

    /// `s_export_op->fh_to_dentry` (Linux `ext4_fh_to_dentry` →
    /// `ext4_nfs_get_inode`): re-read the inode named by an
    /// `open_by_handle_at(2)` handle FROM DISK, so a handle outlives the inode
    /// cache instead of going stale the moment the last opener closed the file.
    ///
    /// The three ways it stays stale are the three Linux enforces: the number
    /// is outside the filesystem, its bit is clear in the inode bitmap (the
    /// slot is free — surfaced here as `i_links_count == 0`, which is what a
    /// freed slot carries), or the on-disk `i_generation` disagrees with the
    /// one the handle was minted against, meaning the number was reallocated to
    /// a different object.
    /// # C: O(1) inode read
    fn fh_to_dentry(&self, sb: &vfs::SuperBlock, ino: vfs::Ino, generation: u32)
        -> Option<vfs::InodeRef>
    {
        // A resident inode is the authoritative incarnation: return the SAME
        // `Arc` a path walk would, never a second parallel copy of one object.
        if let Some(i) = sb.ilookup(ino) {
            return if vfs::export::generation_matches(&i, generation) { Some(i) } else { None };
        }
        if !crate::rootfs::inode::is_ext4_ino(ino) { return None; }
        let raw_ino = crate::rootfs::inode::ext4_unwrap_ino(ino);
        if raw_ino == 0 || raw_ino > self.st.mount.sb.inodes_count { return None; }
        let raw = self.st.mount.read_inode(raw_ino).ok()?;
        // A freed slot keeps its old contents apart from the link count, so
        // `nlink == 0` is how a handle to a deleted file is told apart from one
        // to a live file. The root inode is exempt: it is reachable by
        // definition and some images leave its count unconventional.
        if raw.links_count == 0 && raw_ino != crate::superblock::EXT4_ROOT_INO { return None; }
        // Only the HANDLE's zero wildcards (the reconnect walk cannot know a
        // parent's incarnation). A zero in the on-disk slot is a real value and
        // must still be compared, or a handle minted against a versioned
        // incarnation would open whatever unversioned object took the number.
        if generation != vfs::export::GENERATION_ANY && raw.generation != generation { return None; }
        self.st.wrap_any_ino(raw_ino)
    }

    /// Linux `ext4_evict_inode`: an inode reaching here with no links is the
    /// unlinked-but-was-open (or never-named O_TMPFILE) case — truncate its
    /// data blocks, release its quota charge, and free the inode slot NOW that
    /// the last reference is gone. A still-linked inode is only cleared.
    /// # C: O(N_extents) when it frees, else O(1)
    fn evict_inode(&self, inode: &vfs::Inode) {
        if inode.nlink() == 0 {
            // Linux waits for inode writeback and removes every page-cache
            // page before ext4 truncates/frees the orphan.  Reversing these
            // operations lets a mapping that outlives `struct inode` write
            // stale bytes through a reused inode/block (observed as dconf's
            // `GVariant` payload replacing a Flatpak directory block).
            if let Some(data) = inode.private::<crate::rootfs::inode::Ext4FileData>() {
                data.frames.discard_for_eviction();
            }
            if let Some((st, ino)) = crate::rootfs::ext4_state_of(inode) { let _ = st.evict_orphan(ino); }
        }
        inode.set_state(vfs::inode::I_FREEING | vfs::inode::I_CLEAR, vfs::inode::I_DIRTY);
    }

    /// `s_op->sync_fs`. The `wait` argument selects how far this pass goes, and
    /// ignoring it — which is what this did — makes every whole-filesystem sync
    /// pay for the expensive half TWICE, because the sync path deliberately
    /// issues both passes.
    ///
    /// Either pass starts the journal commit: the point of the non-waiting pass
    /// is to get every filesystem's commit MOVING before any of them is waited
    /// on. Only the waiting pass takes the device barrier, because a barrier is
    /// a claim about writes that have already completed — issuing one on the
    /// pass that does not wait guarantees nothing and costs a full device flush
    /// per mount per `sync(2)`.
    /// # C: O(dirty) + one device flush when `wait`
    fn sync_fs(&self, wait: bool) -> vfs::KResult<()> {
        // sync(2)/syncfs(2): flush buffered file-data pages (Linux buffered
        // writes sit dirty in the page cache until writeback) before the
        // journal tx + device flush. fsync/msync flush per-inode; this is the
        // whole-fs pass.
        // Scoped to THIS mount: `syncfs(2)` syncs the filesystem containing the
        // fd, never a peer ext4 mount the caller did not name.
        #[cfg(feature = "ext4-frame-cache")]
        crate::rootfs::framecache::flush_dirty(Some(&self.st.mount))
            .map_err(|_| vfs::VfsError::Eio)?;
        // Drain the running batched transaction (Linux `sync_fs` IS the
        // per-superblock durability point). `flush_pending_tx` is a no-op —
        // under cross-op batching the metadata sits in `MountState.shadow`
        // until `commit_batch`, so syncfs(2)/freeze must commit it here or
        // return success with metadata not yet on disk. This makes `sync_fs`
        // authoritative for EVERY ext4 mount (incl. non-root `/home`), not
        // just the root helper `commit_rootfs_journal`.
        self.st.mount.commit_batch().map_err(|_| vfs::VfsError::Eio)?;
        if sync_fs_needs_barrier(wait, self.st.opts().behaviour.barrier) {
            self.st.mount.dev.flush().map_err(|_| vfs::VfsError::Eio)?;
        }
        Ok(())
    }

    fn freeze_fs(&self) -> vfs::KResult<()> {
        self.sync_fs(true)?;
        self.st.frozen.store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn thaw_fs(&self) -> vfs::KResult<()> {
        self.st.frozen.store(false, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn remount_fs(&self, sb_flags: u64, data: &str) -> vfs::KResult<()> {
        if let Some(sb) = self.st.i_sb() {
            // Option validation runs FIRST and commits nothing on failure, so a
            // remount naming a change the live filesystem cannot make (a
            // different journalled quota file, a different quota format) leaves
            // both the options and the quota state exactly as they were.
            let quota_loaded = (0..vfs::MAXQUOTAS)
                .any(|slot| sb.s_dquot.is_enabled(vfs::QuotaType::from_slot(slot)));
            self.st.configure_mount_opts(data, quota_loaded)?;
            if sb_flags & SB_RDONLY != 0 { return vfs::quota_suspend_sysfiles(&sb); }
            self.st.enable_mount_quotas(&sb, true)?;
        }
        Ok(())
    }

    fn quota_on(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType, format_id: u32, path: Option<&vfs::VfsPath>) -> vfs::KResult<()> {
        crate::quota::quota_on_ext4(&self.st, sb, kind, format_id, path)
    }

    fn quota_on_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { true }

    fn quota_supported(&self) -> bool { true }

    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }

    fn quota_enable(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> vfs::KResult<()> {
        if !sb.s_dquot.is_enabled(kind) || sb.s_dquot.info(kind).dqi_flags & vfs::DQF_SYS_FILE == 0 {
            return Err(vfs::VfsError::Esrch);
        }
        vfs::quota_enable_limits(sb, kind)
    }

    fn quota_enable_supported(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> bool {
        sb.s_dquot.is_enabled(kind) && sb.s_dquot.info(kind).dqi_flags & vfs::DQF_SYS_FILE != 0
    }

    fn quota_disable(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> vfs::KResult<()> {
        if !sb.s_dquot.is_enabled(kind) || sb.s_dquot.info(kind).dqi_flags & vfs::DQF_SYS_FILE == 0 {
            return Err(vfs::VfsError::Esrch);
        }
        vfs::quota_disable_limits(sb, kind)
    }

    fn quota_disable_supported(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> bool {
        sb.s_dquot.is_enabled(kind) && sb.s_dquot.info(kind).dqi_flags & vfs::DQF_SYS_FILE != 0
    }

    fn quota_off(&self, sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> vfs::KResult<()> {
        vfs::quota_off(sb, kind)
    }

    fn quota_sync_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { true }
}

pub struct Ext4Mount {
    pub(super) st: Arc<RootfsState>,
    dev_t: Option<u64>,
}

impl Ext4Mount {
    pub fn open(dev: Arc<dyn block::BlockDevice>) -> block::types::KResult<Arc<Self>> {
        Self::open_with_dev(dev, None)
    }

    pub fn open_with_dev(
        dev: Arc<dyn block::BlockDevice>,
        dev_t: Option<u64>,
    ) -> block::types::KResult<Arc<Self>> {
        Self::open_with_behaviour(dev, dev_t, Default::default())
    }

    /// Open with the behavioural options already decided. # C: O(N_groups)
    fn open_with_behaviour(
        dev: Arc<dyn block::BlockDevice>,
        dev_t: Option<u64>,
        behaviour: crate::mount_opts::Ext4Behaviour,
    ) -> block::types::KResult<Arc<Self>> {
        let st = RootfsState::open_with_behaviour(dev, behaviour)?;
        // ext4_setup_super: a rw mount marks the fs not-cleanly-unmounted +
        // bumps the mount count, so a crash before Drop is fsck-visible.
        // Best-effort — a marginal SB write must not fail an otherwise-good
        // mount (Linux logs and continues).
        let _ = st.mount.mark_state_dirty();
        let fs = Arc::new(Self { st, dev_t });
        // `commit=` is a promise about a filesystem nobody is syncing, so the
        // timer that keeps it is armed by the first mount rather than by boot.
        crate::commit_timer::arm();
        crate::commit_timer::register(&fs.st.mount);
        Ok(fs)
    }

    /// Open `dev` and apply the mount-data option string to it.
    ///
    /// The string is parsed BEFORE the filesystem is opened and
    /// consistency-checked before the superblock is published, so a rejected
    /// combination (`usrjquota=` without `jqfmt=`, `prjquota` on a filesystem
    /// without the project feature, …) fails the mount with the option error
    /// rather than half-mounting. An unknown non-quota option never fails the
    /// mount.
    ///
    /// Parsing first is not tidiness: the open replays the journal, and
    /// `noload`/`norecovery` is the option that says not to. It is parsed
    /// ONCE — the same context the open consumed is the one applied afterwards.
    /// # C: O(N_groups + len(data))
    pub fn open_with_data(
        dev: Arc<dyn block::BlockDevice>,
        dev_t: Option<u64>,
        data: &str,
    ) -> vfs::KResult<Arc<Self>> {
        let mut ctx = crate::mount_opts::parse_data(data, Default::default())?;
        let fs = Self::open_with_behaviour(dev, dev_t, ctx.behaviour)
            .map_err(|_| vfs::VfsError::Einval)?;
        fs.st.apply_parsed_mount_opts(&mut ctx)?;
        Ok(fs)
    }

    pub fn state(&self) -> &Arc<RootfsState> {
        &self.st
    }
}

impl vfs::fs::FileSystem for Ext4Mount {
    fn name(&self) -> &str { "ext4" }
    fn magic(&self) -> u64 { crate::EXT4_SUPER_MAGIC as u64 }
    fn fs_flags(&self) -> vfs::fs::FsFlags {
        vfs::fs::FsFlags::FS_REQUIRES_DEV | vfs::fs::FsFlags::FS_ALLOW_IDMAP
    }
    fn dev_id(&self) -> Option<u64> { self.dev_t }
    fn sysfs_name(&self) -> Option<String> {
        self.dev_t.and_then(|dt| block::registry::by_dev(dt as u32).map(|d| d.name.clone()))
    }
    fn block_size(&self) -> u32 { self.st.mount.sb.block_size }
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(Ext4SuperOps::new(self.st.clone())))
    }
    fn root(&self) -> Option<vfs::InodeRef> { self.st.wrap_any_ino(2) }
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) -> vfs::KResult<()> { self.st.set_sb(sb) }
}

impl core::ops::Drop for Ext4Mount {
    fn drop(&mut self) {
        // Linux `generic_shutdown_super` → `put_super` writes back before the
        // final clean mark. Under cross-op batching the whole session's metadata
        // sits in `MountState.shadow`; if the mount drops without an explicit
        // sync it would be LOST. Drain it first, then reap orphans + mark clean,
        // then drain again so the clean bit itself is a durable commit (not
        // staged behind data in a shadow that dies with the mount).
        let _ = self.st.mount.commit_batch();
        let orphans: alloc::vec::Vec<u32> = self.st.orphans.lock().drain(..).collect();
        for ino in orphans {
            if let Ok(inode) = self.st.mount.read_inode(ino) {
                if inode.links_count == 0 {
                    let _ = self.st.free_orphan_inode(ino);
                }
            }
        }
        // ext4_put_super: orphans reaped and no writers remain — mark the fs
        // cleanly unmounted. Best-effort on teardown.
        let _ = self.st.mount.mark_state_clean();
        let _ = self.st.mount.commit_batch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
    use sync::TaskList;
    use vfs::fs::FileSystem;

    const IMAGE: &[u8] = include_bytes!("../../../tests/mini-j.img");
    const SECTOR: u32 = 512;

    /// A device that counts its durability barriers and forwards everything
    /// else. The flush COUNT is the whole point: `wait` is not observable from
    /// the return value, only from how much I/O the pass spends.
    struct CountingDev { inner: Arc<MemDisk<TaskList>>, flushes: AtomicUsize }

    impl BlockDevice for CountingDev {
        fn block_size(&self) -> u32 { self.inner.block_size() }
        fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
        fn submit_sync(&self, req: &mut BlockRequest) -> block::types::KResult<()> {
            self.inner.submit_sync(req)
        }
        fn flush(&self) -> block::types::KResult<()> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            self.inner.flush()
        }
    }

    fn fresh_dev() -> Arc<CountingDev> {
        let cap = (IMAGE.len() as u64) / (SECTOR as u64);
        let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
        let mut req = BlockRequest {
            op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
            buffer: Vec::from(IMAGE), ..Default::default()
        };
        inner.submit_sync(&mut req).unwrap();
        Arc::new(CountingDev { inner, flushes: AtomicUsize::new(0) })
    }

    /// The non-waiting pass starts the commit and stops there. Before the split
    /// it also flushed the device, so the two passes the sync path issues cost
    /// two full device flushes per mount for one `sync(2)`.
    #[test]
    fn nowait_sync_fs_starts_the_commit_without_a_device_barrier() {
        let dev = fresh_dev();
        let m = Ext4Mount::open(dev.clone() as Arc<dyn BlockDevice>).unwrap();
        let ops = m.super_ops().expect("ext4 super_ops");
        dev.flushes.store(0, Ordering::SeqCst);

        ops.sync_fs(false).expect("nowait pass");
        assert_eq!(dev.flushes.load(Ordering::SeqCst), 0,
            "the pass that does not wait takes no device barrier");
    }

    /// The waiting pass is the one that owes the barrier, and owes exactly one.
    #[test]
    fn waiting_sync_fs_takes_exactly_one_device_barrier() {
        let dev = fresh_dev();
        let m = Ext4Mount::open(dev.clone() as Arc<dyn BlockDevice>).unwrap();
        let ops = m.super_ops().expect("ext4 super_ops");
        dev.flushes.store(0, Ordering::SeqCst);

        ops.sync_fs(true).expect("waiting pass");
        assert_eq!(dev.flushes.load(Ordering::SeqCst), 1,
            "the waiting pass takes the barrier, once");
    }

    /// The pair as the sync path actually issues it: one barrier for the whole
    /// filesystem, not one per pass.
    #[test]
    fn a_full_sync_pass_pair_costs_one_device_barrier() {
        let dev = fresh_dev();
        let m = Ext4Mount::open(dev.clone() as Arc<dyn BlockDevice>).unwrap();
        let ops = m.super_ops().expect("ext4 super_ops");
        dev.flushes.store(0, Ordering::SeqCst);

        ops.sync_fs(false).expect("nowait pass");
        ops.sync_fs(true).expect("waiting pass");
        assert_eq!(dev.flushes.load(Ordering::SeqCst), 1,
            "one whole-filesystem sync, one device barrier");
    }

    /// The barrier decision itself, stated once: the waiting pass and only it,
    /// and only on a mount that did not ask for the flush to be dropped.
    #[test]
    fn only_the_waiting_pass_of_a_barrier_mount_owes_a_barrier() {
        assert!(!sync_fs_needs_barrier(false, true));
        assert!(sync_fs_needs_barrier(true, true));
        assert!(!sync_fs_needs_barrier(false, false));
        assert!(!sync_fs_needs_barrier(true, false), "-o nobarrier takes no device flush");
    }

    /// `-o nobarrier` reaches the device, not just the option state.
    #[test]
    fn nobarrier_removes_the_device_flush_a_full_sync_would_take() {
        let dev = fresh_dev();
        let m = Ext4Mount::open_with_data(dev.clone() as Arc<dyn BlockDevice>, None, "nobarrier")
            .expect("nobarrier mounts");
        let ops = m.super_ops().expect("ext4 super_ops");
        dev.flushes.store(0, Ordering::SeqCst);
        ops.sync_fs(false).expect("nowait pass");
        ops.sync_fs(true).expect("waiting pass");
        assert_eq!(dev.flushes.load(Ordering::SeqCst), 0,
            "a nobarrier mount takes no device flush");
    }

    /// An option value the filesystem does not have fails the mount instead of
    /// being swallowed. `errors=remount-rw` is not a value; it used to mount.
    #[test]
    fn an_unknown_option_value_fails_the_mount() {
        let dev = fresh_dev() as Arc<dyn BlockDevice>;
        assert!(Ext4Mount::open_with_data(dev.clone(), None, "errors=remount-rw").is_err());
        assert!(Ext4Mount::open_with_data(dev.clone(), None, "data=sideways").is_err());
        assert!(Ext4Mount::open_with_data(dev.clone(), None, "journal_ioprio=8").is_err());
        assert!(Ext4Mount::open_with_data(dev.clone(), None, "commit=notanumber").is_err());
        assert!(Ext4Mount::open_with_data(dev, None, "errors=panic").is_ok());
    }

    /// The options a root filesystem is actually mounted with reach the state
    /// their consumers read, and the ones the string did not name keep their
    /// defaults.
    #[test]
    fn the_behavioural_options_land_where_their_consumers_read_them() {
        let dev = fresh_dev() as Arc<dyn BlockDevice>;
        let m = Ext4Mount::open_with_data(dev, None,
            "errors=continue,commit=30,max_dir_size_kb=64,nodelalloc,discard,noload")
            .expect("mounts");
        let b = m.state().opts().behaviour;
        assert_eq!(b.errors, crate::mount_opts::ErrorsPolicy::Continue);
        assert_eq!(b.commit_secs, 30);
        assert_eq!(b.max_dir_size_bytes(), Some(64 * 1024));
        assert!(!b.delalloc);
        assert!(b.discard);
        assert!(b.noload);
        assert!(b.barrier, "an option the string did not name keeps its default");
        assert_eq!(b.data, crate::mount_opts::DataMode::Ordered);
    }
}
