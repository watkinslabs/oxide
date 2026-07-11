use alloc::sync::Arc;

use super::RootfsState;

/// `super_operations` for an ext4 mount (Linux `ext4_statfs`): live on-disk
/// block/inode accounting read from the per-mount `RootfsState`. Installed as
/// the SB's `s_op` by `FileSystem::super_ops`, replacing the generic
/// `FsBackedSuperOps` (which reported only `f_type`/`f_bsize`).
pub struct Ext4SuperOps {
    st: Arc<RootfsState>,
}

impl Ext4SuperOps {
    pub fn new(st: Arc<RootfsState>) -> Self {
        Self { st }
    }
}

impl vfs::SuperOps for Ext4SuperOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> {
        let m = &self.st.mount;
        let free_blocks = m.state_free_blocks();
        let free_inodes = m.state_free_inodes() as u64;
        Ok(vfs::SbStatFs {
            f_type: crate::EXT4_SUPER_MAGIC as u64,
            f_bsize: m.sb.block_size,
            f_blocks: m.sb.blocks_count_lo as u64,
            f_bfree: free_blocks,
            f_bavail: free_blocks,
            f_files: m.sb.inodes_count as u64,
            f_ffree: free_inodes,
            f_fsid: 0,
            f_flags: 0,
        })
    }

    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        // sync(2)/syncfs(2): flush buffered file-data pages (Linux buffered
        // writes sit dirty in the page cache until writeback) before the
        // journal tx + device flush. fsync/msync flush per-inode; this is the
        // whole-fs pass.
        #[cfg(feature = "ext4-frame-cache")]
        crate::flush_all_dirty().map_err(|_| vfs::VfsError::Eio)?;
        // Drain the running batched transaction (Linux `sync_fs` IS the
        // per-superblock durability point). `flush_pending_tx` is a no-op —
        // under cross-op batching the metadata sits in `MountState.shadow`
        // until `commit_batch`, so syncfs(2)/freeze must commit it here or
        // return success with metadata not yet on disk. This makes `sync_fs`
        // authoritative for EVERY ext4 mount (incl. non-root `/home`), not
        // just the root helper `commit_rootfs_journal`.
        self.st.mount.commit_batch().map_err(|_| vfs::VfsError::Eio)?;
        self.st.mount.dev.flush().map_err(|_| vfs::VfsError::Eio)?;
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
        let st = RootfsState::open(dev)?;
        // ext4_setup_super: a rw mount marks the fs not-cleanly-unmounted +
        // bumps the mount count, so a crash before Drop is fsck-visible.
        // Best-effort — a marginal SB write must not fail an otherwise-good
        // mount (Linux logs and continues).
        let _ = st.mount.mark_state_dirty();
        Ok(Arc::new(Self { st, dev_t }))
    }

    pub fn state(&self) -> &Arc<RootfsState> {
        &self.st
    }
}

impl vfs::fs::FileSystem for Ext4Mount {
    fn name(&self) -> &str { "ext4" }
    fn magic(&self) -> u64 { crate::EXT4_SUPER_MAGIC as u64 }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn dev_id(&self) -> Option<u64> { self.dev_t }
    fn block_size(&self) -> u32 { self.st.mount.sb.block_size }
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(Ext4SuperOps::new(self.st.clone())))
    }
    fn root(&self) -> Option<vfs::InodeRef> { self.st.wrap_any_ino(2) }
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::SuperBlock>) { self.st.set_sb(sb); }
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
                    let _ = self.st.mount.free_orphan_inode(ino);
                }
            }
        }
        // ext4_put_super: orphans reaped and no writers remain — mark the fs
        // cleanly unmounted. Best-effort on teardown.
        let _ = self.st.mount.mark_state_clean();
        let _ = self.st.mount.commit_batch();
    }
}
