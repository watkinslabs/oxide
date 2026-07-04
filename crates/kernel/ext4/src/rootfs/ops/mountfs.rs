use alloc::sync::Arc;

use super::{RootfsState, ext4_file_ino};

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
        self.st.mount.flush_pending_tx().map_err(|_| vfs::VfsError::Eio)?;
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
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        self.st.create_at(path.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enoent)
    }
    fn create_anonymous(&self, dir: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        self.st.create_anonymous_at(dir.as_bytes(), mode as u16).ok_or(vfs::VfsError::Enospc)
    }
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> { self.st.unlink_at(path.as_bytes()) }
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        self.st.link_at(target.as_bytes(), link.as_bytes())
    }
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let ino = ext4_file_ino(&inode).ok_or(vfs::VfsError::Exdev)?;
        self.st.link_inode_at(ino, link.as_bytes())
    }
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        self.st.rename_at(from.as_bytes(), to.as_bytes())
    }
    fn exchange(&self, a: &str, b: &str) -> vfs::fs::KResult<()> {
        self.st.exchange_at(a.as_bytes(), b.as_bytes())
    }
    fn whiteout(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        self.st.whiteout_at(from.as_bytes(), to.as_bytes())
    }
}

impl core::ops::Drop for Ext4Mount {
    fn drop(&mut self) {
        let orphans: alloc::vec::Vec<u32> = self.st.orphans.lock().drain(..).collect();
        for ino in orphans {
            if let Ok(inode) = self.st.mount.read_inode(ino) {
                if inode.links_count == 0 {
                    let _ = self.st.mount.free_orphan_inode(ino);
                }
            }
        }
    }
}
