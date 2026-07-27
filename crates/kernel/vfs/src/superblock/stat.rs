extern crate alloc;
use alloc::string::String;
use crate::inode::Inode;
use crate::types::KResult;
use super::{SbStatFs, SuperBlock};

impl SuperBlock {
    /// `statfs_by_dentry` (Linux fs/statfs.c): run `s_op->statfs`, then apply the
    /// VFS-side defaults — `f_type`/`f_bsize`/`f_fsid` from the superblock and
    /// `f_frsize = f_bsize` when the backend left it zero. `f_namelen` defaults
    /// to `NAME_MAX`, the value every generic Linux `s_op->statfs`
    /// (`simple_statfs`, `shmem_statfs`) reports. Block/inode COUNTS are never
    /// defaulted: a backend that reports zero blocks has zero blocks, which is
    /// what Linux reports for a pseudo filesystem.
    /// # C: O(1)
pub fn statfs(&self) -> KResult<SbStatFs> {
        let mut st = self.s_op.statfs()?;
        if st.f_type == 0 { st.f_type = self.s_magic; }
        if st.f_bsize == 0 { st.f_bsize = self.s_blocksize; }
        if st.f_fsid == 0 { st.f_fsid = self.s_dev; }
        if st.f_namelen == 0 { st.f_namelen = crate::path::NAME_MAX as u64; }
        if st.f_frsize == 0 { st.f_frsize = st.f_bsize; }
        Ok(st)
    }

    /// `s_op->show_options` passthrough — the backend's fs-specific `/proc/mounts`
    /// option tail (each option self-comma-prefixed), appended after the generic
    /// per-mount flags. The SB-level entry point a `/proc/self/mountinfo` reader
    /// calls in hand of the `Arc<SuperBlock>` (mirrors the [`Self::statfs`]
    /// passthrough). # C: O(len opts)
    pub fn show_options(&self) -> String { self.s_op.show_options() }

    /// `s_op->show_devname` passthrough — backend override of the source-device
    /// column, or `None` for the generic `s_id` source. # C: O(len name)
    pub fn show_devname(&self) -> Option<String> { self.s_op.show_devname() }

    /// `s_op->show_path` passthrough — backend override of the mount-point path
    /// column, or `None` for the generic resolved path. # C: O(len path)
    pub fn show_path(&self) -> Option<String> { self.s_op.show_path() }

    /// `s_op->show_stats` passthrough — backend `/proc/self/mountstats` body, or
    /// `None`. # C: O(len stats)
    pub fn show_stats(&self) -> Option<String> { self.s_op.show_stats() }

    /// `__mark_inode_dirty` (Linux fs/fs-writeback.c) → `s_op->dirty_inode`: run
    /// the backend dirty-tracking hook for `inode` with the `I_DIRTY_*` `flags`
    /// being applied (default ORs them into `i_state`). The icache-keyed
    /// [`Self::mark_inode_dirty`] sets state + reconciles the writeback pin by
    /// `ino`; THIS is the `s_op` dispatch in hand of the concrete inode (the path
    /// `__mark_inode_dirty` takes before consulting the writeback list).
    /// # C: O(1)
    pub fn dirty_inode(&self, inode: &Inode, flags: u32) { self.s_op.dirty_inode(inode, flags); }

}
