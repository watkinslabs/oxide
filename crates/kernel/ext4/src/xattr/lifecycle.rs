use crate::mount::{Mount, MountError};

impl Mount {
    /// Remove and free an inode's external xattr block during final deletion.
    /// The caller releases the inode's complete pre-deletion `i_blocks` quota
    /// charge, so this disk teardown must not emit a second quota delta.
    /// # C: O(1) metadata I/O
    pub(crate) fn free_external_xattr_for_deletion(&self, ino: u32) -> Result<(), MountError> {
        let (mut bytes, _) = self.read_inode_bytes(ino)?;
        let block = Self::file_acl_of(&bytes);
        if block == 0 { return Ok(()); }

        Self::detach_external_block(&mut bytes, self.sb.block_size as usize);
        self.write_inode_bytes(ino, &bytes)?;
        self.free_block(block)
    }
}
