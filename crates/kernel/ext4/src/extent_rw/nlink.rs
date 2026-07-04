use crate::mount::{Mount, MountError};

impl Mount {
    /// Bump or decrement the link count of an inode, saturating at zero.
    /// # C: O(1) I/O
    pub fn adjust_nlink(&self, ino: u32, delta: i32) -> Result<u16, MountError> {
        let (mut bytes, off) = self.read_inode_bytes(ino)?;
        let cur = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
        let new = if delta >= 0 {
            cur.saturating_add(delta as u16)
        } else {
            cur.saturating_sub((-delta) as u16)
        };
        bytes[0x1A..0x1C].copy_from_slice(&new.to_le_bytes());
        let _ = off;
        self.write_inode_bytes(ino, &bytes)?;
        Ok(new)
    }
}
