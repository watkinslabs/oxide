use crate::inode::{self, I_BLOCK_LEN};
use crate::mount::{Mount, MountError};
use alloc::vec::Vec;

impl Mount {
    pub(super) fn persist_inode_after_append(
        &self, ino: u32, ino_bytes: &mut alloc::vec::Vec<u8>, _ino_byte_off: u64,
        i_block: &[u8; I_BLOCK_LEN], new_size: u64, extra_meta_sectors: u32,
    ) -> Result<(), MountError> {
        ino_bytes[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(i_block);
        ino_bytes[0x04..0x08].copy_from_slice(&((new_size & 0xFFFF_FFFF) as u32).to_le_bytes());
        ino_bytes[0x6C..0x70].copy_from_slice(&((new_size >> 32) as u32).to_le_bytes());
        let prev_i_blocks = u32::from_le_bytes([ino_bytes[0x1C], ino_bytes[0x1D], ino_bytes[0x1E], ino_bytes[0x1F]]);
        let added_sectors = (self.sb.block_size / 512) as u32 + extra_meta_sectors;
        let new_i_blocks = prev_i_blocks.saturating_add(added_sectors);
        ino_bytes[0x1C..0x20].copy_from_slice(&new_i_blocks.to_le_bytes());
        self.write_inode_bytes(ino, ino_bytes)
    }

    /// Read the raw on-disk inode slot bytes for `ino`. Returns the
    /// bytes + the byte offset they were read from (so the caller
    /// can write the mutated buffer back to the same slot).
    /// # C: O(1) I/O
    pub fn read_inode_bytes(&self, ino: u32) -> Result<(Vec<u8>, u64), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        let bytes = self.read_meta_byte_range(byte_off, self.sb.inode_size as usize)?;
        Ok((bytes, byte_off))
    }

    /// Write a freshly-mutated inode-bytes slot back to disk. Stamps
    /// the metadata_csum (`i_checksum_lo`/`_hi`) before writing so the
    /// slot is valid for stock Linux/e2fsck (no-op without the feature).
    /// # C: O(inode_size) csum + O(1) I/O
    pub fn write_inode_bytes(&self, ino: u32, bytes: &[u8]) -> Result<(), MountError> {
        let (group, idx) = crate::gdt::locate_inode(&self.sb, ino)?;
        let gd = self.group_desc(group)?;
        let off_in_table = (idx as u64) * (self.sb.inode_size as u64);
        let byte_off = gd.inode_table * (self.sb.block_size as u64) + off_in_table;
        if bytes.len() != self.sb.inode_size as usize {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        let mut owned = bytes.to_vec();
        crate::csum::stamp_inode_csum(&self.sb, ino, &mut owned);
        // Inode bytes are metadata — route through journaled path.
        self.metadata_write(byte_off, &owned)
    }

    /// Stamp the `ext4_extent_tail` csum into an external extent
    /// block buffer and write it (journaled). The inline i_block
    /// extent root has no tail — it rides the inode csum — so this
    /// is only for allocated leaf/interior blocks.
    /// # C: O(bs) csum + 1 block I/O
    pub(crate) fn write_extent_block(&self, ino: u32, gen: u32, lba: u64, buf: &mut Vec<u8>)
        -> Result<(), MountError>
    {
        let _ = ino;
        crate::csum::stamp_extent_block_csum(&self.sb, ino, gen, buf);
        let bs = self.sb.block_size as u64;
        self.metadata_write(lba * bs, buf)
    }

    /// Read this inode's on-disk `i_generation` (csum keying input).
    /// # C: O(1)
    pub(super) fn inode_generation(ino_bytes: &[u8]) -> u32 {
        u32::from_le_bytes([ino_bytes[0x64], ino_bytes[0x65], ino_bytes[0x66], ino_bytes[0x67]])
    }

    /// Group containing a given physical block. Inverse of
    /// `group_first_block`.
    /// # C: O(1)
    pub fn group_of_block(&self, phys: u64) -> u32 {
        let bpg = self.sb.blocks_per_group as u64;
        if bpg == 0 { return 0; }
        let rel = phys.saturating_sub(self.sb.first_data_block as u64);
        (rel / bpg) as u32
    }
}
