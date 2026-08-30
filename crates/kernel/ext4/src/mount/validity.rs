//! Linux ext4 `system_blks` ownership and inode extent block validation.

use alloc::vec::Vec;

use crate::gdt;
use crate::superblock::Superblock;

/// Build the immutable reserved-system-block ranges Linux keeps in its
/// `system_blks` tree. Ranges are half-open filesystem-block intervals.
/// # C: O(groups)
pub(crate) fn build_system_zones(sb: &Superblock, gdt_buf: &[u8]) -> Vec<(u64, u64)> {
    let mut zones = Vec::new();
    let mut add = |start: u64, len: u64| { if len != 0 { zones.push((start, start.saturating_add(len))); } };
    add(0, sb.first_data_block as u64);
    let bs = u64::from(sb.block_size);
    add(1024 / bs, 1);
    let gdt_blocks = (gdt_buf.len() as u64 + bs - 1) / bs;
    if sb.feature_incompat & crate::superblock::INCOMPAT_META_BG == 0 {
        let gdt_start = if sb.block_size == 1024 { 2 } else { 1 };
        add(gdt_start, gdt_blocks);
    } else {
        for block in 0..gdt_blocks {
            let byte = crate::mount::gdt_block_byte_offset_for(sb, block as u32);
            add(byte / bs, 1);
        }
    }
    let inode_blocks = (u64::from(sb.inodes_per_group) * u64::from(sb.inode_size) + bs - 1) / bs;
    for group in 0..sb.group_count() {
        let first = u64::from(sb.first_data_block) + u64::from(group) * u64::from(sb.blocks_per_group);
        let has_super = !sb.has_sparse_super() || group == 0 || group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7);
        if has_super {
            add(first, 1);
            if sb.feature_incompat & crate::superblock::INCOMPAT_META_BG == 0 {
                add(first + 1, gdt_blocks);
            }
        }
        let Ok(desc) = gdt::parse_descriptor(gdt_buf, group, sb) else { continue; };
        add(desc.block_bitmap, 1);
        add(desc.inode_bitmap, 1);
        add(desc.inode_table, inode_blocks);
    }
    zones.sort_unstable_by_key(|zone| zone.0);
    zones
}

fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < base { return false; }
    while value % base == 0 { value /= base; }
    value == 1
}

impl crate::mount::Mount {
    /// Reject a file extent that overlaps filesystem-owned metadata or leaves
    /// the filesystem. Linux returns a bad mapping rather than reading a
    /// superblock, bitmap, or inode table as user file data. # C: O(zones)
    pub(crate) fn check_inode_blocks(&self, start: u64, len: u64) -> Result<(), crate::mount::MountError> {
        if !range_allowed(&self.system_zones, self.sb.blocks_count(), self.behaviour().block_validity, start, len) {
            return Err(crate::mount::MountError::BadBlock);
        }
        Ok(())
    }
}

fn range_allowed(zones: &[(u64, u64)], total: u64, enabled: bool, start: u64, len: u64) -> bool {
    if !enabled { return true; }
    let Some(end) = start.checked_add(len) else { return false; };
    end <= total && !zones.iter().any(|&(lo, hi)| start < hi && lo < end)
}

#[cfg(test)]
mod tests {
    use super::range_allowed;
    use crate::superblock::{Superblock, EXT4_SUPER_MAGIC, INCOMPAT_64BIT, INCOMPAT_META_BG};

    fn meta_sb() -> Superblock {
        let mut bytes = [0u8; crate::superblock::SUPERBLOCK_LEN];
        bytes[0x04..0x08].copy_from_slice(&65536u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());
        bytes[0x28..0x2c].copy_from_slice(&1024u32.to_le_bytes());
        bytes[0x38..0x3a].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
        bytes[0x60..0x64].copy_from_slice(&(INCOMPAT_64BIT | INCOMPAT_META_BG).to_le_bytes());
        bytes[0x64..0x68].copy_from_slice(&crate::superblock::RO_COMPAT_SPARSE_SUPER.to_le_bytes());
        bytes[0xfe..0x100].copy_from_slice(&64u16.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&1u32.to_le_bytes());
        Superblock::parse(&bytes).expect("meta_bg superblock")
    }

    #[test]
    fn block_validity_rejects_reserved_and_out_of_range_runs() {
        let zones = [(0, 2), (8, 10)];
        assert!(!range_allowed(&zones, 32, true, 1, 1));
        assert!(!range_allowed(&zones, 32, true, 9, 2));
        assert!(!range_allowed(&zones, 32, true, 31, 2));
        assert!(!range_allowed(&zones, 32, true, u64::MAX, 1));
        assert!(range_allowed(&zones, 32, true, 2, 6));
        assert!(range_allowed(&zones, 32, false, 1, 1));
    }

    #[test]
    fn meta_bg_descriptor_blocks_follow_their_group_geometry() {
        let sb = meta_sb();
        assert_eq!(crate::mount::gdt_block_byte_offset_for(&sb, 0), 4096);
        assert_eq!(crate::mount::gdt_block_byte_offset_for(&sb, 1), 32768u64 * 64 * 4096);
    }
}
