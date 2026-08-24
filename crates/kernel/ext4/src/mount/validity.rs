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
    let gdt_start = if sb.block_size == 1024 { 2 } else { 1 };
    add(gdt_start, (gdt_buf.len() as u64 + bs - 1) / bs);
    let inode_blocks = (u64::from(sb.inodes_per_group) * u64::from(sb.inode_size) + bs - 1) / bs;
    for group in 0..sb.group_count() {
        let first = u64::from(sb.first_data_block) + u64::from(group) * u64::from(sb.blocks_per_group);
        let has_super = !sb.has_sparse_super() || group == 0 || group == 1 || is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7);
        if has_super {
            add(first, 1);
            add(first + 1, (gdt_buf.len() as u64 + bs - 1) / bs);
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
}
