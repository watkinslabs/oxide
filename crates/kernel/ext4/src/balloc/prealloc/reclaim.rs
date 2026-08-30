use alloc::vec::Vec;

use crate::gdt;
use crate::mount::{Mount, MountError};

impl Mount {
    /// Reclaim complete inode preallocations in filesystem group order. Linux
    /// discards the group PA list before retrying allocation; inode PAs are
    /// members of that same lifecycle even though this port stores them under
    /// their inode owner.
    /// # C: O(N_groups * N_inode_PAs)
    pub(crate) fn discard_inode_preallocations(&self, needed: u32) -> Result<u32, MountError> {
        if needed == 0 { return Ok(0); }
        let gdt_bytes = self.read_gdt_bytes()?;
        let mut released = Vec::new();
        let mut free = 0u32;
        let mut empty = Vec::new();
        {
            let mut s = self.state.lock();
            for group in 0..self.sb.group_count() {
                if free >= needed { break; }
                let inos: Vec<u32> = s.inode_prealloc.keys().copied().collect();
                for ino in inos {
                    if free >= needed { break; }
                    let Some(pas) = s.inode_prealloc.get_mut(&ino) else { continue; };
                    let mut keep = Vec::new();
                    for pa in core::mem::take(pas) {
                        let pa_group = pa.blocks.first().map(|&block| self.group_of_block(block));
                        if pa_group == Some(group) {
                            for (block, used) in pa.blocks.into_iter().zip(pa.used) {
                                if !used {
                                    free = free.saturating_add(1);
                                    released.push(block);
                                }
                            }
                        } else {
                            keep.push(pa);
                        }
                    }
                    *pas = keep;
                    if pas.is_empty() { empty.push(ino); }
                }
                for ino in empty.drain(..) { s.inode_prealloc.remove(&ino); }
            }
        }
        self.refresh_released_prealloc_blocks(&gdt_bytes, released)?;
        Ok(free)
    }

    fn refresh_released_prealloc_blocks(&self, gdt_bytes: &[u8], released: Vec<u64>) -> Result<(), MountError> {
        let mut s = self.state.lock();
        for block in released {
            let Ok((group, bit)) = self.locate_block(block) else { continue; };
            let Ok(gd) = gdt::parse_descriptor(gdt_bytes, group, &self.sb) else { continue; };
            let off = gd.block_bitmap * self.sb.block_size as u64;
            if let Some(bitmap) = s.block_bitmap_cache.get_mut(&off) {
                bitmap[bit as usize >> 3] &= !(1 << (bit & 7));
                let order = super::super::scan::largest_free_order(bitmap, self.blocks_in_group(group));
                let avg = super::super::scan::average_fragment_order(bitmap, self.blocks_in_group(group));
                let old_order = s.group_free_order.insert(group, order.unwrap_or(0));
                super::super::scan::replace_order_index(&mut s.group_free_order_index, group, old_order, order);
                if order.is_none() { s.group_free_order.remove(&group); }
                let old_avg = s.group_avg_fragment_order.insert(group, avg.unwrap_or(0));
                super::super::scan::replace_order_index(&mut s.group_avg_fragment_index, group, old_avg, avg);
                if avg.is_none() { s.group_avg_fragment_order.remove(&group); }
            }
        }
        Ok(())
    }
}
