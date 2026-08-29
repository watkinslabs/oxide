// Freeing a block, and handing it back to the device.
//
// `-o discard` is what makes the second half exist: without it a filesystem
// that frees a block leaves the device believing those contents still matter,
// which on flash costs write amplification for the life of the block.

use crate::gdt;
use crate::mount::{Mount, MountError};
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::Ordering;

impl Mount {
    /// Free a block previously returned by `alloc_block`. Clears
    /// the bitmap bit + bumps both counters. Wraps in a journal
    /// scope. `DoubleFree` if the bit was already clear.
    /// # C: O(block_size) within one group
    pub fn free_block(&self, phys_blk: u64) -> Result<(), MountError> {
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.faults.next_free_block.swap(false, Ordering::AcqRel) { return Err(MountError::BlockIo); }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let left = self.faults.free_block_after.load(Ordering::Acquire);
            if left != 0 && self.faults.free_block_after.fetch_sub(1, Ordering::AcqRel) == 1 {
                return Err(MountError::BlockIo);
            }
        }
        let r = self.free_block_inner(phys_blk);
        // The block is now free as far as the filesystem is concerned, so tell
        // the device it no longer has to preserve those contents. Issued AFTER
        // the bitmap transaction, never before: a discard that landed first and
        // then lost its transaction would have destroyed live data.
        if r.is_ok() && self.behaviour().discard { self.issue_discard(phys_blk); }
        r
    }

    /// Hand one freed filesystem block back to the device (`-o discard`).
    ///
    /// A device advertising no discard limit is not asked — an unsupported
    /// operation is not a capability probe. Failure is dropped on purpose: the
    /// block IS free, the trim is an optimisation, and turning a device's
    /// refusal into a failed `unlink` would be the worse answer. That is also
    /// what the reference does with the one error it expects here.
    /// # C: O(1) submission
    fn issue_discard(&self, phys_blk: u64) {
        if !self.dev.supports_discard() { return; }
        let dev_bs = self.dev.block_size() as u64;
        if dev_bs == 0 { return; }
        let fs_bs = self.sb.block_size as u64;
        // The filesystem block is addressed in device sectors. One smaller than
        // a sector covers no whole sector of its own, so trimming it would
        // reach a neighbouring block's live data.
        if fs_bs < dev_bs { return; }
        let per_fs_block = fs_bs / dev_bs;
        let mut req = block::BlockRequest::new_discard(phys_blk * per_fs_block, per_fs_block as u32);
        let _ = self.dev.submit_sync(&mut req);
    }

    fn free_block_inner(&self, phys_blk: u64) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (group, bit) = m.locate_block(phys_blk)?;
            let group_lock = m.group_lock(group);
            // SAFETY: process context, with no spinlock held.
            let _group_guard = unsafe { group_lock.lock() };
            // SAFETY: the GDT owner is a sleepable leaf and no spinlock is held.
            let _gdt_guard = unsafe { m.gdt_lock.lock() };
            let gdt_bytes = m.read_gdt_bytes()?;
            let gd_orig = gdt::parse_descriptor(&gdt_bytes, group, &m.sb)?;
            let bbm_byte_off = gd_orig.block_bitmap * (m.sb.block_size as u64);
            let cached = m.cached_group_bitmap(bbm_byte_off);
            // The metadata cache stores the authoritative disk image. PA
            // reservations are already free bits in that image; only the
            // allocator's scan view is masked, so never clear PA bits here
            // before verifying the on-disk checksum.
            let mut bitmap = cached.unwrap_or(m.read_meta_byte_range(bbm_byte_off, m.sb.block_size as usize)?);
            let mut disk_bitmap = bitmap.clone();
            if !crate::csum::verify_block_bitmap_csum_at(&m.sb, &gdt_bytes, group, &disk_bitmap) {
                crate::mount::first_csum_failure(b"block-bitmap-free", group as u64, bbm_byte_off);
                return Err(MountError::BadChecksum);
            }
            let bidx = bit as usize;
            let mask = 1u8 << (bidx & 7);
            if (disk_bitmap[bidx >> 3] & mask) == 0 {
                return Err(MountError::DoubleFree);
            }
            bitmap[bidx >> 3] &= !mask;
            disk_bitmap[bidx >> 3] &= !mask;
            // Update the cached GDT image; the superblock counter is updated
            // from its authoritative metadata buffer below.
            let mut gd = gd_orig;
            gd.free_blocks_count = gd.free_blocks_count.saturating_add(1);
            {
                let mut s = m.state.lock();
                gdt::write_descriptor_counters(&mut s.gdt_buf, group, &m.sb, &gd)?;
                crate::csum::set_block_bitmap_csum(&m.sb, &mut s.gdt_buf, group, &disk_bitmap);
                crate::csum::stamp_group_desc_csum(&m.sb, &mut s.gdt_buf, group);
            }
            m.metadata_write(bbm_byte_off, &disk_bitmap)?;
            m.persist_gdt_slot_meta(group)?;
            m.persist_sb_free_blocks_meta(1)?;
            m.flush_pending_tx()?;
            m.publish_group_bitmap(group, bbm_byte_off, bitmap);
            Ok(())
        })
    }
}
