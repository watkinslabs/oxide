// Queue-limit update validation and stacking use the Linux block ABI objects.
use crate::linux_block::types::*;

const FEAT_WRITE_CACHE: u32 = 1 << 0;
const FEAT_FUA: u32 = 1 << 1;
const FEAT_NOWAIT: u32 = 1 << 7;
const FEAT_POLL: u32 = 1 << 9;
const FEAT_PCI_P2PDMA: u32 = 1 << 12;
const FEAT_INHERIT: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5) | (1 << 10) | (1 << 15);
const FLAG_MISALIGNED: u32 = 1 << 1;
const STACK_SEG_BOUNDARY: usize = u32::MAX as usize;

/// Register Linux queue-limit KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("blk_set_stacking_limits", blk_set_stacking_limits as *const () as usize),
        ("queue_limits_commit_update", queue_limits_commit_update as *const () as usize),
        ("queue_limits_stack_bdev", queue_limits_stack_bdev as *const () as usize),
    ] { export(name, addr, false); }
}

fn min_nz(a: u32, b: u32) -> u32 { if a == 0 { b } else if b == 0 { a } else { a.min(b) } }
fn min_nz16(a: u16, b: u16) -> u16 { if a == 0 { b } else if b == 0 { a } else { a.min(b) } }
fn gcd(mut a: u32, mut b: u32) -> u32 { while b != 0 { let r = a % b; a = b; b = r; } a }
fn lcm_nz(a: u32, b: u32) -> u32 { if a == 0 { b } else if b == 0 { a } else { a / gcd(a, b) * b } }
fn round_sectors(value: u32, logical: u32) -> u32 { value - value % (logical >> LINUX_SECTOR_SHIFT) }

fn validate(lim: &mut LinuxQueueLimits) -> bool {
    if lim.logical_block_size == 0 { lim.logical_block_size = LINUX_SECTOR_SIZE; }
    if !lim.logical_block_size.is_power_of_two() || lim.logical_block_size < LINUX_SECTOR_SIZE { return false; }
    if lim.physical_block_size < lim.logical_block_size { lim.physical_block_size = lim.logical_block_size; }
    if !lim.physical_block_size.is_power_of_two() { return false; }
    lim.io_min = lim.io_min.max(lim.physical_block_size);
    lim.io_opt -= lim.io_opt % lim.physical_block_size;
    if lim.max_hw_sectors == 0 { lim.max_hw_sectors = 255; }
    let sectors = lim.logical_block_size >> LINUX_SECTOR_SHIFT;
    if lim.max_hw_sectors < 8 || sectors > lim.max_hw_sectors { return false; }
    lim.max_hw_sectors = round_sectors(lim.max_hw_sectors, lim.logical_block_size);
    let cap = min_nz(lim.max_hw_sectors, lim.max_dev_sectors);
    lim.max_sectors = round_sectors(if lim.max_user_sectors != 0 { cap.min(lim.max_user_sectors) } else { cap.min(8192) }, lim.logical_block_size);
    if lim.max_segments == 0 { lim.max_segments = MAX_SEGMENTS; }
    if lim.max_hw_wzeroes_unmap_sectors != 0 && lim.max_hw_wzeroes_unmap_sectors != lim.max_write_zeroes_sectors { return false; }
    lim.max_wzeroes_unmap_sectors = lim.max_hw_wzeroes_unmap_sectors.min(lim.max_user_wzeroes_unmap_sectors);
    lim.max_discard_sectors = lim.max_hw_discard_sectors.min(lim.max_user_discard_sectors);
    lim.discard_granularity = if lim.max_discard_sectors == 0 { 0 } else { lim.discard_granularity.max(lim.physical_block_size) };
    if lim.max_discard_segments == 0 { lim.max_discard_segments = 1; }
    if lim.seg_boundary_mask == 0 { lim.seg_boundary_mask = STACK_SEG_BOUNDARY; }
    if lim.seg_boundary_mask < 4095 { return false; }
    if lim.max_segment_size == 0 { lim.max_segment_size = if lim.virt_boundary_mask == 0 { 65536 } else { u32::MAX }; }
    if lim.virt_boundary_mask == 0 && lim.max_segment_size < 4096 { return false; }
    lim.max_fast_segment_size = lim.max_segment_size.min((lim.seg_boundary_mask.saturating_add(1)).min(u32::MAX as usize) as u32).min(4096);
    if lim.dma_alignment == 0 { lim.dma_alignment = LINUX_SECTOR_SIZE - 1; }
    if lim.dma_alignment > 4096 { return false; }
    if lim.alignment_offset != 0 { lim.alignment_offset &= lim.physical_block_size - 1; lim.flags &= !FLAG_MISALIGNED; }
    if lim.features & FEAT_WRITE_CACHE == 0 { lim.features &= !FEAT_FUA; }
    true
}

unsafe extern "C" fn blk_set_stacking_limits(lim: *mut LinuxQueueLimits) {
    if lim.is_null() { return; }
    let mut out = unsafe { core::mem::zeroed::<LinuxQueueLimits>() };
    out.logical_block_size = LINUX_SECTOR_SIZE;
    out.physical_block_size = LINUX_SECTOR_SIZE;
    out.io_min = LINUX_SECTOR_SIZE;
    out.discard_granularity = LINUX_SECTOR_SIZE;
    out.dma_alignment = LINUX_SECTOR_SIZE - 1;
    out.seg_boundary_mask = STACK_SEG_BOUNDARY;
    out.max_segments = u16::MAX;
    out.max_discard_segments = u16::MAX;
    out.max_hw_sectors = u32::MAX;
    out.max_segment_size = u32::MAX;
    out.max_sectors = u32::MAX;
    out.max_dev_sectors = u32::MAX;
    out.max_write_zeroes_sectors = u32::MAX;
    out.max_hw_wzeroes_unmap_sectors = u32::MAX;
    out.max_user_wzeroes_unmap_sectors = u32::MAX;
    out.max_hw_zone_append_sectors = u32::MAX;
    out.max_user_discard_sectors = u32::MAX;
    out.atomic_write_hw_max = u32::MAX;
    // SAFETY: lim is non-null caller-owned queue-limit ABI storage and out is a fully initialized value.
    unsafe { *lim = out; }
}

unsafe extern "C" fn queue_limits_commit_update(q: *mut LinuxRequestQueue, lim: *mut LinuxQueueLimits) -> i32 {
    if q.is_null() || lim.is_null() { return -LINUX_EINVAL; }
    // SAFETY: q and lim are non-null Linux ABI objects held by the caller's limit-update transaction.
    let lim = unsafe { &mut *lim };
    if !validate(lim) { return -LINUX_EINVAL; }
    // SAFETY: the caller owns the update transaction and commit replaces the queue's full validated snapshot.
    unsafe { (*q).limits = *lim; }
    LINUX_OK
}

fn stack(t: &mut LinuxQueueLimits, b: &LinuxQueueLimits, start: u64) -> bool {
    let mut aligned = true;
    t.features |= b.features & FEAT_INHERIT;
    for feature in [FEAT_NOWAIT, FEAT_POLL, FEAT_PCI_P2PDMA] { if b.features & feature == 0 { t.features &= !feature; } }
    t.flags |= b.flags & FLAG_MISALIGNED;
    t.max_sectors = min_nz(t.max_sectors, b.max_sectors); t.max_user_sectors = min_nz(t.max_user_sectors, b.max_user_sectors);
    t.max_hw_sectors = min_nz(t.max_hw_sectors, b.max_hw_sectors); t.max_dev_sectors = min_nz(t.max_dev_sectors, b.max_dev_sectors);
    t.max_write_zeroes_sectors = t.max_write_zeroes_sectors.min(b.max_write_zeroes_sectors);
    t.max_user_wzeroes_unmap_sectors = t.max_user_wzeroes_unmap_sectors.min(b.max_user_wzeroes_unmap_sectors);
    t.max_hw_wzeroes_unmap_sectors = t.max_hw_wzeroes_unmap_sectors.min(b.max_hw_wzeroes_unmap_sectors);
    t.max_hw_zone_append_sectors = t.max_hw_zone_append_sectors.min(b.max_hw_zone_append_sectors);
    t.seg_boundary_mask = if t.seg_boundary_mask == 0 { b.seg_boundary_mask } else if b.seg_boundary_mask == 0 { t.seg_boundary_mask } else { t.seg_boundary_mask.min(b.seg_boundary_mask) };
    t.virt_boundary_mask = if t.virt_boundary_mask == 0 { b.virt_boundary_mask } else if b.virt_boundary_mask == 0 { t.virt_boundary_mask } else { t.virt_boundary_mask.min(b.virt_boundary_mask) };
    t.max_segments = min_nz16(t.max_segments, b.max_segments); t.max_discard_segments = min_nz16(t.max_discard_segments, b.max_discard_segments); t.max_integrity_segments = min_nz16(t.max_integrity_segments, b.max_integrity_segments);
    t.max_segment_size = min_nz(t.max_segment_size, b.max_segment_size);
    let gran = b.physical_block_size.max(b.io_min) as u64;
    let bottom = if gran == 0 { 0 } else { ((start << LINUX_SECTOR_SHIFT) % gran) as u32 + b.alignment_offset };
    if t.alignment_offset != bottom { let top = t.physical_block_size.max(t.io_min) + t.alignment_offset; let lower = b.physical_block_size.max(b.io_min) + bottom; if top.max(lower) % top.min(lower).max(1) != 0 { aligned = false; } }
    t.logical_block_size = t.logical_block_size.max(b.logical_block_size); t.physical_block_size = t.physical_block_size.max(b.physical_block_size); t.io_min = t.io_min.max(b.io_min); t.io_opt = lcm_nz(t.io_opt, b.io_opt); t.dma_alignment = t.dma_alignment.max(b.dma_alignment);
    if b.chunk_sectors != 0 { t.chunk_sectors = gcd(t.chunk_sectors, b.chunk_sectors); }
    if t.physical_block_size % t.logical_block_size != 0 { t.physical_block_size = t.logical_block_size; aligned = false; }
    if t.io_min % t.physical_block_size != 0 { t.io_min = t.physical_block_size; aligned = false; }
    if t.io_opt % t.physical_block_size != 0 { t.io_opt = 0; aligned = false; }
    let physical_sectors = t.physical_block_size >> LINUX_SECTOR_SHIFT;
    if physical_sectors != 0 && t.chunk_sectors % physical_sectors != 0 { t.chunk_sectors = 0; aligned = false; }
    t.alignment_offset = lcm_nz(t.alignment_offset, bottom) % t.physical_block_size.max(t.io_min);
    if t.alignment_offset % t.logical_block_size != 0 { aligned = false; }
    t.max_sectors = round_sectors(t.max_sectors, t.logical_block_size); t.max_hw_sectors = round_sectors(t.max_hw_sectors, t.logical_block_size); t.max_dev_sectors = round_sectors(t.max_dev_sectors, t.logical_block_size);
    if b.discard_granularity != 0 { let align = ((start << LINUX_SECTOR_SHIFT) % b.discard_granularity as u64) as u32 + b.discard_alignment; t.max_discard_sectors = min_nz(t.max_discard_sectors, b.max_discard_sectors); t.max_hw_discard_sectors = min_nz(t.max_hw_discard_sectors, b.max_hw_discard_sectors); t.discard_granularity = t.discard_granularity.max(b.discard_granularity); t.discard_alignment = lcm_nz(t.discard_alignment, align) % t.discard_granularity; }
    t.max_secure_erase_sectors = min_nz(t.max_secure_erase_sectors, b.max_secure_erase_sectors); t.zone_write_granularity = t.zone_write_granularity.max(b.zone_write_granularity);
    if !aligned { t.flags |= FLAG_MISALIGNED; }
    aligned
}

unsafe extern "C" fn queue_limits_stack_bdev(t: *mut LinuxQueueLimits, bdev: *mut LinuxBlockDevice, offset: u64, _pfx: *const i8) {
    if t.is_null() || bdev.is_null() { return; }
    // SAFETY: bdev is a live block-device ABI object; its disk is the canonical owner of the queue limits.
    let (q, start) = unsafe { let disk = (*bdev).bd_disk; if disk.is_null() { return; } ((*disk).queue, (*bdev).bd_start_sect.saturating_add(offset)) };
    if q.is_null() { return; }
    // SAFETY: t is caller-owned stacking state and q is the live lower queue selected through bdev's disk.
    unsafe { stack(&mut *t, &(*q).limits, start); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stacking_combines_limits_and_marks_incompatible_topology() {
        let mut top = crate::linux_block::core::default_limits();
        let mut bottom = crate::linux_block::core::default_limits();
        top.max_sectors = 1024; top.max_segments = 64; top.features = FEAT_NOWAIT | FEAT_POLL | FEAT_PCI_P2PDMA;
        bottom.max_sectors = 511; bottom.max_segments = 32; bottom.logical_block_size = 4096;
        bottom.physical_block_size = 4096; bottom.io_min = 4096; bottom.features = FEAT_NOWAIT;
        assert!(stack(&mut top, &bottom, 0));
        assert_eq!(top.max_segments, 32);
        assert_eq!(top.logical_block_size, 4096);
        assert_eq!(top.max_sectors, 504);
        assert_eq!(top.features & (FEAT_NOWAIT | FEAT_POLL | FEAT_PCI_P2PDMA), FEAT_NOWAIT);
        bottom.alignment_offset = 512;
        assert!(!stack(&mut top, &bottom, 0));
        assert_ne!(top.flags & FLAG_MISALIGNED, 0);
    }

    #[test]
    fn commit_normalizes_and_rejects_invalid_limit_snapshots() {
        let q = crate::linux_block::core::blk_alloc_queue(0);
        assert!(!q.is_null());
        let mut lim = crate::linux_block::core::default_limits();
        lim.logical_block_size = 4096; lim.physical_block_size = 0; lim.max_hw_sectors = 513;
        // SAFETY: q is a fresh queue and lim is this test's mutable ABI snapshot.
        assert_eq!(unsafe { queue_limits_commit_update(q, &mut lim) }, LINUX_OK);
        assert_eq!(lim.physical_block_size, 4096);
        assert_eq!(lim.max_hw_sectors, 512);
        lim.logical_block_size = 768;
        // SAFETY: q remains live and lim is still owned by this test.
        assert_eq!(unsafe { queue_limits_commit_update(q, &mut lim) }, -LINUX_EINVAL);
        // SAFETY: q is the fresh test queue and is not published or in use.
        unsafe { crate::linux_block::core::blk_cleanup_queue(q); }
    }
}
