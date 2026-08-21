// Temporary translation tables for the terminal restore window.

use hal::pt_walker::{map_at_level_with_root, PtWalker, WalkErr};
use hal::PageFlags;

use crate::vmm::PtWalkerArm;

use super::{ArchHeader, LinearMap, PlanError, PAGE_BYTES};

const BLOCK_BYTES: u64 = 2 * 1024 * 1024;
const BLOCK_LEVEL: u8 = 2;
const PAGE_LEVEL: u8 = 3;

fn map_error(error: WalkErr) -> PlanError {
    match error {
        WalkErr::AllocFailed => PlanError::Capacity,
        WalkErr::HitHugeOrBlock | WalkErr::AlreadyMapped => PlanError::Range,
    }
}

/// Construct the two inactive table roots consumed by terminal restore.
///
/// TTBR0 identity-maps only the copied trampoline and restored context. TTBR1
/// maps the admitted physical window at its temporary linear offset with 2 MiB
/// blocks. `alloc` remains the sole owner of every zeroed intermediate table.
///
/// # Safety
/// Roots and every allocation are exclusive zeroed destination-safe
/// pages; `hhdm_offset + page_pa` is their writable live-kernel mapping; no
/// concurrent walker can observe either inactive root.
/// # C: O(linear-map bytes / 2 MiB + page-table depth)
pub unsafe fn build_temporary_tables<F: FnMut() -> Option<u64>>(
    h: &ArchHeader, ttbr0_root_pa: u64, ttbr1_root_pa: u64, hhdm_offset: u64,
    trampoline_pa: u64, linear: LinearMap, mut alloc: F,
) -> Result<(), PlanError> {
    super::validate_header(h)?;
    if ttbr0_root_pa == 0 || ttbr1_root_pa == 0 || trampoline_pa == 0
        || !ttbr0_root_pa.is_multiple_of(PAGE_BYTES) || !ttbr1_root_pa.is_multiple_of(PAGE_BYTES)
        || !trampoline_pa.is_multiple_of(PAGE_BYTES) || !hhdm_offset.is_multiple_of(PAGE_BYTES) {
        return Err(PlanError::Alignment);
    }
    if linear.physical.start >= linear.physical.end
        || !linear.physical.start.is_multiple_of(BLOCK_BYTES)
        || !linear.physical.end.is_multiple_of(BLOCK_BYTES)
        || !linear.va_offset.is_multiple_of(BLOCK_BYTES) { return Err(PlanError::Range); }
    let rx = PageFlags::READ | PageFlags::EXEC;
    let rw = PageFlags::READ | PageFlags::WRITE;
    let trampoline_leaf = PtWalkerArm::pack_4k_leaf(trampoline_pa, rx);
    // SAFETY: fn contract supplies the exclusive root, HHDM and allocator.
    unsafe { map_at_level_with_root::<PtWalkerArm, _>(ttbr0_root_pa, trampoline_pa,
        PAGE_LEVEL, trampoline_leaf, hhdm_offset, &mut alloc).map_err(map_error)?; }
    let context_leaf = PtWalkerArm::pack_4k_leaf(h.context_pa, rw);
    // SAFETY: same inactive-root ownership; context and trampoline are distinct admitted pages.
    unsafe { map_at_level_with_root::<PtWalkerArm, _>(ttbr0_root_pa, h.context_pa,
        PAGE_LEVEL, context_leaf, hhdm_offset, &mut alloc).map_err(map_error)?; }
    let mut pa = linear.physical.start;
    while pa < linear.physical.end {
        let va = pa.checked_add(linear.va_offset).ok_or(PlanError::Range)?;
        let leaf = PtWalkerArm::pack_block_leaf(pa, rw);
        // SAFETY: same contract; each aligned block is written once into the inactive TTBR1 tree.
        unsafe { map_at_level_with_root::<PtWalkerArm, _>(ttbr1_root_pa, va,
            BLOCK_LEVEL, leaf, hhdm_offset, &mut alloc).map_err(map_error)?; }
        pa = pa.checked_add(BLOCK_BYTES).ok_or(PlanError::Range)?;
    }
    Ok(())
}
