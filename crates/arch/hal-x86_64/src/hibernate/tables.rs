// Temporary mappings used only by the terminal restore window.

use hal::pt_walker::{map_at_level_with_root, PtWalker, WalkErr};
use hal::PageFlags;

use crate::vmm::PtWalkerX86;

use super::{page_base, ArchHeader, PhysRange, PlanError, TextMapping, PAGE_BYTES};

/// Conservative huge-leaf size requiring no optional CPU feature.
pub const BLOCK_BYTES: u64 = 2 * 1024 * 1024;
const BLOCK_LEVEL: u8 = 2;
const PAGE_LEVEL: u8 = 3;

fn map_error(e: WalkErr) -> PlanError {
    match e {
        WalkErr::AllocFailed => PlanError::TooMany,
        WalkErr::HitHugeOrBlock | WalkErr::AlreadyMapped => PlanError::Range,
    }
}

/// Build the temporary HHDM and restored-text mapping into a fresh root.
///
/// `alloc` is the sole page owner: it yields fresh, zeroed, destination-safe
/// page-table frames. `root_pa` is one such frame and is already zero. The
/// direct interval is widened to 2 MiB leaves, matching the minimum x86 huge
/// page support; the one image text page remains a 4 KiB executable leaf.
///
/// # SAFETY: every table frame belongs exclusively to this restore, `hhdm`
/// maps each frame writable in the live kernel, and no yielded frame appears
/// as an image destination.
/// # C: O(direct bytes / 2 MiB + page-table depth)
pub unsafe fn build_temporary_tables<F: FnMut() -> Option<u64>>(
    h: &ArchHeader, root_pa: u64, hhdm: u64, direct: PhysRange,
    text: TextMapping, mut alloc: F,
) -> Result<(), PlanError> {
    super::validate_header(h)?;
    if h.paging_levels != 4 { return Err(PlanError::Header); }
    if root_pa == 0 || root_pa % PAGE_BYTES != 0 || hhdm == 0 || hhdm % BLOCK_BYTES != 0 {
        return Err(PlanError::Alignment);
    }
    if !direct.valid() || text.va != page_base(h.restore_entry_va)
        || text.pa != page_base(h.restore_entry_pa)
    { return Err(PlanError::Range); }

    let start = direct.start & !(BLOCK_BYTES - 1);
    let end = direct.end.checked_add(BLOCK_BYTES - 1).ok_or(PlanError::Range)? & !(BLOCK_BYTES - 1);
    let flags = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC;
    let mut pa = start;
    while pa < end {
        let leaf = PtWalkerX86::pack_block_leaf(pa, flags);
        // SAFETY: fn contract supplies exclusive zeroed tables and HHDM access.
        unsafe { map_at_level_with_root::<PtWalkerX86, _>(root_pa, hhdm.wrapping_add(pa),
            BLOCK_LEVEL, leaf, hhdm, &mut alloc).map_err(map_error)?; }
        pa += BLOCK_BYTES;
    }

    let leaf = PtWalkerX86::pack_4k_leaf(text.pa, PageFlags::READ | PageFlags::EXEC);
    // SAFETY: same table ownership; the header admission pins the requested page.
    unsafe { map_at_level_with_root::<PtWalkerX86, _>(root_pa, text.va, PAGE_LEVEL,
        leaf, hhdm, &mut alloc).map_err(map_error)?; }
    Ok(())
}
