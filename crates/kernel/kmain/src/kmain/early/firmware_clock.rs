//! Retained device-tree ownership and early persistent-clock installation.

use crate::BootInfo;

/// Publish the retained FDT, then install CMOS/PL031 as the one persistent
/// clock used for both boot wall time and system-sleep accounting.
/// # SAFETY: caller runs after PMM, MMU/HHDM and page-table allocation are
/// live; the DT physical extent is reserved for kernel life.
/// # C: O(struct_block_size + mapped pages)
pub(super) unsafe fn init(info: &BootInfo) {
    if info.dtb_pa != 0 && info.dtb_len != 0 && info.hhdm_offset != 0 {
        let va = info.hhdm_offset.wrapping_add(info.dtb_pa);
        // SAFETY: `va` is the direct-map mirror of the retained, reserved
        // physical extent; firmware revalidates its header before publishing.
        unsafe { firmware::fdt::retain(va, info.dtb_pa, info.dtb_len, info.dtb_crc32); }
    }
    crate::kmain::suspend_wiring::init_persistent_clock();
}
