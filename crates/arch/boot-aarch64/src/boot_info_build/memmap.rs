//! Kernel-image ownership in the ARM boot topology.

use boot_info::{BootMemKind, BootMemRegion};

/// Retain the loaded image even when EFI classified it as loader memory.
/// Existing DT-carved ownership wins; an EFI-only image gets one exact entry.
/// # C: O(n)
pub(super) fn retain_kernel_image(map: &mut [BootMemRegion], count: &mut usize,
                                  start: u64, end: u64) {
    if end <= start || map[..*count].iter().any(|r| r.kind == BootMemKind::KernelImage) { return; }
    assert!(*count < map.len(), "ARM boot topology lacks kernel-image capacity");
    map[*count] = BootMemRegion { base_pa: start, len: end - start,
        kind: BootMemKind::KernelImage };
    *count += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: BootMemRegion = BootMemRegion { base_pa: 0, len: 0,
        kind: BootMemKind::Reserved };

    #[test]
    fn efi_loader_image_outside_allocator_regions_remains_in_topology() {
        let mut map = [EMPTY; 3];
        map[0] = BootMemRegion { base_pa: 0x5000_0000, len: 0x1000_0000,
            kind: BootMemKind::Usable };
        let mut count = 1;
        retain_kernel_image(&mut map, &mut count, 0x4020_0000, 0x4060_0000);
        assert_eq!(count, 2);
        assert_eq!(map[1].base_pa, 0x4020_0000);
        assert_eq!(map[1].len, 0x40_0000);
        assert_eq!(map[1].kind, BootMemKind::KernelImage);
    }

    #[test]
    fn dt_carve_is_not_duplicated() {
        let mut map = [EMPTY; 2];
        map[0] = BootMemRegion { base_pa: 0x4020_0000, len: 0x40_0000,
            kind: BootMemKind::KernelImage };
        let mut count = 1;
        retain_kernel_image(&mut map, &mut count, 0x4020_0000, 0x4060_0000);
        assert_eq!(count, 1);
    }
}
