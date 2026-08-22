//! DTB and ACPI ranges consumed by the boot-info builder.

use crate::{dtb, selfboot};

/// Page-aligned physical extent of every directly referenced ACPI table.
/// # SAFETY: firmware-published tables are HHDM mapped and header bounded.
/// # C: O(n_tables)
pub(super) unsafe fn acpi_extent() -> Option<(u64, u64)> {
    let h = selfboot::ARM_SELFBOOT_HHDM;
    let rsdp_pa = selfboot::EFI_RSDP_PA.load(core::sync::atomic::Ordering::Acquire);
    if rsdp_pa == 0 { return None; }
    // SAFETY: HHDM covers RAM; ACPI fields need not be aligned.
    let rd32 = |pa: u64| -> u32 { unsafe { core::ptr::read_unaligned((h + pa) as *const u32) } };
    // SAFETY: HHDM covers RAM; ACPI fields need not be aligned.
    let rd64 = |pa: u64| -> u64 { unsafe { core::ptr::read_unaligned((h + pa) as *const u64) } };
    let xsdt_pa = rd64(rsdp_pa + 24);
    if xsdt_pa == 0 { return None; }
    let xsdt_len = rd32(xsdt_pa + 4) as u64;
    if xsdt_len < 36 || xsdt_len > 4096 { return None; }
    let mut lo = rsdp_pa.min(xsdt_pa);
    let mut hi = (rsdp_pa + 36).max(xsdt_pa + xsdt_len);
    let n = ((xsdt_len - 36) / 8).min(64);
    let mut i = 0u64;
    while i < n {
        let tpa = rd64(xsdt_pa + 36 + i * 8); i += 1;
        if tpa == 0 { continue; }
        let mut len = rd32(tpa + 4) as u64;
        if len < 36 { len = 36; }
        if len > 0x10_0000 { len = 0x10_0000; }
        lo = lo.min(tpa); hi = hi.max(tpa + len);
    }
    Some((lo & !0xFFF, (hi + 0xFFF) & !0xFFF))
}

/// Every DTB `/memory` entry. # SAFETY: `pa` names a firmware DTB. # C: O(dtb)
pub(super) unsafe fn read_dtb_memory_all(pa: u64, out: &mut [(u64, u64)]) -> usize {
    // SAFETY: caller supplies the firmware pointer; header bounds the result.
    let Some(blob) = (unsafe { dtb_blob(pa) }) else { return 0 };
    dtb::memory_regions(blob, out)
}

/// Every firmware-owned DTB range. # SAFETY: `pa` names a firmware DTB. # C: O(dtb)
pub(super) unsafe fn read_dtb_reserved_all(pa: u64, out: &mut [(u64, u64)]) -> usize {
    // SAFETY: caller supplies the firmware pointer; header bounds the result.
    let Some(blob) = (unsafe { dtb_blob(pa) }) else { return 0 };
    dtb::reserved_regions(blob, out)
}

/// HHDM-mapped complete DTB. # SAFETY: `pa` names its readable header. # C: O(1)
pub(super) unsafe fn dtb_blob(pa: u64) -> Option<&'static [u8]> {
    if pa == 0 { return None; }
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: caller supplies the firmware pointer; prefix supplies the bound.
    let len = unsafe { dtb_totalsize(pa) } as usize;
    if len < dtb::FDT_HEADER_LEN || len > dtb::FDT_MAX_TOTALSIZE { return None; }
    // SAFETY: validated length bounds this retained HHDM mapping.
    Some(unsafe { core::slice::from_raw_parts(va as *const u8, len) })
}

/// First DTB memory range. # SAFETY: `pa` names a firmware DTB. # C: O(dtb)
#[allow(dead_code)]
pub(super) unsafe fn read_dtb_memory(pa: u64) -> Option<(u64, u64)> {
    // SAFETY: caller supplies the firmware pointer; helper validates it.
    unsafe { dtb_blob(pa) }.and_then(dtb::first_memory_region)
}

/// Publish the PL011 input clock. # SAFETY: `pa` names a firmware DTB. # C: O(dtb)
pub(super) unsafe fn publish_pl011_clock(pa: u64) {
    // SAFETY: caller supplies the firmware pointer; helper validates it.
    let Some(blob) = (unsafe { dtb_blob(pa) }) else { return };
    if let Some(hz) = dtb::pl011_clock_hz(blob) { hal_aarch64::pl011::set_uartclk_hz(hz); }
}

/// DTB byte length. # SAFETY: `pa` names an HHDM-mapped 8-byte header. # C: O(1)
pub(super) unsafe fn dtb_totalsize(pa: u64) -> u64 {
    let va = selfboot::ARM_SELFBOOT_HHDM + pa;
    // SAFETY: fn contract guarantees the readable prefix.
    let head = unsafe { core::slice::from_raw_parts(va as *const u8, 8) };
    dtb::totalsize_from_prefix(head).unwrap_or(0) as u64
}
