//! EFI descriptor classification and stable physical topology.

use boot_info::{BootMemKind, BootMemRegion};

const EFI_PAGE_BYTES: u64 = 4096;
const EFI_DESC_MIN: usize = 40;
const EFI_MEMORY_WC: u64 = 1 << 1;
const EFI_MEMORY_WT: u64 = 1 << 2;
const EFI_MEMORY_WB: u64 = 1 << 3;

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_UNUSABLE_MEMORY: u32 = 8;
const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
const EFI_ACPI_MEMORY_NVS: u32 = 10;
const EFI_PERSISTENT_MEMORY: u32 = 14;

const EMPTY: BootMemRegion = BootMemRegion { base_pa: 0, len: 0,
    kind: BootMemKind::Reserved };

fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(off..off + 8)?.try_into().ok()?))
}

fn kind(ty: u32, attr: u64) -> Option<BootMemKind> {
    if attr & (EFI_MEMORY_WB | EFI_MEMORY_WT | EFI_MEMORY_WC) == 0 { return None; }
    Some(match ty {
        EFI_ACPI_RECLAIM_MEMORY => BootMemKind::AcpiReclaim,
        EFI_ACPI_MEMORY_NVS => BootMemKind::AcpiNvs,
        EFI_UNUSABLE_MEMORY => BootMemKind::BadMem,
        EFI_LOADER_CODE | EFI_LOADER_DATA | EFI_BOOT_SERVICES_CODE |
        EFI_BOOT_SERVICES_DATA | EFI_CONVENTIONAL_MEMORY |
        EFI_PERSISTENT_MEMORY if attr & EFI_MEMORY_WB != 0 => BootMemKind::Usable,
        _ => BootMemKind::Reserved,
    })
}

fn push(out: &mut [BootMemRegion], n: &mut usize, region: BootMemRegion) -> bool {
    if region.len == 0 { return true; }
    if *n != 0 {
        let prev = &mut out[*n - 1];
        if prev.kind == region.kind && prev.base_pa.checked_add(prev.len) == Some(region.base_pa) {
            let Some(len) = prev.len.checked_add(region.len) else { return false; };
            prev.len = len;
            return true;
        }
    }
    if *n == out.len() { return false; }
    out[*n] = region;
    *n += 1;
    true
}

/// Decode the retained EFI map into sorted, coalesced physical-memory truth.
/// # C: O(descriptors^2), bounded by the 16 KiB firmware-map handoff
pub(super) fn decode(bytes: &[u8], desc_size: usize,
                     out: &mut [BootMemRegion]) -> Option<usize> {
    if desc_size < EFI_DESC_MIN || bytes.is_empty() || bytes.len() % desc_size != 0 { return None; }
    let mut raw = [EMPTY; super::MAX_BOOT_REGIONS];
    let mut nr = 0usize;
    for desc in bytes.chunks_exact(desc_size) {
        let ty = u32_at(desc, 0)?;
        let base_pa = u64_at(desc, 8)?;
        let pages = u64_at(desc, 24)?;
        let attr = u64_at(desc, 32)?;
        let Some(kind) = kind(ty, attr) else { continue; };
        let len = pages.checked_mul(EFI_PAGE_BYTES)?;
        if len == 0 { continue; }
        base_pa.checked_add(len)?;
        if nr == raw.len() { return None; }
        raw[nr] = BootMemRegion { base_pa, len, kind };
        nr += 1;
    }
    let mut i = 1usize;
    while i < nr {
        let mut j = i;
        while j > 0 && raw[j - 1].base_pa > raw[j].base_pa {
            raw.swap(j - 1, j);
            j -= 1;
        }
        i += 1;
    }
    let mut n = 0usize;
    for region in raw[..nr].iter().copied() {
        if n != 0 {
            let prev = out[n - 1];
            if prev.base_pa.checked_add(prev.len)? > region.base_pa { return None; }
        }
        if !push(out, &mut n, region) { return None; }
    }
    Some(n)
}

/// Overlay exact kernel/firmware owners onto a non-overlapping base topology.
/// # C: O(regions * blocks)
pub(super) fn overlay(base: &[BootMemRegion],
                      blocks: &[(u64, u64, BootMemKind)],
                      out: &mut [BootMemRegion]) -> Option<usize> {
    let mut n = 0usize;
    for region in base.iter().copied() {
        let end = region.base_pa.checked_add(region.len)?;
        let mut cur = region.base_pa;
        for &(start, stop, kind) in blocks {
            if stop <= cur || start >= end { continue; }
            let start = start.max(cur);
            let stop = stop.min(end);
            if stop <= start { continue; }
            if start > cur && !push(out, &mut n, BootMemRegion {
                base_pa: cur, len: start - cur, kind: region.kind,
            }) { return None; }
            if !push(out, &mut n, BootMemRegion {
                base_pa: start, len: stop - start, kind,
            }) { return None; }
            cur = stop;
        }
        if cur < end && !push(out, &mut n, BootMemRegion {
            base_pa: cur, len: end - cur, kind: region.kind,
        }) { return None; }
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(ty: u32, base: u64, pages: u64, attr: u64) -> [u8; 40] {
        let mut d = [0u8; 40];
        d[0..4].copy_from_slice(&ty.to_le_bytes());
        d[8..16].copy_from_slice(&base.to_le_bytes());
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d[32..40].copy_from_slice(&attr.to_le_bytes());
        d
    }

    #[test]
    fn transient_loader_boot_services_and_conventional_partitions_coalesce() {
        let mut bytes = [0u8; 120];
        bytes[0..40].copy_from_slice(&desc(EFI_LOADER_DATA, 0x4000, 2, EFI_MEMORY_WB));
        bytes[40..80].copy_from_slice(&desc(EFI_BOOT_SERVICES_DATA, 0x6000, 3, EFI_MEMORY_WB));
        bytes[80..120].copy_from_slice(&desc(EFI_CONVENTIONAL_MEMORY, 0x9000, 4, EFI_MEMORY_WB));
        let mut out = [EMPTY; 8];
        assert_eq!(decode(&bytes, 40, &mut out), Some(1));
        assert_eq!(out[0].base_pa, 0x4000);
        assert_eq!(out[0].len, 9 * EFI_PAGE_BYTES);
        assert_eq!(out[0].kind, BootMemKind::Usable);
    }

    #[test]
    fn firmware_owned_memory_is_retained_and_mmio_is_excluded() {
        let mut bytes = [0u8; 160];
        bytes[0..40].copy_from_slice(&desc(EFI_ACPI_RECLAIM_MEMORY, 0x1000, 1, EFI_MEMORY_WB));
        bytes[40..80].copy_from_slice(&desc(EFI_ACPI_MEMORY_NVS, 0x2000, 1, EFI_MEMORY_WB));
        bytes[80..120].copy_from_slice(&desc(EFI_UNUSABLE_MEMORY, 0x3000, 1, EFI_MEMORY_WB));
        bytes[120..160].copy_from_slice(&desc(11, 0x4000, 1, 1));
        let mut out = [EMPTY; 8];
        assert_eq!(decode(&bytes, 40, &mut out), Some(3));
        assert_eq!(out[0].kind, BootMemKind::AcpiReclaim);
        assert_eq!(out[1].kind, BootMemKind::AcpiNvs);
        assert_eq!(out[2].kind, BootMemKind::BadMem);
    }

    #[test]
    fn exact_owner_overlay_splits_without_losing_physical_topology() {
        let base = [BootMemRegion { base_pa: 0x1000, len: 0x8000,
            kind: BootMemKind::Usable }];
        let blocks = [(0x3000, 0x5000, BootMemKind::KernelImage)];
        let mut out = [EMPTY; 4];
        assert_eq!(overlay(&base, &blocks, &mut out), Some(3));
        assert_eq!((out[0].base_pa, out[0].len, out[0].kind),
                   (0x1000, 0x2000, BootMemKind::Usable));
        assert_eq!((out[1].base_pa, out[1].len, out[1].kind),
                   (0x3000, 0x2000, BootMemKind::KernelImage));
        assert_eq!((out[2].base_pa, out[2].len, out[2].kind),
                   (0x5000, 0x4000, BootMemKind::Usable));
    }
}
