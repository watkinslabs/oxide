// Firmware-owned physical ranges retained from the boot memory map.
//
// The buddy is seeded only from the usable ranges, so by the time anything
// else runs, WHERE the firmware description tables live has been forgotten.
// That answer is needed later by anything that has to build a page table
// covering more than RAM — the tables a replacement kernel reads before it
// has built any mapping of its own sit in exactly these ranges, and a map
// built from usable RAM alone faults on the first one it touches.
//
// Retained rather than re-derived: the boot memory map is not available after
// early init, and a second source for "where the firmware tables are" could
// disagree with the one the allocator was actually seeded against.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use boot_info::BootMemKind;

use super::topology::MemoryRegion;
use hal::PAGE_SIZE_BYTES;

/// Firmware ranges retained. Machines describe few; the bound only has to
/// cover the description tables, not the whole map.
pub const MAX_FIRMWARE_REGIONS: usize = 32;

/// One retained range, as `[start, end)` physical bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareRegion {
    /// First byte.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
}

struct Buf(UnsafeCell<[FirmwareRegion; MAX_FIRMWARE_REGIONS]>);
// SAFETY: written once during single-CPU early init, read-only afterwards; the
// count is published with release ordering after the writes.
unsafe impl Sync for Buf {}

static BUF: Buf = Buf(UnsafeCell::new(
    [FirmwareRegion { start: 0, end: 0 }; MAX_FIRMWARE_REGIONS]));
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Does a boot-map entry of this kind hold firmware description tables?
///
/// Both reclaimable tables and non-volatile firmware storage qualify: the
/// first holds the description tables themselves, the second holds state
/// firmware keeps across the transition and expects to still be able to reach.
/// # C: O(1)
pub fn is_firmware_kind(kind: BootMemKind) -> bool {
    matches!(kind, BootMemKind::AcpiReclaim | BootMemKind::AcpiNvs)
}

/// Derive every firmware byte range from the canonical normalized topology.
/// Called once during early init; this cache preserves the legacy slice API
/// but cannot disagree with the topology owner.
/// # C: O(map.len)
pub fn publish(map: &[MemoryRegion]) {
    let mut n = 0usize;
    for r in map {
        if n >= MAX_FIRMWARE_REGIONS { break; }
        if !is_firmware_kind(r.kind) { continue; }
        if r.end.0 <= r.start.0 { continue; }
        // SAFETY: single-CPU early init is the only writer of `BUF`, and no
        // reader can observe the entry before `COUNT` is released below.
        unsafe { (*BUF.0.get())[n] = FirmwareRegion {
            start: r.start.0.saturating_mul(PAGE_SIZE_BYTES),
            end: r.end.0.saturating_mul(PAGE_SIZE_BYTES),
        }; }
        n += 1;
    }
    COUNT.store(n, Ordering::Release);
}

/// The retained firmware ranges. Empty before `publish`.
/// # C: O(1)
pub fn firmware_regions() -> &'static [FirmwareRegion] {
    let n = COUNT.load(Ordering::Acquire);
    // SAFETY: `BUF[0..n]` was written once during single-CPU init and never
    // mutated afterwards; `COUNT` is published with release ordering after
    // those writes.
    unsafe { core::slice::from_raw_parts(BUF.0.get() as *const FirmwareRegion, n) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_firmware_table_kinds_are_retained() {
        // Retaining usable RAM here would double every range the allocator
        // already reports; retaining nothing leaves a replacement kernel
        // faulting on the first description table it reads.
        assert!(is_firmware_kind(BootMemKind::AcpiReclaim));
        assert!(is_firmware_kind(BootMemKind::AcpiNvs));
        for k in [BootMemKind::Usable, BootMemKind::Reserved, BootMemKind::BadMem,
                  BootMemKind::BootloaderUsed, BootMemKind::KernelImage,
                  BootMemKind::Initramfs] {
            assert!(!is_firmware_kind(k));
        }
    }
}
