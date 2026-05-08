// Architecture-neutral MSI vector allocator for virtio + future PCI
// drivers. Today this hands out SPI numbers from the GICv2m frame's
// allocatable range on aarch64; x86 MSI-vector allocation rides
// alongside the LAPIC vector allocator and is wired in F38+.
//
// Per `34§*`. Allocation is monotonic — frees + reuse will be added
// when virtio drivers learn to release vectors at shutdown (no
// shutdown path exists in v1).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Kernel VA the GICv2m frame is device-mapped at. Published by
/// `device_map_smoke_arm` after mapping. Zero = unmapped.
/// SETSPI_NS register lives at `+0x040`.
pub static GICV2M_VA: AtomicU64 = AtomicU64::new(0);

/// First SPI the GICv2m frame can trigger. Published by F36's TYPER
/// read at boot. Zero = no GICv2m discovered (e.g. pre-init or x86).
pub static GICV2M_SPI_FIRST: AtomicU32 = AtomicU32::new(0);
/// Number of consecutive SPIs the GICv2m frame supports.
pub static GICV2M_SPI_COUNT: AtomicU32 = AtomicU32::new(0);
/// Bump cursor for SPI allocation. Initialised lazily from
/// `GICV2M_SPI_FIRST` on the first call.
static SPI_NEXT: AtomicU32 = AtomicU32::new(0);

/// Count of MSI deliveries observed by the IRQ dispatcher, per arch.
/// Bumped every time `oxide_arm_irq_dispatch` (or x86 equivalent)
/// sees an INTID in the GICv2m SPI range. Diagnostic only — once
/// virtio drivers learn to dispatch by SPI to a specific completion
/// callback, this counter goes away.
pub static MSI_FIRES: AtomicU32 = AtomicU32::new(0);

/// True iff `intid` falls inside the published v2m SPI range. Cheap
/// check used by the per-arch IRQ dispatcher.
/// # C: O(1) — two atomic loads.
pub fn intid_is_v2m(intid: u32) -> bool {
    let first = GICV2M_SPI_FIRST.load(Ordering::Acquire);
    let count = GICV2M_SPI_COUNT.load(Ordering::Acquire);
    first != 0 && count != 0 && intid >= first && intid < first + count
}

/// Allocate one SPI from the GICv2m frame's range. Returns `None`
/// when the range is unconfigured or exhausted.
/// # C: O(1) — atomic CAS bump.
#[cfg(target_arch = "aarch64")]
pub fn alloc_arm_spi() -> Option<u32> {
    let first = GICV2M_SPI_FIRST.load(Ordering::Acquire);
    let count = GICV2M_SPI_COUNT.load(Ordering::Acquire);
    if first == 0 || count == 0 { return None; }
    // Lazy cursor init.
    let _ = SPI_NEXT.compare_exchange(0, first, Ordering::AcqRel, Ordering::Relaxed);
    let cur = SPI_NEXT.fetch_add(1, Ordering::AcqRel);
    if cur >= first + count { return None; }
    Some(cur)
}
