// GICv2 bring-up per `22§5` (aarch64).
//
// Maps GICD (distributor) + GICC (CPU interface) MMIO via the
// device mapper, asserts global enables (GICD_CTLR + GICC_CTLR
// EnableGrp0/1), and lifts GICC_PMR so any priority can interrupt
// the CPU. Reads back GICD_TYPER + GICC_IIDR as a sanity log.
//
// IRQ routing per-line + EOI helpers ride alongside the timer-LVT
// follow-up that needs them.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "aarch64")]
const GICD_CTLR:  usize = 0x000;
#[cfg(target_arch = "aarch64")]
const GICD_TYPER: usize = 0x004;
#[cfg(target_arch = "aarch64")]
const GICD_IIDR:  usize = 0x008;

#[cfg(target_arch = "aarch64")]
const GICC_CTLR: usize = 0x000;
#[cfg(target_arch = "aarch64")]
const GICC_PMR:  usize = 0x004;
#[cfg(target_arch = "aarch64")]
const GICC_IIDR: usize = 0x0FC;

/// GICD_CTLR / GICC_CTLR Group-0 + Group-1 enable bits.
#[cfg(target_arch = "aarch64")]
const CTLR_ENGRP0: u32 = 1 << 0;
#[cfg(target_arch = "aarch64")]
const CTLR_ENGRP1: u32 = 1 << 1;

/// Priority mask: 0xFF = let every priority through.
#[cfg(target_arch = "aarch64")]
const PMR_OPEN: u32 = 0xFF;

/// Stash GICD/GICC bases so EOI / IAR helpers can find them later.
#[cfg(target_arch = "aarch64")]
static GICD_VA: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static GICC_VA: AtomicU64 = AtomicU64::new(0);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GicStatus {
    AlreadyOn,
    Enabled { typer: u32, gicd_iidr: u32, gicc_iidr: u32 },
}

/// Map → enable both halves of GICv2. Sets EnableGrp0/1 in both
/// GICD_CTLR and GICC_CTLR, opens GICC_PMR.
///
/// # SAFETY: caller asserts both `gicd_va` and `gicc_va` are
/// freshly Device-attr-mapped over the matching phys pages; runs
/// single-CPU, IRQ-off; no other path is touching the GIC.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable(gicd_va: u64, gicc_va: u64) -> GicStatus {
    if GICD_VA.load(Ordering::Acquire) != 0 {
        return GicStatus::AlreadyOn;
    }
    // SAFETY: both VAs are freshly Device-nGnRnE 4 KiB mappings per fn contract; we own the device pre-init; reads/writes lie within those pages.
    unsafe {
        // Distributor: assert both group enables.
        let gicd_ctlr = (gicd_va + GICD_CTLR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(gicd_ctlr);
        core::ptr::write_volatile(gicd_ctlr, cur | CTLR_ENGRP0 | CTLR_ENGRP1);

        // CPU interface: open priority mask + assert group enables.
        let gicc_pmr  = (gicc_va + GICC_PMR  as u64) as *mut u32;
        let gicc_ctlr = (gicc_va + GICC_CTLR as u64) as *mut u32;
        core::ptr::write_volatile(gicc_pmr, PMR_OPEN);
        let cur = core::ptr::read_volatile(gicc_ctlr);
        core::ptr::write_volatile(gicc_ctlr, cur | CTLR_ENGRP0 | CTLR_ENGRP1);

        let typer     = core::ptr::read_volatile((gicd_va + GICD_TYPER as u64) as *const u32);
        let gicd_iidr = core::ptr::read_volatile((gicd_va + GICD_IIDR  as u64) as *const u32);
        let gicc_iidr = core::ptr::read_volatile((gicc_va + GICC_IIDR  as u64) as *const u32);
        GICD_VA.store(gicd_va, Ordering::Release);
        GICC_VA.store(gicc_va, Ordering::Release);
        GicStatus::Enabled { typer, gicd_iidr, gicc_iidr }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gic_status_distinct() {
        let a = GicStatus::AlreadyOn;
        let b = GicStatus::Enabled { typer: 0, gicd_iidr: 0, gicc_iidr: 0 };
        assert_ne!(a, b);
    }
}
