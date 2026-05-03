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
const GICC_IAR:  usize = 0x00C;
#[cfg(target_arch = "aarch64")]
const GICC_EOIR: usize = 0x010;
#[cfg(target_arch = "aarch64")]
const GICC_IIDR: usize = 0x0FC;

/// GICD_ISENABLER0 covers SGI/PPI INTIDs 0..31 (banked per CPU).
#[cfg(target_arch = "aarch64")]
const GICD_ISENABLER: usize = 0x100;
/// GICD_IPRIORITYR — one byte per INTID.
#[cfg(target_arch = "aarch64")]
const GICD_IPRIORITYR: usize = 0x400;
/// IAR INTID field is bits [9:0] (GICv2 with up to 1020 INTIDs).
#[cfg(target_arch = "aarch64")]
const IAR_INTID_MASK: u32 = 0x3FF;
/// Spurious INTID — IAR returns 1023 when no IRQ is pending.
#[cfg(target_arch = "aarch64")]
const SPURIOUS_INTID: u32 = 1023;

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

/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "aarch64")]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Last INTID acknowledged by the Rust dispatcher (debug aid).
#[cfg(target_arch = "aarch64")]
pub static LAST_INTID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

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

/// Enable an SGI/PPI/SPI INTID at the distributor and set its
/// priority below the PMR threshold so it is deliverable.
///
/// # SAFETY: caller asserts `enable` has run; runs single-CPU,
/// IRQ-off; the chosen INTID is owned by the caller.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_intid(intid: u32) {
    let gicd = GICD_VA.load(Ordering::Acquire);
    if gicd == 0 { return; }
    // SAFETY: GICD_VA is the freshly-mapped Device-attr distributor; ISENABLER + IPRIORITYR offsets stay within the 4 KiB; per-CPU banked regs (INTID < 32) are write-1-to-set so no RMW race.
    unsafe {
        let word = (intid / 32) as usize;
        let bit  = intid & 31;
        let isenabler = (gicd + GICD_ISENABLER as u64 + (word * 4) as u64) as *mut u32;
        core::ptr::write_volatile(isenabler, 1u32 << bit);
        // Priority byte: 0x80 < PMR (0xFF) so this INTID can interrupt.
        let prio = (gicd + GICD_IPRIORITYR as u64 + intid as u64) as *mut u8;
        core::ptr::write_volatile(prio, 0x80);
    }
}

/// Acknowledge the highest-priority pending INTID; returns it.
/// Returns `SPURIOUS_INTID` (1023) if no IRQ is actually pending.
///
/// # SAFETY: pair with an in-progress IRQ.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn iar() -> u32 {
    let gicc = GICC_VA.load(Ordering::Acquire);
    if gicc == 0 { return SPURIOUS_INTID; }
    // SAFETY: per fn contract; GICC was mapped Device-attr; offset 0xC lies within.
    unsafe { core::ptr::read_volatile((gicc + GICC_IAR as u64) as *const u32) }
}

/// Drop the active priority for `intid` by writing GICC_EOIR.
///
/// # SAFETY: must mirror a prior `iar()` for the same INTID.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn eoi(intid: u32) {
    let gicc = GICC_VA.load(Ordering::Acquire);
    if gicc == 0 { return; }
    // SAFETY: per fn contract; GICC was mapped Device-attr; offset 0x10 lies within.
    unsafe { core::ptr::write_volatile((gicc + GICC_EOIR as u64) as *mut u32, intid); }
}

/// Rust IRQ dispatcher invoked from `oxide_irq_vector_handler`.
/// Reads IAR, dispatches by INTID (only the virtual generic-timer
/// INTID 27 today), then writes EOIR.
///
/// # SAFETY: invoked only from the asm vector entry with IRQs masked
/// (vector entry clears DAIF.I implicitly via the table form).
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_arm_irq_dispatch() {
    // SAFETY: dispatcher runs inside an in-progress IRQ; GIC was mapped+enabled before any IRQ unmask.
    let raw = unsafe { iar() };
    let intid = raw & IAR_INTID_MASK;
    LAST_INTID.store(intid, Ordering::Relaxed);
    if intid != SPURIOUS_INTID {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        // CNTV virtual timer INTID is 27 on QEMU virt. Reload TVAL
        // so the level-triggered line drops and re-arms for the next
        // period; otherwise the IRQ would re-fire immediately on
        // eret. Period is published by `arm_timer::timer_periodic`.
        if intid == 27 {
            let p = crate::arm_timer::PERIOD.load(Ordering::Relaxed) as u64;
            // SAFETY: CNTV_TVAL_EL0 is an unprivileged sysreg; writing it advances CVAL past the current count, deasserting the line.
            unsafe {
                core::arch::asm!("msr cntv_tval_el0, {v:x}", v = in(reg) p, options(nomem, nostack, preserves_flags));
            }
        }
        // SAFETY: mirrors the IAR read above; same INTID; GIC was mapped Device-attr.
        unsafe { eoi(raw); }
        // Defer reschedule (see lapic::oxide_irq_dispatch comment).
        crate::preempt::NEED_RESCHED.store(true, Ordering::Release);
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
