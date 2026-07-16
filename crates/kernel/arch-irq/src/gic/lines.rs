use core::sync::atomic::Ordering;

use super::regs::{
    GICD_ICENABLER, GICD_ICFGR, GICD_IPRIORITYR, GICD_IROUTER, GICD_ISENABLER,
    GICD_ISPENDR, GICD_VA, GICR_IGROUPR0, GICR_IPRIORITYR, GICR_ISENABLER0,
    GICR_SGI_OFFSET, GICR_VA,
};

/// Enable an SGI/PPI/SPI INTID. SGIs/PPIs (INTID < 32) live in the
/// per-CPU Redistributor (SGI frame); SPIs (INTID >= 32) live in
/// the Distributor and additionally need GICD_IROUTER set so the
/// SPI is routed to a participating PE.
///
/// # SAFETY: caller asserts `enable` has run; runs single-CPU,
/// IRQ-off; the chosen INTID is owned by the caller.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_intid(intid: u32) {
    let gicd = GICD_VA.load(Ordering::Acquire);
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicd == 0 || gicr == 0 { return; }
    // SAFETY: GICD/GICR are Device-attr-mapped; offsets stay within their regions.
    unsafe {
        if intid < 32 {
            // SGI/PPI: per-CPU banked in GICR SGI frame.
            let sgi_base   = gicr + GICR_SGI_OFFSET;
            let bit        = 1u32 << (intid & 31);
            let group      = (sgi_base + GICR_IGROUPR0 as u64) as *mut u32;
            core::ptr::write_volatile(group, core::ptr::read_volatile(group) | bit);
            let isenabler  = (sgi_base + GICR_ISENABLER0 as u64) as *mut u32;
            core::ptr::write_volatile(isenabler, bit);
            let prio = (sgi_base + GICR_IPRIORITYR as u64 + intid as u64) as *mut u8;
            core::ptr::write_volatile(prio, 0x80);
            core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags));
            // PPIs typically default to level-sensitive; leave ICFGR alone.
        } else {
            spi_enable_common(gicd, intid, /*level=*/false);
        }
    }
}

/// Same as `enable_intid` for SPIs but marks the line as
/// level-sensitive (ICFGR=0b00) instead of edge-triggered. Use for
/// device lines that hold the line asserted while a condition is
/// true (PL011 RX, virtio-net-mmio legacy) — edge-trigger only fires
/// on the rising transition and so misses subsequent assertions
/// when the device-side line stays high through the IRQ ack.
///
/// # SAFETY: caller asserts `enable` has run; runs single-CPU,
/// IRQ-off; the chosen SPI is owned by the caller.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_intid_level(intid: u32) {
    let gicd = GICD_VA.load(Ordering::Acquire);
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicd == 0 || gicr == 0 { return; }
    // SAFETY: same Device-mapped GIC bases; per-CPU PPI branch.
    if intid < 32 { unsafe { enable_intid(intid); } return; }
    // SAFETY: GICD region is Device-attr-mapped; offset stays inside.
    unsafe { spi_enable_common(gicd, intid, /*level=*/true); }
}

/// Disable an SGI/PPI/SPI INTID owned by a driver during remove.
/// # SAFETY: caller owns `intid`; GIC bring-up has published its bases.
/// # C: O(1)
/// # Ctx: driver remove / boot teardown
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn disable_intid(intid: u32) {
    let gicd = GICD_VA.load(Ordering::Acquire);
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicd == 0 || gicr == 0 { return; }
    // SAFETY: GICD/GICR are Device-attr-mapped; offsets stay within their regions.
    unsafe {
        if intid < 32 {
            let sgi_base = gicr + GICR_SGI_OFFSET;
            let icenabler = (sgi_base + GICD_ICENABLER as u64) as *mut u32;
            core::ptr::write_volatile(icenabler, 1u32 << (intid & 31));
        } else {
            let word = (intid / 32) as u64 * 4;
            let icenabler = (gicd + GICD_ICENABLER as u64 + word) as *mut u32;
            core::ptr::write_volatile(icenabler, 1u32 << (intid & 31));
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
unsafe fn spi_enable_common(gicd: u64, intid: u32, level: bool) {
    // SAFETY: caller asserted Device-mapped GICD; offsets stay inside.
    unsafe {
        let word = (intid / 32) as u64 * 4;
        let isenabler = (gicd + GICD_ISENABLER as u64 + word) as *mut u32;
        core::ptr::write_volatile(isenabler, 1u32 << (intid & 31));
        let prio = (gicd + GICD_IPRIORITYR as u64 + intid as u64) as *mut u8;
        core::ptr::write_volatile(prio, 0x80);
        // ICFGR field: 0b00 = level (hold while line high),
        //              0b10 = edge (rising transition only).
        // Device pin behaviour dictates which: PL011 holds the line
        // through RX-FIFO drain (level); virtio MSI-class lines pulse
        // and clear (edge).
        let icfgr_off = (intid / 16) as u64 * 4;
        let shift     = ((intid % 16) * 2) as u32;
        let icfgr     = (gicd + GICD_ICFGR as u64 + icfgr_off) as *mut u32;
        let cur       = core::ptr::read_volatile(icfgr);
        let cleared   = cur & !(0b11u32 << shift);
        let val = if level { 0b00u32 } else { 0b10u32 };
        core::ptr::write_volatile(icfgr, cleared | (val << shift));
        // IROUTER: route to CPU 0. v1 is single-CPU UP.
        let irouter = (gicd + GICD_IROUTER as u64 + (intid as u64) * 8) as *mut u64;
        core::ptr::write_volatile(irouter, 0u64);
    }
}
/// Read the GICD_ISPENDR word covering `intid`. Diagnostic only.
///
/// # SAFETY: distributor must have been mapped via `enable`.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn ispendr_word(intid: u32) -> u32 {
    let gicd = GICD_VA.load(Ordering::Acquire);
    if gicd == 0 { return 0; }
    let off = (intid / 32) as u64 * 4;
    // SAFETY: distributor freshly mapped Device-attr; ISPENDR within the 64 KiB GICD region.
    unsafe { core::ptr::read_volatile((gicd + GICD_ISPENDR as u64 + off) as *const u32) }
}
