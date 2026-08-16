// GICv3 bring-up per `22§5` (aarch64).
//
// Replaces the GICv2 implementation as part of F55 silent-MSI fix.
// QEMU virt is launched with `gic-version=3,its=on`; the CPU
// interface is now system-register only (ICC_*) — no GICC MMIO.
// The Distributor stays MMIO at the same base; per-CPU state lives
// in the Redistributor (GICR) region. SPI affinity routing is via
// GICD_IROUTER (writes a 64-bit MPIDR target), replacing v2's
// GICD_ITARGETSR. ITS is a separate driver (`its.rs`); MSI delivery
// targets ITS_BASE + GITS_TRANSLATER.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicU64;

// Architectural offsets and INTID-count arithmetic live in `crate::gicdef`,
// ungated so the suspend/resume state machine can be tested on the host.
// Re-exported here under the names this module's callers already use.
#[cfg(target_arch = "aarch64")]
pub(super) use crate::gicdef::{
    CTLR_ARE_NS, CTLR_ENGRP0, CTLR_ENGRP1, GICD_ICENABLER,
    GICD_CTLR, GICD_ICFGR, GICD_IGROUPR, GICD_IIDR, GICD_IPRIORITYR, GICD_IROUTER,
    GICD_ISENABLER, GICD_ISPENDR, GICD_TYPER,
    GICR_CTLR, GICR_ICFGR1, GICR_IGROUPR0, GICR_IPRIORITYR, GICR_ISENABLER0,
    GICR_PENDBASER, GICR_PROPBASER, GICR_SGI_OFFSET, GICR_TYPER, GICR_WAKER,
    IAR_INTID_MASK, SPURIOUS_INTID, WAKER_CHILDREN_ASLEEP, WAKER_PROCESSOR_SLEEP,
};

/// Stash GICD/GICR bases so EOI / IAR helpers + ITS can find them.
#[cfg(target_arch = "aarch64")]
pub(crate) static GICD_VA: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
pub(crate) static GICR_VA: AtomicU64 = AtomicU64::new(0);
