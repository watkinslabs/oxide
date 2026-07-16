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
use core::sync::atomic::{AtomicU64, Ordering};

// ---- Distributor offsets (shared with v2) ---------------------------------

#[cfg(target_arch = "aarch64")]
pub(super) const GICD_CTLR:       usize = 0x0000;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_TYPER:      usize = 0x0004;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_IIDR:       usize = 0x0008;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_ISENABLER:  usize = 0x0100;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_ICENABLER:  usize = 0x0180;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_IPRIORITYR: usize = 0x0400;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_ICFGR:      usize = 0x0C00;
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_ISPENDR:    usize = 0x0200;
/// GICv3-only: SPI affinity-routing register (8 bytes per INTID, base 0x6000).
#[cfg(target_arch = "aarch64")]
pub(super) const GICD_IROUTER:    usize = 0x6000;

/// GICD_CTLR bits (GICv3 with ARE_NS=1):
///   bit 0 — EnableGrp0
///   bit 1 — EnableGrp1NS
///   bit 4 — ARE_NS (MUST be 1 for GICv3)
#[cfg(target_arch = "aarch64")]
pub(super) const CTLR_ENGRP0:  u32 = 1 << 0;
#[cfg(target_arch = "aarch64")]
pub(super) const CTLR_ENGRP1:  u32 = 1 << 1;
#[cfg(target_arch = "aarch64")]
pub(super) const CTLR_ARE_NS:  u32 = 1 << 4;

// ---- Redistributor offsets (RD frame at gicr_va, SGI frame at +0x10000) ----

#[cfg(target_arch = "aarch64")]
pub(super) const GICR_CTLR:        usize = 0x0000;
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_TYPER:       usize = 0x0008;
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_WAKER:       usize = 0x0014;
/// LPI configuration table base + size (RD frame).
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_PROPBASER:   usize = 0x0070;
/// LPI pending table base (RD frame, per-PE).
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_PENDBASER:   usize = 0x0078;
/// SGI frame is at gicr_va + 0x10000.
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_SGI_OFFSET:  u64   = 0x10000;
/// In the SGI frame (relative to gicr_va + GICR_SGI_OFFSET).
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_IGROUPR0:    usize = 0x0080;
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_ISENABLER0:  usize = 0x0100;
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_IPRIORITYR:  usize = 0x0400;
#[cfg(target_arch = "aarch64")]
pub(super) const GICR_ICFGR1:      usize = 0x0C04;

/// WAKER bits.
#[cfg(target_arch = "aarch64")]
pub(super) const WAKER_PROCESSOR_SLEEP:  u32 = 1 << 1;
#[cfg(target_arch = "aarch64")]
pub(super) const WAKER_CHILDREN_ASLEEP:  u32 = 1 << 2;

// ---- Misc ------------------------------------------------------------------

/// IAR INTID field width on GICv3 (bits[23:0]).
#[cfg(target_arch = "aarch64")]
pub(super) const IAR_INTID_MASK: u32 = 0x00FF_FFFF;
/// Spurious INTID — IAR returns 1023 (or 1022/1021 for special) when no IRQ pending.
#[cfg(target_arch = "aarch64")]
pub(super) const SPURIOUS_INTID: u32 = 1023;

/// Stash GICD/GICR bases so EOI / IAR helpers + ITS can find them.
#[cfg(target_arch = "aarch64")]
pub(super) static GICD_VA: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
pub(super) static GICR_VA: AtomicU64 = AtomicU64::new(0);
