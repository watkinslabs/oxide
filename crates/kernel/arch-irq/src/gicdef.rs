// GICv3 distributor / redistributor register layout (aarch64).
//
// Ungated on purpose: the offsets and the words-per-register-class arithmetic
// are architectural, and the suspend/resume state machine that consumes them
// (`pm::gic_state`) must be testable on the host. The gated accessors in
// `gic::regs` re-export from here rather than keeping a second copy.

// ---- Distributor -----------------------------------------------------------

pub const GICD_CTLR:       usize = 0x0000;
pub const GICD_TYPER:      usize = 0x0004;
pub const GICD_IIDR:       usize = 0x0008;
pub const GICD_IGROUPR:    usize = 0x0080;
pub const GICD_ISENABLER:  usize = 0x0100;
pub const GICD_ICENABLER:  usize = 0x0180;
pub const GICD_ISPENDR:    usize = 0x0200;
pub const GICD_IPRIORITYR: usize = 0x0400;
pub const GICD_ICFGR:      usize = 0x0C00;
/// SPI affinity routing, eight bytes per INTID.
pub const GICD_IROUTER:    usize = 0x6000;

pub const CTLR_ENGRP0: u32 = 1 << 0;
pub const CTLR_ENGRP1: u32 = 1 << 1;
pub const CTLR_ARE_NS: u32 = 1 << 4;

/// Every bit of a one-bit-per-INTID register, the value written to a
/// write-one-to-clear enable register to clear the whole word.
pub const ALL_BITS: u32 = u32::MAX;

// ---- Redistributor ---------------------------------------------------------

pub const GICR_CTLR:      usize = 0x0000;
pub const GICR_TYPER:     usize = 0x0008;
pub const GICR_WAKER:     usize = 0x0014;
pub const GICR_PROPBASER: usize = 0x0070;
pub const GICR_PENDBASER: usize = 0x0078;
/// The SGI/PPI frame sits one 64 KiB page past the redistributor base.
pub const GICR_SGI_OFFSET: u64 = 0x10000;

// Offsets within the SGI frame.
pub const GICR_IGROUPR0:   usize = 0x0080;
pub const GICR_ISENABLER0: usize = 0x0100;
pub const GICR_ICENABLER0: usize = 0x0180;
pub const GICR_IPRIORITYR: usize = 0x0400;
pub const GICR_ICFGR1:     usize = 0x0C04;

pub const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
pub const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// ---- Interrupt-number arithmetic -------------------------------------------

/// INTIDs below this are the per-CPU software-generated and private
/// interrupts; the distributor's shared range starts here.
pub const SPI_BASE: u32 = 32;
/// Largest INTID a distributor reports through its type register.
pub const MAX_SHARED_INTID: u32 = 1020;
/// First architected Locality-specific Peripheral Interrupt.
pub const LPI_BASE: u32 = 8192;

/// Implemented INTID count from the distributor's type register. # C: O(1)
pub const fn gic_irqs(typer: u32) -> u32 {
    let n = ((typer & 0x1F) + 1) * 32;
    if n > MAX_SHARED_INTID { MAX_SHARED_INTID } else { n }
}

/// Words in a one-bit-per-INTID register class. # C: O(1)
pub const fn words_1bit(irqs: u32) -> u32 { irqs.div_ceil(32) }
/// Words in a two-bit-per-INTID register class. # C: O(1)
pub const fn words_2bit(irqs: u32) -> u32 { irqs.div_ceil(16) }
/// Words in an eight-bit-per-INTID register class. # C: O(1)
pub const fn words_8bit(irqs: u32) -> u32 { irqs.div_ceil(4) }

/// First one-bit word holding a shared INTID. # C: O(1)
pub const fn first_1bit_word() -> u32 { SPI_BASE / 32 }
/// First two-bit word holding a shared INTID. # C: O(1)
pub const fn first_2bit_word() -> u32 { SPI_BASE / 16 }
/// First eight-bit word holding a shared INTID. # C: O(1)
pub const fn first_8bit_word() -> u32 { SPI_BASE / 4 }

// ---- Misc ------------------------------------------------------------------

pub const IAR_INTID_MASK: u32 = 0x00FF_FFFF;
pub const SPURIOUS_INTID: u32 = 1023;
