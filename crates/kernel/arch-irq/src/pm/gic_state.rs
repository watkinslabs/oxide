// GIC state across a sleep that powers the interrupt controller down
// (`32a§7`).
//
// The restore order is the contract:
//
//   * The distributor is disabled first and re-enabled last, so nothing is
//     delivered through a partially-programmed routing table.
//   * Enables are cleared before they are set. The enable registers are
//     write-one-to-set with a separate write-one-to-clear register, so writing
//     the saved word alone can only ever ADD enabled lines — the ones the
//     saved word has clear would keep whatever the sleep left behind.
//   * Group-1 delivery on the CPU interface goes back on last, after the
//     priority mask and control are in place.
//
// Deviation, deliberate (`32a§7`): the reference has no distributor-wide
// save/restore for this GIC generation — its power management covers only
// CPU-local retention, where distributor state survives. A system sleep that
// powers the controller down does lose it, so the distributor and
// redistributor state is saved here as well. The restore discipline is the one
// the reference uses for the generation that does save it.

use alloc::vec::Vec;

use crate::gicdef::*;

/// A GIC memory-mapped register window.
pub trait GicRegs {
    /// Read the 32-bit register at `off`. # C: O(1)
    fn read(&self, off: usize) -> u32;
    /// Write `v` to the 32-bit register at `off`. # C: O(1)
    fn write(&mut self, off: usize, v: u32);
    /// Read the 64-bit register at `off`. # C: O(1)
    fn read64(&self, off: usize) -> u64;
    /// Write `v` to the 64-bit register at `off`. # C: O(1)
    fn write64(&mut self, off: usize, v: u64);
}

/// The CPU interface's system registers, which are per-CPU rather than in the
/// memory window.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct GicCpuIf {
    /// Priority mask: interrupts at or above this priority value are blocked.
    pub pmr: u32,
    /// Control, holding the end-of-interrupt mode.
    pub ctlr: u32,
    /// Group-1 delivery enable.
    pub grpen1: u32,
}

/// Distributor state a powered-down controller loses.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GicDistState {
    /// Implemented INTID count.
    pub irqs: u32,
    pub ctlr: u32,
    /// Shared-INTID words only; the private range lives in the redistributor.
    pub group: Vec<u32>,
    pub enable: Vec<u32>,
    pub priority: Vec<u32>,
    pub config: Vec<u32>,
    /// One affinity route per shared INTID.
    pub route: Vec<u64>,
}

/// Redistributor state for this CPU's private INTIDs.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct GicRedistState {
    pub group0: u32,
    pub enable0: u32,
    /// Eight words cover the thirty-two private INTIDs at one byte each.
    pub priority: [u32; PRIVATE_PRIORITY_WORDS],
    pub config1: u32,
}

/// Words of priority covering the thirty-two private INTIDs.
pub const PRIVATE_PRIORITY_WORDS: usize = (SPI_BASE / 4) as usize;

// ---- distributor -----------------------------------------------------------

/// Read the distributor state a powered-down controller loses.
/// # C: O(N_irqs)
/// # Ctx: IRQ-off, single-CPU
pub fn dist_save<R: GicRegs>(r: &R) -> GicDistState {
    let irqs = gic_irqs(r.read(GICD_TYPER));
    let mut s = GicDistState { irqs, ctlr: r.read(GICD_CTLR), ..Default::default() };
    for i in first_1bit_word()..words_1bit(irqs) {
        s.group.push(r.read(GICD_IGROUPR + (i * 4) as usize));
        s.enable.push(r.read(GICD_ISENABLER + (i * 4) as usize));
    }
    for i in first_8bit_word()..words_8bit(irqs) {
        s.priority.push(r.read(GICD_IPRIORITYR + (i * 4) as usize));
    }
    for i in first_2bit_word()..words_2bit(irqs) {
        s.config.push(r.read(GICD_ICFGR + (i * 4) as usize));
    }
    for intid in SPI_BASE..irqs {
        s.route.push(r.read64(GICD_IROUTER + (intid * 8) as usize));
    }
    s
}

/// Put the distributor state back: disabled first, enabled last, and every
/// enable word cleared before it is set.
/// # C: O(N_irqs)
/// # Ctx: IRQ-off, single-CPU
pub fn dist_restore<R: GicRegs>(r: &mut R, s: &GicDistState) {
    r.write(GICD_CTLR, 0);
    for (n, v) in s.config.iter().enumerate() {
        r.write(GICD_ICFGR + ((first_2bit_word() as usize + n) * 4), *v);
    }
    for (n, v) in s.priority.iter().enumerate() {
        r.write(GICD_IPRIORITYR + ((first_8bit_word() as usize + n) * 4), *v);
    }
    for (n, v) in s.route.iter().enumerate() {
        r.write64(GICD_IROUTER + ((SPI_BASE as usize + n) * 8), *v);
    }
    for (n, v) in s.group.iter().enumerate() {
        r.write(GICD_IGROUPR + ((first_1bit_word() as usize + n) * 4), *v);
    }
    for (n, v) in s.enable.iter().enumerate() {
        let word = (first_1bit_word() as usize + n) * 4;
        r.write(GICD_ICENABLER + word, ALL_BITS);
        r.write(GICD_ISENABLER + word, *v);
    }
    r.write(GICD_CTLR, s.ctlr);
}

/// Stop the distributor delivering anything. # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn dist_quiesce<R: GicRegs>(r: &mut R) { r.write(GICD_CTLR, 0); }

// ---- redistributor ---------------------------------------------------------

/// Read this CPU's private-INTID state from the redistributor's SGI frame.
/// Offsets are relative to that frame.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn redist_save<R: GicRegs>(r: &R) -> GicRedistState {
    let mut s = GicRedistState {
        group0: r.read(GICR_IGROUPR0),
        enable0: r.read(GICR_ISENABLER0),
        priority: [0; PRIVATE_PRIORITY_WORDS],
        config1: r.read(GICR_ICFGR1),
    };
    for (i, w) in s.priority.iter_mut().enumerate() { *w = r.read(GICR_IPRIORITYR + i * 4); }
    s
}

/// Put this CPU's private-INTID state back, enables cleared before set.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn redist_restore<R: GicRegs>(r: &mut R, s: &GicRedistState) {
    r.write(GICR_ICFGR1, s.config1);
    for (i, w) in s.priority.iter().enumerate() { r.write(GICR_IPRIORITYR + i * 4, *w); }
    r.write(GICR_IGROUPR0, s.group0);
    r.write(GICR_ICENABLER0, ALL_BITS);
    r.write(GICR_ISENABLER0, s.enable0);
}

/// Mark this redistributor asleep and wait for it to say its children are.
/// Returns whether the acknowledgement arrived within `spins`.
/// # C: O(spins)
/// # Ctx: IRQ-off, single-CPU
pub fn redist_sleep<R: GicRegs>(r: &mut R, spins: u32) -> bool {
    let w = r.read(GICR_WAKER);
    r.write(GICR_WAKER, w | WAKER_PROCESSOR_SLEEP);
    if r.read(GICR_WAKER) & WAKER_PROCESSOR_SLEEP == 0 { return false; }
    for _ in 0..spins {
        if r.read(GICR_WAKER) & WAKER_CHILDREN_ASLEEP != 0 { return true; }
    }
    false
}

/// Wake this redistributor and wait for it to say its children are awake.
/// # C: O(spins)
/// # Ctx: IRQ-off, single-CPU
pub fn redist_wake<R: GicRegs>(r: &mut R, spins: u32) -> bool {
    let w = r.read(GICR_WAKER);
    r.write(GICR_WAKER, w & !WAKER_PROCESSOR_SLEEP);
    for _ in 0..spins {
        if r.read(GICR_WAKER) & WAKER_CHILDREN_ASLEEP == 0 { return true; }
    }
    false
}

// ---- CPU interface ---------------------------------------------------------

/// The order the CPU interface's system registers go back in: the mask and the
/// control before Group-1 delivery is re-enabled.
/// # C: O(1)
pub const CPUIF_RESTORE_ORDER: [CpuIfReg; 3] = [CpuIfReg::Pmr, CpuIfReg::Ctlr, CpuIfReg::Grpen1];

/// One CPU-interface system register.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CpuIfReg { Pmr, Ctlr, Grpen1 }

impl GicCpuIf {
    /// The value `reg` is restored to. # C: O(1)
    pub const fn value(&self, reg: CpuIfReg) -> u32 {
        match reg { CpuIfReg::Pmr => self.pmr, CpuIfReg::Ctlr => self.ctlr,
                    CpuIfReg::Grpen1 => self.grpen1 }
    }
}
