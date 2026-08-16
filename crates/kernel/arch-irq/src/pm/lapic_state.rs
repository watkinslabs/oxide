// Local-APIC state across a sleep that loses CPU context (`32a§7`).
//
// The order is the contract, twice over, and neither half is the other's
// reverse:
//
//   * Save reads the identification, priority, routing and timer registers.
//   * Restore writes the error entry MASKED first, so nothing the intervening
//     writes provoke can raise an error interrupt into a half-restored APIC;
//     then identification and addressing, then the spurious register (which
//     is what re-enables the APIC, so everything it could deliver must already
//     be programmed), then the local vector entries, then the timer, and only
//     at the very end the real error entry — with the error status cleared on
//     both sides of that write.
//
// Generic over the register window so the whole round trip runs on the host.

use crate::apicdef::*;

/// A local-APIC register window.
pub trait ApicRegs {
    /// Read the register at `off`. # C: O(1)
    fn read(&self, off: usize) -> u32;
    /// Write `v` to the register at `off`. # C: O(1)
    fn write(&mut self, off: usize, v: u32);
}

/// Saved local-APIC state.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct LapicState {
    /// Highest implemented local-vector entry, deciding which of the optional
    /// entries below were saved and must be restored.
    pub maxlvt: u32,
    pub id: u32,
    pub taskpri: u32,
    pub ldr: u32,
    pub dfr: u32,
    pub spiv: u32,
    pub lvt_timer: u32,
    pub lvt_perf: u32,
    pub lvt_lint0: u32,
    pub lvt_lint1: u32,
    pub lvt_error: u32,
    pub timer_init: u32,
    pub timer_div: u32,
    pub lvt_thermal: u32,
    pub lvt_cmci: u32,
}

impl LapicState {
    /// Whether the performance-counter entry exists on this APIC. # C: O(1)
    pub const fn has_perf(&self) -> bool { self.maxlvt >= MAXLVT_PERF }
    /// Whether the thermal-sensor entry exists on this APIC. # C: O(1)
    pub const fn has_thermal(&self) -> bool { self.maxlvt >= MAXLVT_THERMAL }
    /// Whether the corrected-machine-check entry exists. # C: O(1)
    pub const fn has_cmci(&self) -> bool { self.maxlvt >= MAXLVT_CMCI }
}

/// Read the local-APIC state that a context-losing sleep destroys.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn save<R: ApicRegs>(r: &R) -> LapicState {
    let maxlvt = maxlvt(r.read(REG_VERSION));
    let mut s = LapicState {
        maxlvt,
        id: r.read(REG_ID),
        taskpri: r.read(REG_TASKPRI),
        ldr: r.read(REG_LDR),
        dfr: r.read(REG_DFR),
        spiv: r.read(REG_SVR),
        lvt_timer: r.read(REG_LVT_TIMER),
        lvt_perf: 0,
        lvt_lint0: r.read(REG_LVT_LINT0),
        lvt_lint1: r.read(REG_LVT_LINT1),
        lvt_error: r.read(REG_LVT_ERROR),
        timer_init: r.read(REG_TIMER_INIT),
        timer_div: r.read(REG_TIMER_DIV),
        lvt_thermal: 0,
        lvt_cmci: 0,
    };
    if s.has_perf() { s.lvt_perf = r.read(REG_LVT_PERF); }
    if s.has_thermal() { s.lvt_thermal = r.read(REG_LVT_THERMAL); }
    if s.has_cmci() { s.lvt_cmci = r.read(REG_LVT_CMCI); }
    s
}

/// Quiesce the local APIC: mask every implemented local-vector entry and clear
/// the software-enable bit, so nothing is delivered while the machine is on its
/// way down.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn quiesce<R: ApicRegs>(r: &mut R, s: &LapicState) {
    for off in [REG_LVT_TIMER, REG_LVT_LINT0, REG_LVT_LINT1, REG_LVT_ERROR] {
        let v = r.read(off);
        r.write(off, v | LVT_MASKED);
    }
    if s.has_perf() { let v = r.read(REG_LVT_PERF); r.write(REG_LVT_PERF, v | LVT_MASKED); }
    if s.has_thermal() { let v = r.read(REG_LVT_THERMAL); r.write(REG_LVT_THERMAL, v | LVT_MASKED); }
    if s.has_cmci() { let v = r.read(REG_LVT_CMCI); r.write(REG_LVT_CMCI, v | LVT_MASKED); }
    let spiv = r.read(REG_SVR);
    r.write(REG_SVR, spiv & !SVR_ENABLE);
}

/// Put the saved state back, in the order that keeps the APIC from delivering
/// anything through a half-programmed configuration.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn restore<R: ApicRegs>(r: &mut R, s: &LapicState) {
    r.write(REG_LVT_ERROR, s.lvt_error | LVT_MASKED);
    r.write(REG_ID, s.id);
    r.write(REG_DFR, s.dfr);
    r.write(REG_LDR, s.ldr);
    r.write(REG_TASKPRI, s.taskpri);
    r.write(REG_SVR, s.spiv);
    r.write(REG_LVT_LINT0, s.lvt_lint0);
    r.write(REG_LVT_LINT1, s.lvt_lint1);
    if s.has_thermal() { r.write(REG_LVT_THERMAL, s.lvt_thermal); }
    if s.has_cmci() { r.write(REG_LVT_CMCI, s.lvt_cmci); }
    if s.has_perf() { r.write(REG_LVT_PERF, s.lvt_perf); }
    r.write(REG_LVT_TIMER, s.lvt_timer);
    r.write(REG_TIMER_DIV, s.timer_div);
    r.write(REG_TIMER_INIT, s.timer_init);
    r.write(REG_ESR, 0);
    let _ = r.read(REG_ESR);
    r.write(REG_LVT_ERROR, s.lvt_error);
    r.write(REG_ESR, 0);
    let _ = r.read(REG_ESR);
}
