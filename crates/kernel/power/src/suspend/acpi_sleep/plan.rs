// The register writes one sleep entry performs, in order, as data.
//
// The order IS the contract and the split IS deliberate. On the legacy
// register pair the SLP_TYP field and the SLP_EN bit go out in TWO separate
// writes to the same register, because hardware exists that latches the
// transition on the SLP_EN edge and samples SLP_TYP from the previous bus
// cycle; merging them makes such a machine enter whatever state its
// SLP_TYP field happened to hold. The reduced-hardware register takes the
// opposite shape — one write carrying both — and mirroring the legacy split
// there would issue a spurious transition-less write.
//
// Producing the writes as data rather than performing them is what makes the
// ordering testable at all: the executor in `io.rs` is a loop.

use firmware::acpi::Gas;

use crate::poweroff_plan::legacy_writes;

/// Reduced-hardware sleep-control layout: SLP_TYP at bit 2, SLP_EN at bit 5,
/// and WAK_STS at bit 7 of the paired status register.
pub const REDUCED_SLEEP_TYPE_SHIFT: u8 = 2;
pub const REDUCED_SLEEP_TYPE_MASK: u8 = 0x1c;
pub const REDUCED_SLEEP_ENABLE: u8 = 0x20;
pub const REDUCED_WAKE_STATUS: u8 = 0x80;

/// PM1 status bit 15, `WAK_STS`. Write-1-to-clear.
pub const PM1_WAKE_STATUS: u16 = 1 << 15;

/// What one write in the plan is for. The executor does not care; the tests
/// and the log do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SleepWriteKind {
    /// Clear the wake status bit, so the wake that ends this sleep is
    /// distinguishable from the one that ended the last.
    WakeStatusClear,
    /// The SLP_TYP field, with no enable bit set.
    SleepType,
    /// The write that starts the transition.
    SleepEnable,
    /// SLP_TYP and SLP_EN together — the reduced-hardware register's shape.
    SleepTypeAndEnable,
}

/// One register write.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SleepWrite {
    pub kind: SleepWriteKind,
    pub gas: Gas,
    /// Access width in bytes: 1 for the reduced-hardware registers, 2 for
    /// the PM1 pair.
    pub width: u8,
    pub value: u32,
}

/// Both PM1 registers, both halves of the split, plus both status clears.
pub const MAX_SLEEP_WRITES: usize = 6;

/// An ordered, bounded write list. No allocation: this is built with
/// interrupts disabled on the last CPU standing.
#[derive(Copy, Clone, Debug)]
pub struct SleepPlan {
    writes: [Option<SleepWrite>; MAX_SLEEP_WRITES],
    len: usize,
}

impl SleepPlan {
    fn new() -> Self { SleepPlan { writes: [None; MAX_SLEEP_WRITES], len: 0 } }

    fn push(&mut self, kind: SleepWriteKind, gas: Gas, width: u8, value: u32) {
        if self.len >= MAX_SLEEP_WRITES { return; }
        self.writes[self.len] = Some(SleepWrite { kind, gas, width, value });
        self.len += 1;
    }

    /// How many writes the plan holds. # C: O(1)
    pub fn len(&self) -> usize { self.len }

    /// Whether the plan performs no write at all. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// The write at `index`, in issue order. # C: O(1)
    pub fn get(&self, index: usize) -> Option<SleepWrite> {
        if index >= self.len { return None; }
        self.writes[index]
    }

    /// The kinds, in issue order, for the given prefix. # C: O(n)
    pub fn kinds(&self) -> [Option<SleepWriteKind>; MAX_SLEEP_WRITES] {
        let mut out = [None; MAX_SLEEP_WRITES];
        for index in 0..self.len { out[index] = self.writes[index].map(|w| w.kind); }
        out
    }
}

/// The legacy PM1 sleep sequence.
///
/// `base` is the live PM1a control value: the non-sleep control bits in it
/// are preserved, because the register also carries SCI_EN and the bus-master
/// controls, and a sleep entry that clears those does not come back.
/// # C: O(1)
pub fn legacy_plan(pm1a_control: Gas, pm1b_control: Option<Gas>,
                   status_a: Option<(Gas, u8)>, status_b: Option<(Gas, u8)>,
                   base: u16, type_a: u8, type_b: u8) -> SleepPlan {
    let mut plan = SleepPlan::new();
    if let Some((gas, width)) = status_a {
        plan.push(SleepWriteKind::WakeStatusClear, gas, width.min(2), PM1_WAKE_STATUS as u32);
    }
    if let Some((gas, width)) = status_b {
        plan.push(SleepWriteKind::WakeStatusClear, gas, width.min(2), PM1_WAKE_STATUS as u32);
    }
    let w = legacy_writes(base, type_a, type_b);
    plan.push(SleepWriteKind::SleepType, pm1a_control, 2, w.first_a as u32);
    if let Some(gas) = pm1b_control { plan.push(SleepWriteKind::SleepType, gas, 2, w.first_b as u32); }
    plan.push(SleepWriteKind::SleepEnable, pm1a_control, 2, w.enable_a as u32);
    if let Some(gas) = pm1b_control { plan.push(SleepWriteKind::SleepEnable, gas, 2, w.enable_b as u32); }
    plan
}

/// The reduced-hardware sleep sequence: clear the wake status, then one
/// write carrying SLP_TYP and SLP_EN together.
/// # C: O(1)
pub fn reduced_plan(sleep_control: Gas, sleep_status: Gas, sleep_type: u8) -> SleepPlan {
    let mut plan = SleepPlan::new();
    plan.push(SleepWriteKind::WakeStatusClear, sleep_status, 1, REDUCED_WAKE_STATUS as u32);
    let value = ((sleep_type << REDUCED_SLEEP_TYPE_SHIFT) & REDUCED_SLEEP_TYPE_MASK) | REDUCED_SLEEP_ENABLE;
    plan.push(SleepWriteKind::SleepTypeAndEnable, sleep_control, 1, value as u32);
    plan
}

#[cfg(test)]
#[path = "tests/plan.rs"]
mod tests;
