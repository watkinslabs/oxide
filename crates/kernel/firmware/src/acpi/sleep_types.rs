// `_Sx` sleep-type ownership: the AML-declared SLP_TYP pair per sleep state,
// the PM1 status register the wake bit lives in, and the firmware-authorised
// action a sleep state resolves to.
//
// `\_S5` keeps its own publication path (`power_action`) because the terminal
// transition consumes it and must not depend on anything the reversible sleep
// path installs later. The DECODE is shared: one pure function reads a `_Sx`
// package for every state, so a fix to the packed single-value form cannot
// apply to one state and not the others.

use sync::{Devices, Spinlock};

use super::fadt::{Fadt, Gas, PowerOffAction, SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY};

/// Reversible sleep states this port evaluates `_Sx` for. `_S5` is terminal
/// and lives on the power-off path; `_S2` and `_S4` name states no platform
/// operations table here admits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SleepState { S1 = 1, S3 = 3 }

/// Every state evaluated at namespace-construction time.
pub const EVALUATED: [SleepState; 2] = [SleepState::S1, SleepState::S3];

impl SleepState {
    /// Fully-qualified AML object name holding this state's SLP_TYP package.
    /// # C: O(1)
    pub fn aml_path(self) -> &'static str {
        match self { SleepState::S1 => "\\_S1", SleepState::S3 => "\\_S3" }
    }

    /// Dense index into the publication table. # C: O(1)
    pub fn index(self) -> usize {
        match self { SleepState::S1 => 0, SleepState::S3 => 1 }
    }
}

/// Decode a `_Sx` package's integer values into the PM1a/PM1b SLP_TYP pair.
///
/// Two encodings exist and both are in the field: a package of at least two
/// integers holds the values separately, and a package of exactly one holds
/// them packed, PM1b in the second byte. Reading the packed form as a
/// one-element list gives PM1b = 0, which is a legal SLP_TYP value on most
/// chipsets — so the bug is silent and the machine enters the wrong state.
/// # C: O(1)
pub fn sleep_type_pair(values: &[u64]) -> Option<(u8, u8)> {
    let first = *values.first()?;
    let second = if values.len() == 1 { first >> 8 } else { values[1] };
    Some((first as u8, second as u8))
}

/// Largest SLP_TYP a three-bit PM1 control field can carry.
pub const MAX_SLEEP_TYPE: u8 = 7;

/// The PM1 event block halves and the flags the sleep path consumes,
/// alongside the control registers `PowerRegisters` already carries.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SleepRegisters {
    pub pm1a_event: Gas,
    pub pm1b_event: Gas,
    pub pm1_event_len: u8,
}

/// PM1 status bit 15, `WAK_STS`. Write-1-to-clear, and cleared before every
/// sleep entry so the wake that ends the sleep is distinguishable from the
/// one that ended the last.
pub const PM1_WAKE_STATUS: u16 = 1 << 15;

/// The PM1 status register: the FIRST half of the PM1 event block. The
/// second half is the enable register, and writing the wake-status bit
/// there arms an event instead of clearing one.
///
/// `None` when firmware published no event block, or one too short to have
/// two halves — a one-byte "event block" cannot carry a 16-bit status word.
/// # C: O(1)
pub fn status_register(event: Gas, event_len: u8) -> Option<(Gas, u8)> {
    if event.address == 0 { return None; }
    match event.space_id { SPACE_SYSTEM_IO | SPACE_SYSTEM_MEMORY => {} _ => return None }
    let half = event_len / 2;
    if half < 2 { return None; }
    Some((event, half))
}

/// Extract the PM1 event-block state the sleep path consumes. # C: O(1)
pub fn sleep_registers(f: &Fadt) -> SleepRegisters {
    SleepRegisters { pm1a_event: f.pm1a_event, pm1b_event: f.pm1b_event, pm1_event_len: f.pm1_event_len }
}

static TYPES: Spinlock<[Option<(u8, u8)>; EVALUATED.len()], Devices> = Spinlock::new([None; EVALUATED.len()]);
static REGISTERS: Spinlock<Option<SleepRegisters>, Devices> = Spinlock::new(None);

/// Retain one state's AML-declared SLP_TYP pair (first wins). # C: O(1)
pub fn set_sleep_types(state: SleepState, types: (u8, u8)) {
    if types.0 > MAX_SLEEP_TYPE || types.1 > MAX_SLEEP_TYPE { return; }
    let mut table = TYPES.lock();
    if table[state.index()].is_none() { table[state.index()] = Some(types); }
}

/// The SLP_TYP pair firmware declared for `state`. # C: O(1)
pub fn sleep_types(state: SleepState) -> Option<(u8, u8)> { TYPES.lock()[state.index()] }

/// Retain the PM1 event-block registers (first wins). # C: O(1)
pub fn set_sleep_registers(registers: SleepRegisters) {
    let mut present = REGISTERS.lock();
    if present.is_none() { *present = Some(registers); }
}

/// The retained PM1 event-block registers. # C: O(1)
pub fn sleep_registers_published() -> Option<SleepRegisters> { *REGISTERS.lock() }

/// The PM1 status register and its byte width, if firmware published a
/// usable event block. # C: O(1)
pub fn wake_status_registers() -> Option<((Gas, u8), Option<(Gas, u8)>)> {
    let r = sleep_registers_published()?;
    let a = status_register(r.pm1a_event, r.pm1_event_len)?;
    let b = status_register(r.pm1b_event, r.pm1_event_len);
    Some((a, b))
}

/// The firmware-authorised register write for `state`: the same register
/// ownership ladder the terminal transition uses, combined with this state's
/// AML-declared SLP_TYP pair instead of `_S5`'s.
/// # C: O(1)
pub fn sleep_action(state: SleepState) -> Option<PowerOffAction> {
    let registers = super::power_action::power_registers()?;
    let (type_a, type_b) = sleep_types(state)?;
    super::fadt::poweroff_action(registers, type_a, type_b)
}

/// Whether firmware declared `_Sx` for `state`. # C: O(1)
pub fn state_declared(state: SleepState) -> bool { sleep_types(state).is_some() }

#[cfg(test)]
#[path = "sleep_types/tests.rs"]
mod tests;
