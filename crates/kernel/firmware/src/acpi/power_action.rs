//! Canonical FADT-plus-AML S5 action publication.

use sync::{Devices, Spinlock};

use super::fadt::{PowerOffAction, PowerRegisters};

static REGISTERS: Spinlock<Option<PowerRegisters>, Devices> = Spinlock::new(None);
static ACTION: Spinlock<Option<PowerOffAction>, Devices> = Spinlock::new(None);

/// Retain the one FADT register contract from which S5 is built. # C: O(1)
pub(crate) fn set_power_registers(registers: PowerRegisters) {
    let mut present = REGISTERS.lock();
    if present.is_none() { *present = Some(registers); }
}

/// Read the FADT register contract while AML resolves `_S5`. # C: O(1)
pub(crate) fn power_registers() -> Option<PowerRegisters> { *REGISTERS.lock() }

/// Publish the one validated terminal power-off action. # C: O(1)
pub(crate) fn set_poweroff_action(action: PowerOffAction) {
    let mut present = ACTION.lock();
    if present.is_none() { *present = Some(action); }
}

/// Return the firmware-authorised S5 action, if AML and FADT supplied one. # C: O(1)
pub fn poweroff_action() -> Option<PowerOffAction> { *ACTION.lock() }
