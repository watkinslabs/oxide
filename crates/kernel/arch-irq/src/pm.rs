// Interrupt-controller core callbacks (`32a§7`).
//
// The interrupt controllers have no device to hang from, so they register a
// core operations table rather than a driver one. The table's suspend runs
// with interrupts disabled and one CPU online, after every device is down.
//
// Module manifest:
// - `lapic_state`:  local-APIC save/quiesce/restore, generic over the window.
// - `ioapic_state`: I/O-APIC redirection-table save/mask/restore.
// - `gic_state`:    GIC distributor, redistributor and CPU-interface state.
// - `syscore_x86`:  those state machines bound to the real x86 controllers.
// - `syscore_arm`:  the same for the GIC.
// - `tests`:        register round trips and the ordering contracts.

pub mod lapic_state;
pub mod ioapic_state;
pub mod gic_state;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod syscore_x86;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub mod syscore_arm;

/// Register every interrupt controller this architecture has with the core
/// callback table (`32a§7`). Called once from boot, before any sleep is
/// possible.
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub fn register() {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    syscore_x86::register();
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    syscore_arm::register();
}

#[cfg(test)]
#[path = "pm/tests/lapic.rs"]
mod tests_lapic;
#[cfg(test)]
#[path = "pm/tests/ioapic.rs"]
mod tests_ioapic;
#[cfg(test)]
#[path = "pm/tests/gic.rs"]
mod tests_gic;
