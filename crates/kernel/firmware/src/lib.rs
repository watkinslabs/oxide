// Firmware tables per `33`. Owns ACPI RSDP/XSDT/MADT/HPET/MCFG
// parsing. DT (device-tree) bring-up rides v2.x.
//
// Public surface:
//   - try_log_acpi(rsdp_pa, hhdm)   — boot-time table walk + log
//   - set_add_cpu_hook(f)           — install the kernel-side
//                                     cpu_topology callback fired
//                                     for each MADT CPU entry
//
// The kernel installs `set_add_cpu_hook(cpu_topology::add_cpu)`
// once at boot before invoking try_log_acpi. This decouples the
// ACPI walker (here) from the kernel's cpu-topology registry.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU64, Ordering};

pub mod acpi;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Io }

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time init reporter. Real walk happens via `try_log_acpi`.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

/// Add-cpu hook fired for each MADT entry. Kernel installs the
/// cpu_topology::add_cpu callback at boot.
pub type AddCpu = unsafe fn(id: u32, flags: u32) -> bool;

static ADD_CPU_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the per-CPU registration callback. Called once at boot
/// from the kernel before the ACPI walk.
/// # C: O(1)
pub fn set_add_cpu_hook(f: AddCpu) {
    ADD_CPU_HOOK.store(f as u64, Ordering::Release);
}

/// Fire the registered add-cpu callback. No-op when not installed.
/// # SAFETY: forwards to caller-installed hook with the documented signature; only invoked from acpi.rs MADT walk inside an `unsafe { try_log_acpi }`.
/// # C: O(1)
pub unsafe fn fire_add_cpu(id: u32, flags: u32) -> bool {
    let h = ADD_CPU_HOOK.load(Ordering::Acquire);
    if h == 0 { return false; }
    // SAFETY: h was installed by `set_add_cpu_hook` with a matching `unsafe fn(u32,u32)->bool` ABI.
    let f: AddCpu = unsafe { core::mem::transmute(h) };
    // SAFETY: hook ABI matches the documented signature; caller of fire_add_cpu holds the same boot-path preconditions.
    unsafe { f(id, flags) }
}

pub use acpi::try_log_acpi;
pub use acpi::RsdpStatus;

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no side effects.
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
}
