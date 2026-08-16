// The `PlatformSuspendOps` PSCI installs, and its registration (`32a§4`).
//
// Only `valid` and `enter` are supplied. PSCI's deep sleep needs no begin/end
// bracket, no prepare phases and no recovery hook: the whole platform side is
// one firmware call, and everything around it is the generic sequence.

use hal_aarch64::psci_probe::SuspendSupport;

use crate::decide::{Error, KResult};
use crate::suspend::ops::PlatformSuspendOps;
use crate::suspend::state::SuspendState;
use super::admit;

/// The probe result this machine reported. Absent on any build without the
/// aarch64 firmware conduit, where nothing can be admitted.
/// # C: O(1)
fn support() -> SuspendSupport {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { hal_aarch64::psci::system_suspend_support() }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { SuspendSupport::Unprobed }
}

/// `32a§4` validity check. # C: O(1)
fn ops_valid(state: SuspendState) -> bool { admit::valid(support(), state) }

/// `32a§5` step 15. Hands the machine to firmware and returns once the resume
/// entry has restored the processor state.
/// # C: O(sleep)
/// # Ctx: IRQ-off, single-CPU
fn ops_enter(state: SuspendState) -> KResult<()> {
    if !ops_valid(state) { return Err(Error::Nosys); }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        use hal_aarch64::cpu_suspend::{system_suspend, SuspendError};
        // SAFETY: the sequence reaches step 15 with interrupts disabled, one CPU online and every device suspended, which is exactly this call's contract.
        return match unsafe { system_suspend(support()) } {
            Ok(())                          => Ok(()),
            Err(SuspendError::Refused(r))   => Err(admit::refusal_error(r)),
            Err(SuspendError::Firmware(st)) => Err(admit::firmware_error(st)),
        };
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    Err(Error::Nosys)
}

/// The table `32a§4` registers. Every other member is absent by design.
pub static PSCI_SUSPEND_OPS: PlatformSuspendOps = PlatformSuspendOps {
    valid: Some(ops_valid),
    enter: Some(ops_enter),
    begin: None, prepare: None, prepare_late: None, wake: None, finish: None,
    suspend_again: None, end: None, recover: None,
};

/// Probe the firmware and install the table when it reports `SYSTEM_SUSPEND`.
///
/// A platform that reports it unsupported registers nothing, so
/// `/sys/power/state` offers `freeze` alone — the correct reading of the
/// firmware, not a gap (`32a§9`).
/// # SAFETY: caller is the boot path before `/sys/power` is readable; issues
/// firmware calls on the platform conduit.
/// # C: O(two PSCI calls)
/// # Ctx: boot, single-CPU
pub unsafe fn init() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: per fn contract — boot path, single CPU, conduit configured; both probe calls only read firmware state.
        let support = unsafe { hal_aarch64::psci::probe_system_suspend() };
        if !support.admits_mem() { return false; }
        crate::suspend::ops::suspend_set_ops(&PSCI_SUSPEND_OPS);
        return true;
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    false
}

#[cfg(test)]
#[path = "tests/table.rs"]
mod tests;
