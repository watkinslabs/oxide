// Which sleep states PSCI offers, and what a firmware refusal means at the
// syscall boundary (`32a§9`).
//
// No target gate: this is the decision `/sys/power/state` renders and the one
// `enter` reports, so it must be reachable from a hosted run. The firmware
// calls that feed it live in `table.rs`.

use hal_aarch64::psci_probe::{SuspendRefusal, SuspendSupport};
use hal_aarch64::psci_uapi::PsciStatus;

use crate::decide::Error;
use crate::suspend::state::SuspendState;

/// Whether this platform can enter `state`.
///
/// `mem` needs the feature probe to have said yes. `standby` is never offered:
/// PSCI has no shallow system state to enter, so admitting it would put a label
/// on `/sys/power/state` that no firmware call backs (`32a§9`). `freeze` never
/// reaches here — suspend-to-idle does not consult the deep table at all
/// (`32a§4`) — and answering true for it would claim the platform enters it
/// through firmware.
/// # C: O(1)
pub fn valid(support: SuspendSupport, state: SuspendState) -> bool {
    match state {
        SuspendState::Mem => support.admits_mem(),
        SuspendState::Standby | SuspendState::ToIdle | SuspendState::On => false,
    }
}

/// Map a firmware status onto the sleep sequence's error. The interface's four
/// meaningful refusals are kept distinct: absent, malformed request, bad
/// address, and refused by policy.
///
/// `Success` arrives here only when firmware returned from a call that should
/// have suspended the machine, which is a firmware defect and is reported as an
/// I/O failure rather than a completed sleep.
/// # C: O(1)
pub fn firmware_error(st: PsciStatus) -> Error {
    match st {
        PsciStatus::NotSupported      => Error::Nosys,
        PsciStatus::InvalidParameters => Error::Inval,
        PsciStatus::InvalidAddress    => Error::Inval,
        PsciStatus::Denied            => Error::Perm,
        _                             => Error::Io,
    }
}

/// Map a pre-call refusal onto the same error space. These are the kernel's own
/// preconditions, not firmware's answer, so only the unsupported case reports
/// "no such facility"; the rest mean the machine could not be handed a resume
/// path it would survive.
/// # C: O(1)
pub fn refusal_error(r: SuspendRefusal) -> Error {
    match r {
        SuspendRefusal::Unsupported      => Error::Nosys,
        SuspendRefusal::NoResumeEntry    => Error::Io,
        SuspendRefusal::NoIdentityTable  => Error::Io,
        SuspendRefusal::NoContextAddress => Error::Io,
    }
}

#[cfg(test)]
#[path = "tests/admit.rs"]
mod tests;
