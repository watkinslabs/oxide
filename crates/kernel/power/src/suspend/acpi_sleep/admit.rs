// Which ACPI sleep states this machine may enter, as a pure function of what
// firmware published.
//
// `32a§2` invariant 7: a state that loses CPU context needs BOTH a resume
// vector and a saved processor state, and a platform that cannot supply both
// must not admit it. So the two are separate facts here, and `mem` needs both
// — a machine whose resume stub could not be placed offers `standby` and
// suspend-to-idle, and offering `mem` there is how a suspend becomes a
// power-off with unsaved work in it.

use crate::suspend::state::SuspendState;

/// What firmware and the arch layer actually supplied, one fact each.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformFacts {
    /// `_S1` resolved to a SLP_TYP pair AND the FADT registers resolve to a
    /// write. Either half missing means there is no S1 to enter.
    pub s1_action: bool,
    /// Same for `_S3`.
    pub s3_action: bool,
    /// A physical resume address exists and can be published in the FACS
    /// firmware waking vector.
    pub resume_vector: bool,
    /// The processor-context record exists, so the state a deep sleep loses
    /// is saved before the machine is handed to firmware.
    pub state_save: bool,
}

/// Whether the platform admits `state`.
///
/// Suspend-to-idle is never asked about here: it needs no platform support
/// and the sequence routes it to the s2idle table instead (`32a§4`).
/// # C: O(1)
pub fn admits(facts: PlatformFacts, state: SuspendState) -> bool {
    match state {
        SuspendState::Standby => facts.s1_action,
        SuspendState::Mem => facts.s3_action && facts.resume_vector && facts.state_save,
        SuspendState::ToIdle | SuspendState::On => false,
    }
}

#[cfg(test)]
#[path = "tests/admit.rs"]
mod tests;
