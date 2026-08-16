// What the installed table means for `/sys/power/state` and
// `/sys/power/mem_sleep`. Hosted: `table.rs` carries no target gate; the
// firmware calls inside it do.

use super::*;
use crate::suspend::state::{mem_sleep_states, pm_states, valid_state};

/// A table shaped exactly like the real one but wired to a platform whose probe
/// said yes, so the admission ladder can be exercised without firmware.
fn valid_on_a_supporting_platform(state: SuspendState) -> bool {
    admit::valid(SuspendSupport::Supported(0), state)
}
fn never_entered(_: SuspendState) -> KResult<()> { Err(Error::Io) }

static SUPPORTING_OPS: PlatformSuspendOps = PlatformSuspendOps {
    valid: Some(valid_on_a_supporting_platform),
    enter: Some(never_entered),
    begin: None, prepare: None, prepare_late: None, wake: None, finish: None,
    suspend_again: None, end: None, recover: None,
};

#[test]
fn the_table_supplies_only_the_two_hooks_psci_needs() {
    assert!(PSCI_SUSPEND_OPS.valid.is_some());
    assert!(PSCI_SUSPEND_OPS.enter.is_some());
    assert!(PSCI_SUSPEND_OPS.begin.is_none());
    assert!(PSCI_SUSPEND_OPS.prepare.is_none());
    assert!(PSCI_SUSPEND_OPS.prepare_late.is_none());
    assert!(PSCI_SUSPEND_OPS.wake.is_none());
    assert!(PSCI_SUSPEND_OPS.finish.is_none());
    assert!(PSCI_SUSPEND_OPS.suspend_again.is_none());
    assert!(PSCI_SUSPEND_OPS.end.is_none());
    assert!(PSCI_SUSPEND_OPS.recover.is_none());
}

#[test]
fn a_supporting_platform_offers_deep_and_never_standby() {
    let ops = Some(&SUPPORTING_OPS);
    assert!(valid_state(ops, SuspendState::Mem));
    assert!(!valid_state(ops, SuspendState::Standby));
    let mech = mem_sleep_states(ops);
    assert!(mech.contains(SuspendState::Mem), "deep must be listed");
    assert!(mech.contains(SuspendState::ToIdle));
    assert!(!mech.contains(SuspendState::Standby), "shallow must never be listed");
    // `standby` never appears on /sys/power/state either.
    assert!(!pm_states(ops).contains(SuspendState::Standby));
}

#[test]
fn an_unprobed_machine_offers_no_deep_state_through_this_table() {
    let ops = Some(&PSCI_SUSPEND_OPS);
    assert!(!valid_state(ops, SuspendState::Mem));
    assert!(!valid_state(ops, SuspendState::Standby));
    let mech = mem_sleep_states(ops);
    assert!(mech.contains(SuspendState::ToIdle), "freeze is always available");
    assert!(!mech.contains(SuspendState::Mem));
    assert!(!mech.contains(SuspendState::Standby));
}

#[test]
fn entering_a_state_the_table_does_not_admit_is_refused_not_attempted() {
    let enter = PSCI_SUSPEND_OPS.enter.expect("enter present");
    assert_eq!(enter(SuspendState::Standby), Err(Error::Nosys));
    assert_eq!(enter(SuspendState::ToIdle),  Err(Error::Nosys));
    // Unprobed on a hosted run, so `mem` is refused here too.
    assert_eq!(enter(SuspendState::Mem), Err(Error::Nosys));
}

#[test]
fn init_installs_nothing_where_there_is_no_firmware_conduit() {
    let _g = crate::suspend::test_lock();
    // SAFETY: hosted build; the arch call is compiled out and this is the no-op branch.
    let installed = unsafe { init() };
    assert!(!installed, "a machine with no PSCI conduit must not register a deep table");
    assert!(crate::suspend::ops::suspend_ops().is_none()
        || !valid_state(crate::suspend::ops::suspend_ops(), SuspendState::Mem));
}
