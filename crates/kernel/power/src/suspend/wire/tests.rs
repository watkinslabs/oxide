use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::suspend::state::SuspendState;

static CALLED: AtomicU32 = AtomicU32::new(0);
fn mark(bit: u32) { CALLED.fetch_or(1 << bit, Ordering::SeqCst); }

fn h_sync() -> KResult<()> { mark(0); Ok(()) }
fn h_freeze_u() -> KResult<()> { mark(1); Ok(()) }
fn h_freeze_k() -> KResult<()> { mark(2); Ok(()) }
fn h_thaw() { mark(3); }
fn h_dpm_prepare() -> KResult<()> { mark(4); Ok(()) }
fn h_dpm_suspend() -> KResult<()> { mark(5); Ok(()) }
fn h_dpm_resume() { mark(6); }
fn h_dpm_complete() { mark(7); }

#[test]
fn an_unwired_machine_still_completes_a_freeze_cycle() {
    let _g = crate::suspend::test_lock();
    set_hooks(SuspendHooks::default());
    crate::suspend::tunables::release_transition();
    assert!(crate::suspend::run::pm_suspend(
        SuspendState::ToIdle, &backend(), crate::suspend::platform::Tables::none()).is_ok());
}

#[test]
fn an_unwired_machine_refuses_the_deep_states() {
    let _g = crate::suspend::test_lock();
    set_hooks(SuspendHooks::default());
    crate::suspend::tunables::release_transition();
    let t = crate::suspend::platform::Tables::none();
    assert!(crate::suspend::run::pm_suspend(SuspendState::Mem, &backend(), t).is_err());
}

#[test]
fn every_installed_hook_is_reached_by_a_cycle() {
    let _g = crate::suspend::test_lock();
    CALLED.store(0, Ordering::SeqCst);
    set_hooks(SuspendHooks {
        sync_filesystems: Some(h_sync), freeze_processes: Some(h_freeze_u),
        freeze_kernel_threads: Some(h_freeze_k), thaw_processes: Some(h_thaw),
        dpm_prepare: Some(h_dpm_prepare), dpm_suspend: Some(h_dpm_suspend),
        dpm_resume: Some(h_dpm_resume), dpm_complete: Some(h_dpm_complete),
        ..SuspendHooks::default()
    });
    crate::suspend::tunables::release_transition();
    crate::suspend::tunables::set_sync_on_suspend(true);
    assert!(crate::suspend::run::pm_suspend(
        SuspendState::ToIdle, &backend(), crate::suspend::platform::Tables::none()).is_ok());
    assert_eq!(CALLED.load(Ordering::SeqCst), 0xFF, "an installed hook was never called");
    set_hooks(SuspendHooks::default());
}

#[test]
fn a_hook_that_refuses_stops_the_cycle() {
    let _g = crate::suspend::test_lock();
    fn refuse() -> KResult<()> { Err(crate::decide::Error::Busy) }
    set_hooks(SuspendHooks { freeze_processes: Some(refuse), ..SuspendHooks::default() });
    crate::suspend::tunables::release_transition();
    assert_eq!(crate::suspend::run::pm_suspend(
        SuspendState::ToIdle, &backend(), crate::suspend::platform::Tables::none()),
        Err(crate::decide::Error::Busy));
    set_hooks(SuspendHooks::default());
}

#[test]
fn the_interrupt_state_round_trips_through_the_backend() {
    // Hosted, both are no-ops; the check is that the pair type-checks against
    // the arch gate and that a restore accepts what the disable returned.
    let saved = irqs_off();
    irqs_on(saved);
}
