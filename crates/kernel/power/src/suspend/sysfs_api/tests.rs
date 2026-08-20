use super::*;
use crate::suspend::wire::{set_hooks, SuspendHooks};

fn quiesce() {
    set_hooks(SuspendHooks::default());
    tunables::release_transition();
    tunables::set_mem_sleep_current(SuspendState::ToIdle);
    tunables::set_sync_on_suspend(true);
    wakeup::SYSTEM.wakeup_clear(0);
    wakeup::SYSTEM.disarm();
}

#[test]
fn state_reads_the_available_set() {
    let _g = crate::suspend::test_lock();
    quiesce();
    // No platform table is installed in a hosted build, so the reference's
    // unconditional pair is what shows.
    assert_eq!(show("state").unwrap(), b"freeze mem\n".to_vec());
}

#[test]
fn mem_sleep_reads_the_selection_bracketed() {
    let _g = crate::suspend::test_lock();
    quiesce();
    assert_eq!(show("mem_sleep").unwrap(), b"[s2idle]\n".to_vec());
}

#[test]
fn the_boolean_attributes_round_trip() {
    let _g = crate::suspend::test_lock();
    quiesce();
    for name in ["pm_async", "pm_debug_messages", "sync_on_suspend"] {
        store(name, b"0\n").unwrap();
        assert_eq!(show(name).unwrap(), b"0\n".to_vec(), "{name}");
        store(name, b"1\n").unwrap();
        assert_eq!(show(name).unwrap(), b"1\n".to_vec(), "{name}");
        assert_eq!(store(name, b"2\n"), Err(Error::Inval), "{name} accepted 2");
        assert_eq!(show(name).unwrap(), b"1\n".to_vec(), "{name} changed on a bad write");
    }
    quiesce();
}

#[test]
fn an_unknown_attribute_reads_and_writes_as_an_error() {
    let _g = crate::suspend::test_lock();
    quiesce();
    assert_eq!(show("nonesuch"), Err(Error::Nodata));
    assert_eq!(store("nonesuch", b"1\n"), Err(Error::Inval));
}

#[test]
fn writing_an_unavailable_state_is_rejected_without_suspending() {
    let _g = crate::suspend::test_lock();
    quiesce();
    assert_eq!(store("state", b"standby\n"), Err(Error::Inval));
    assert_eq!(store("state", b"disk\n"), Err(Error::Inval));
    assert_eq!(store("state", b"\n"), Err(Error::Inval));
}

#[test]
fn writing_freeze_runs_a_cycle_and_returns_once_it_is_over() {
    let _g = crate::suspend::test_lock();
    quiesce();
    let before = stats::STATS.success();
    assert_eq!(store("state", b"freeze\n"), Ok(()));
    assert_eq!(stats::STATS.success(), before + 1);
    assert!(!tunables::transition_in_progress());
}

#[test]
fn writing_mem_enters_the_selected_mechanism() {
    let _g = crate::suspend::test_lock();
    quiesce();
    // With no platform table the selection is s2idle, so `mem` is enterable
    // even though no deep state exists — that indirection is the whole point.
    let before = stats::STATS.success();
    assert_eq!(store("state", b"mem\n"), Ok(()));
    assert_eq!(stats::STATS.success(), before + 1);
}

#[test]
fn the_mem_sleep_selection_only_accepts_listed_mechanisms() {
    let _g = crate::suspend::test_lock();
    quiesce();
    assert_eq!(store("mem_sleep", b"s2idle\n"), Ok(()));
    assert_eq!(tunables::mem_sleep_current(), SuspendState::ToIdle);
    // `deep` is not listed with no platform table, so selecting it fails and
    // leaves the selection alone.
    assert_eq!(store("mem_sleep", b"deep\n"), Err(Error::Inval));
    assert_eq!(tunables::mem_sleep_current(), SuspendState::ToIdle);
    assert_eq!(store("mem_sleep", b"mem\n"), Err(Error::Inval));
}

#[test]
fn wakeup_count_reads_the_registered_count() {
    let _g = crate::suspend::test_lock();
    quiesce();
    let (before, _) = wakeup::SYSTEM.get_wakeup_count();
    wakeup::SYSTEM.source_activate();
    wakeup::SYSTEM.source_deactivate();
    let want = alloc::format!("{}\n", before + 1);
    assert_eq!(show("wakeup_count").unwrap(), want.into_bytes());
}

#[test]
fn a_blocking_wakeup_count_read_renders_after_the_source_finishes() {
    let _g = crate::suspend::test_lock();
    quiesce();
    let before = wakeup::SYSTEM.counts().registered;
    wakeup::SYSTEM.source_activate();
    let count = wakeup::SYSTEM.get_wakeup_count_with_wait(|counters| {
        counters.source_deactivate();
        sched::WaitOutcome::Ready
    });
    let want = alloc::format!("{}\n", before + 1).into_bytes();
    assert_eq!(render_wakeup_count(count), Ok(want));
}

#[test]
fn a_signal_while_a_wakeup_source_remains_active_is_eintr() {
    let _g = crate::suspend::test_lock();
    quiesce();
    wakeup::SYSTEM.source_activate();
    let count = wakeup::SYSTEM.get_wakeup_count_with_wait(
        |_| sched::WaitOutcome::Interrupted);
    assert_eq!(render_wakeup_count(count), Err(Error::Intr));
    wakeup::SYSTEM.source_deactivate();
}

#[test]
fn the_wakeup_count_write_arms_the_check_and_a_stale_count_does_not() {
    let _g = crate::suspend::test_lock();
    quiesce();
    let (count, _) = wakeup::SYSTEM.get_wakeup_count();
    let good = alloc::format!("{count}\n");
    assert_eq!(store("wakeup_count", good.as_bytes()), Ok(()));
    assert!(wakeup::SYSTEM.check_enabled());
    let stale = alloc::format!("{}\n", count.wrapping_add(7));
    assert_eq!(store("wakeup_count", stale.as_bytes()), Err(Error::Inval));
    assert!(!wakeup::SYSTEM.check_enabled(), "a stale write left the check armed");
    assert_eq!(store("wakeup_count", b"x\n"), Err(Error::Inval));
    quiesce();
}

#[test]
fn an_event_after_arming_aborts_the_suspend_that_follows() {
    let _g = crate::suspend::test_lock();
    quiesce();
    // This is the race `/sys/power/wakeup_count` exists to close: read the
    // count, write it back, then a source fires before the suspend commits.
    let (count, _) = wakeup::SYSTEM.get_wakeup_count();
    let armed = alloc::format!("{count}\n");
    assert_eq!(store("wakeup_count", armed.as_bytes()), Ok(()));
    wakeup::SYSTEM.source_activate();
    wakeup::SYSTEM.source_deactivate();
    assert!(wakeup::pm_wakeup_pending(), "the event that arrived was lost");
    quiesce();
}

#[test]
fn every_declared_attribute_answers_a_read() {
    let _g = crate::suspend::test_lock();
    quiesce();
    for a in ATTRS {
        assert!(show(a.name).is_ok(), "{} does not read", a.name);
        assert!(a.writable, "{} is declared read-only", a.name);
    }
    for name in STATS_ATTRS { assert!(show_stat(name).is_ok(), "{name} does not read"); }
    assert_eq!(show_stat("nonesuch"), Err(Error::Nodata));
}

#[test]
fn a_transition_in_progress_refuses_the_selection_writes() {
    let _g = crate::suspend::test_lock();
    quiesce();
    assert!(tunables::try_claim_transition());
    assert_eq!(store("mem_sleep", b"s2idle\n"), Err(Error::Busy));
    assert_eq!(store("wakeup_count", b"0\n"), Err(Error::Busy));
    tunables::release_transition();
}
