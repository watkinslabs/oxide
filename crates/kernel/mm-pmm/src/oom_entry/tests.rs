//! Hosted tests for the allocation-context out-of-memory slowpath.
//
// Ungated module, so these genuinely compile and run.

use super::*;
use std::cell::Cell;

#[test]
fn atomic_context_never_enters_the_slowpath() {
    assert!(!slowpath_allowed(true));
    assert!(slowpath_allowed(false));
    let reclaimed = Cell::new(0u32);
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(0, slowpath_allowed(true),
        || Some(7u8),
        || { reclaimed.set(reclaimed.get() + 1); true },
        || { killed.set(killed.get() + 1); OomOutcome::Progress });
    assert_eq!(out, None);
    assert_eq!(reclaimed.get(), 0, "an atomic caller must not reclaim");
    assert_eq!(killed.get(), 0, "an atomic caller must not select a victim");
}

#[test]
fn costly_order_reclaims_but_never_kills() {
    assert!(may_invoke_oom(PAGE_ALLOC_COSTLY_ORDER));
    assert!(!may_invoke_oom(PAGE_ALLOC_COSTLY_ORDER + 1));
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(PAGE_ALLOC_COSTLY_ORDER + 1, true,
        || None, || false, || { killed.set(killed.get() + 1); OomOutcome::Progress });
    assert_eq!(out, None);
    assert_eq!(killed.get(), 0, "a kill frees pages, not contiguity");
}

#[test]
fn reclaim_precedes_any_kill() {
    let events = Cell::new(0u32);
    let first_kill_at = Cell::new(u32::MAX);
    let out: Option<u8> = run_slowpath(0, true,
        || None,
        || { events.set(events.get() + 1); false },
        || {
            if first_kill_at.get() == u32::MAX { first_kill_at.set(events.get()); }
            OomOutcome::NoKillable
        });
    assert_eq!(out, None);
    assert!(first_kill_at.get() > MAX_RECLAIM_RETRIES,
            "killed after {} reclaim passes, want more than {}", first_kill_at.get(), MAX_RECLAIM_RETRIES);
}

#[test]
fn progressing_reclaim_never_reaches_the_killer() {
    let passes = Cell::new(0u32);
    let killed = Cell::new(0u32);
    // Reclaim keeps freeing, and the allocation succeeds well after the retry
    // bound would have expired had progress not reset it.
    let out: Option<u8> = run_slowpath(0, true,
        || if passes.get() >= MAX_RECLAIM_RETRIES * 3 { Some(1u8) } else { None },
        || { passes.set(passes.get() + 1); true },
        || { killed.set(killed.get() + 1); OomOutcome::Progress });
    assert_eq!(out, Some(1u8));
    assert_eq!(killed.get(), 0, "progressing reclaim must not turn a shortage into a kill");
}

#[test]
fn costly_order_progress_still_counts_against_the_retry_bound() {
    let mut state = RetryState::default();
    state.note_reclaim(true, PAGE_ALLOC_COSTLY_ORDER);
    assert_eq!(state.no_progress_loops, 0);
    state.note_reclaim(true, PAGE_ALLOC_COSTLY_ORDER + 1);
    assert_eq!(state.no_progress_loops, 1, "freed pages do not make a costly order available");
}

#[test]
fn a_kill_is_followed_by_a_retry_not_a_failure() {
    let mut state = RetryState { no_progress_loops: MAX_RECLAIM_RETRIES + 1, oom_attempts: 0 };
    assert_eq!(after_oom(&mut state, OomOutcome::Progress), Step::Retry);
    assert_eq!(state.no_progress_loops, 0, "a kill restarts the reclaim budget");
    assert_eq!(state.oom_attempts, 1);
}

#[test]
fn allocation_succeeds_on_the_memory_a_victim_released() {
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(0, true,
        || if killed.get() > 0 { Some(9u8) } else { None },
        || false,
        || { killed.set(killed.get() + 1); OomOutcome::Progress });
    assert_eq!(out, Some(9u8));
    assert_eq!(killed.get(), 1, "one victim per shortage, not a killing spree");
}

#[test]
fn nothing_killable_fails_the_allocation_at_once() {
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(0, true,
        || None, || false,
        || { killed.set(killed.get() + 1); OomOutcome::NoKillable });
    assert_eq!(out, None);
    assert_eq!(killed.get(), 1, "an unkillable system is not retried");
}

#[test]
fn contended_selector_retries_until_the_selector_reports_no_killable() {
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(0, true,
        || None, || false,
        || {
            killed.set(killed.get() + 1);
            if killed.get() > 32 { OomOutcome::NoKillable } else { OomOutcome::Contended }
        });
    assert_eq!(out, None);
    assert_eq!(killed.get(), 33, "selector ownership is retried until it reports no victim");
}

#[test]
fn progressing_kills_are_retried_until_no_killable() {
    let killed = Cell::new(0u32);
    let out: Option<u8> = run_slowpath(0, true,
        || None, || false,
        || {
            killed.set(killed.get() + 1);
            if killed.get() > 32 { OomOutcome::NoKillable } else { OomOutcome::Progress }
        });
    assert_eq!(out, None);
    assert_eq!(killed.get(), 33);
}
