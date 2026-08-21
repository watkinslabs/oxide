// Hosted tests for the cross-CPU call protocol.
//
// These drive the REAL `CallQueues` — the same object the arch driver uses —
// with the arch parts (IPI send, handler bodies) replaced by recording
// closures. Everything asserted here is a property the arch driver depends
// on and cannot check for itself: entries run in push order, an IPI is sent
// exactly when the reference sends one, a slot is released only after its
// handler has RUN, and a sender's completion test cannot pass before that.

extern crate std;
use std::vec::Vec;
use std::cell::RefCell;

use super::mask::*;
use super::queue::{CallQueues, SlotState};

fn mask(word: u64) -> crate::CpuMask { crate::CpuMask::from_words(&[word]) }

// ---------------------------------------------------------------- targets

#[test]
fn targets_exclude_the_caller() {
    // Every CPU requested, all online, caller is 2.
    assert_eq!(targets_for(mask(0b1111), mask(0b1111), 2), mask(0b1011));
}

#[test]
fn targets_exclude_cpus_that_are_not_online() {
    // The mm names CPUs 0..3; only 0 and 1 have finished bring-up.
    assert_eq!(targets_for(mask(0b1111), mask(0b0011), 0), mask(0b0010));
}

#[test]
fn targets_exclude_cpus_outside_the_requested_mask() {
    // Four CPUs online but the mm has only ever run on 0 and 3.
    assert_eq!(targets_for(mask(0b1001), mask(0b1111), 0), mask(0b1000));
}

#[test]
fn an_empty_request_targets_nobody() {
    assert_eq!(targets_for(mask(0), mask(0b1111), 0), mask(0));
}

#[test]
fn a_caller_alone_in_the_mask_targets_nobody() {
    assert_eq!(targets_for(mask(0b0100), mask(0b1111), 2), mask(0));
}

#[test]
fn an_out_of_range_caller_id_removes_nothing_and_panics_nothing() {
    assert_eq!(targets_for(mask(0b1111), mask(0b1111), 99), mask(0b1111));
}

#[test]
fn drop_unreachable_clears_only_that_cpu() {
    assert_eq!(drop_unreachable(mask(0b1011), 1), mask(0b1001));
    assert_eq!(drop_unreachable(mask(0b1011), 2), mask(0b1011));
    assert_eq!(drop_unreachable(mask(0b1011), 64), mask(0b1011));
}

#[test]
fn escalation_falls_back_to_spins_while_the_clock_reads_zero() {
    assert!(!escalation_due(0, 500, 10, 100));
    assert!(escalation_due(0, 500, 100, 100));
    assert!(escalation_due(600, 500, 0, u64::MAX));
}

#[test]
fn escalation_gap_grows_and_cannot_wrap() {
    assert_eq!(escalation_gap(100, 0), 100);
    assert_eq!(escalation_gap(100, 2), 300);
    assert_eq!(escalation_gap(u64::MAX, 5), u64::MAX);
}

// ------------------------------------------------------------------ queue

const A: usize = 1;
const B: usize = 2;
const T: usize = 0;

fn q() -> CallQueues { CallQueues::new() }

#[test]
fn a_fresh_queue_has_every_slot_idle_and_drains_nothing() {
    let q = q();
    assert_eq!(q.state(A, T), SlotState::Idle);
    let mut ran = 0;
    q.drain(T, |_, _| ran += 1);
    assert_eq!(ran, 0);
}

#[test]
fn the_first_push_asks_for_an_ipi_and_later_ones_do_not() {
    let q = q();
    q.lock_slot(A, T, || {});
    assert!(q.push(A, T, 7, 70), "first push onto an empty list must request the IPI");
    q.lock_slot(B, T, || {});
    assert!(!q.push(B, T, 8, 80), "a target with work queued needs no second IPI");
}

#[test]
fn an_ipi_is_requested_again_once_the_queue_has_been_drained() {
    let q = q();
    q.lock_slot(A, T, || {});
    assert!(q.push(A, T, 7, 70));
    q.drain(T, |_, _| {});
    q.lock_slot(A, T, || {});
    assert!(q.push(A, T, 9, 90), "the list is empty again, so the IPI is needed again");
}

#[test]
fn entries_run_in_push_order_not_reverse() {
    // The list is built by prepending, so without the reversal in `drain`
    // two calls from different senders would run newest-first.
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    q.lock_slot(B, T, || {});
    q.push(B, T, 2, 22);
    let seen = RefCell::new(Vec::new());
    q.drain(T, |k, a| seen.borrow_mut().push((k, a)));
    assert_eq!(&seen.borrow()[..], &[(1u32, 11u64), (2, 22)]);
}

#[test]
fn a_slot_stays_locked_until_its_handler_has_run() {
    // The free-after-converge ordering: the sender must not observe
    // completion from inside the handler.
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    assert!(!q.is_complete(A, T), "locked before the drain");
    let inside = RefCell::new(None);
    q.drain(T, |_, _| { *inside.borrow_mut() = Some(q.is_complete(A, T)); });
    assert_eq!(*inside.borrow(), Some(false), "slot released BEFORE the handler ran");
    assert!(q.is_complete(A, T), "slot must be released once the handler returned");
}

#[test]
fn every_drained_slot_is_released_not_just_the_last() {
    let q = q();
    for s in [A, B, 3] {
        q.lock_slot(s, T, || {});
        q.push(s, T, 1, s as u64);
    }
    q.drain(T, |_, _| {});
    for s in [A, B, 3] { assert!(q.is_complete(s, T), "sender {} left locked", s); }
}

#[test]
fn a_sender_reusing_its_slot_waits_for_the_previous_call_to_complete() {
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    // Re-locking must spin; drain from inside the relax closure is exactly
    // what the arch driver's spin does.
    let spins = RefCell::new(0);
    q.lock_slot(A, T, || {
        *spins.borrow_mut() += 1;
        q.drain(T, |_, _| {});
    });
    assert!(*spins.borrow() >= 1, "re-lock did not wait for the outstanding call");
    assert_eq!(q.state(A, T), SlotState::Locked);
}

#[test]
fn two_senders_hold_independent_slots_for_one_target() {
    // The property that replaced the single global in-flight slot: B is not
    // blocked by A's outstanding call to the same target.
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    let spins = RefCell::new(0);
    q.lock_slot(B, T, || *spins.borrow_mut() += 1);
    assert_eq!(*spins.borrow(), 0, "B blocked on A's slot — the slots are not independent");
}

#[test]
fn one_sender_can_target_several_cpus_at_once() {
    let q = q();
    for t in [0usize, 2, 3] {
        q.lock_slot(A, t, || {});
        assert!(q.push(A, t, 5, t as u64));
    }
    for t in [0usize, 2, 3] { assert!(!q.is_complete(A, t)); }
    for t in [0usize, 2, 3] {
        let seen = RefCell::new(Vec::new());
        q.drain(t, |k, a| seen.borrow_mut().push((k, a)));
        assert_eq!(&seen.borrow()[..], &[(5u32, t as u64)]);
    }
    for t in [0usize, 2, 3] { assert!(q.is_complete(A, t)); }
}

#[test]
fn a_handler_that_re_enters_drain_does_not_rerun_the_detached_entries() {
    // The spin-relax hook calls `drain` from inside a handler's own spin.
    // The outer drain detached the list first, so the inner call must find
    // nothing rather than run the same entry twice.
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    let outer = RefCell::new(0);
    let inner = RefCell::new(0);
    q.drain(T, |_, _| {
        *outer.borrow_mut() += 1;
        q.drain(T, |_, _| *inner.borrow_mut() += 1);
    });
    assert_eq!(*outer.borrow(), 1);
    assert_eq!(*inner.borrow(), 0, "re-entrant drain re-ran a detached entry");
}

#[test]
fn a_push_made_during_a_drain_is_not_lost() {
    // A sender that queues while the target is mid-drain gets an IPI request
    // (the list was emptied by the swap), so its entry runs in the next drain.
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 1, 11);
    let need_ipi = RefCell::new(None);
    q.drain(T, |_, _| {
        q.lock_slot(B, T, || {});
        *need_ipi.borrow_mut() = Some(q.push(B, T, 2, 22));
    });
    assert_eq!(*need_ipi.borrow(), Some(true), "late push must request its own IPI");
    let seen = RefCell::new(Vec::new());
    q.drain(T, |k, a| seen.borrow_mut().push((k, a)));
    assert_eq!(&seen.borrow()[..], &[(2u32, 22u64)]);
}

#[test]
fn abandoning_an_undelivered_slot_frees_the_sender() {
    let q = q();
    q.lock_slot(A, T, || {});
    assert!(!q.is_complete(A, T));
    q.abandon_unpushed(A, T);
    assert!(q.is_complete(A, T));
}

#[test]
fn a_terminal_handler_can_publish_completion_before_it_stops() {
    let q = q();
    q.lock_slot(A, T, || {});
    q.push(A, T, 9, A as u64);
    q.drain(T, |_, sender| {
        q.complete_terminal(sender as usize, T);
        assert!(q.is_complete(A, T), "CPU-down sender must be released before target play-dead");
    });
    assert!(q.is_complete(A, T));
}

#[test]
fn out_of_range_cpu_ids_clamp_instead_of_indexing_out_of_bounds() {
    let q = q();
    q.lock_slot(999, 999, || {});
    q.push(999, 999, 1, 1);
    q.drain(999, |_, _| {});
    assert!(q.is_complete(999, 999));
}
