// Lock-free per-CPU wake list (Linux `llist`) — the invariants that make it
// safe to push from the timer ISR (`skizm.md` 3.1 #4).
//
// The list is a raw-pointer chain carrying one strong reference per node, so
// the properties worth pinning are ownership (no leak, no double-free) and the
// double-push guard that stops a task from cycling its own `wake_next`.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::common::normal;
use crate::live::ttwu::{wake_list_drain, wake_list_push};

/// Each test uses a distinct CPU index so the static per-CPU heads stay
/// independent and the suite can run in any order.
const CPU_ROUNDTRIP: u32 = 1;
const CPU_DOUBLE: u32 = 2;
const CPU_ORDER: u32 = 3;
const CPU_REPUSH: u32 = 4;

#[test]
fn push_then_drain_returns_the_task_and_releases_the_claim() {
    let t = normal(9001, 0, 1024);
    assert!(!t.on_wake_list.load(Ordering::Acquire));
    wake_list_push(CPU_ROUNDTRIP, Arc::clone(&t));
    assert!(t.on_wake_list.load(Ordering::Acquire), "push must claim the task");

    let drained = wake_list_drain(CPU_ROUNDTRIP);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].tid, 9001);
    assert!(!t.on_wake_list.load(Ordering::Acquire), "drain must release the claim");

    // The list is empty again, and draining an empty list is a no-op.
    assert!(wake_list_drain(CPU_ROUNDTRIP).is_empty());

    // Ownership: the only refs left are `t` and the drained copy. If the list
    // had leaked or double-freed a reference this count would be wrong.
    drop(drained);
    assert_eq!(Arc::strong_count(&t), 1);
}

#[test]
fn a_second_push_of_a_linked_task_is_coalesced_not_duplicated() {
    let t = normal(9002, 0, 1024);
    wake_list_push(CPU_DOUBLE, Arc::clone(&t));
    // Second waker finds it already linked. Pushing again would overwrite
    // `wake_next` with the list head — which at that moment IS this same node —
    // cycling the list and hanging the drain.
    wake_list_push(CPU_DOUBLE, Arc::clone(&t));

    let drained = wake_list_drain(CPU_DOUBLE);
    assert_eq!(drained.len(), 1, "the task must appear exactly once");
    drop(drained);
    assert_eq!(Arc::strong_count(&t), 1, "the rejected push must drop its reference");
}

#[test]
fn drain_claims_every_pushed_task() {
    let a = normal(9010, 0, 1024);
    let b = normal(9011, 0, 1024);
    let c = normal(9012, 0, 1024);
    wake_list_push(CPU_ORDER, Arc::clone(&a));
    wake_list_push(CPU_ORDER, Arc::clone(&b));
    wake_list_push(CPU_ORDER, Arc::clone(&c));

    let drained = wake_list_drain(CPU_ORDER);
    let mut tids: alloc::vec::Vec<u32> = drained.iter().map(|t| t.tid).collect();
    tids.sort_unstable();
    assert_eq!(tids, alloc::vec![9010, 9011, 9012]);
    // LIFO, as Linux's `llist_del_all` yields.
    assert_eq!(drained[0].tid, 9012, "most recent push comes out first");

    drop(drained);
    for t in [&a, &b, &c] { assert_eq!(Arc::strong_count(t), 1); }
}

#[test]
fn a_task_can_be_pushed_again_after_being_drained() {
    // `wake_list_ready` re-pushes tasks that are still switching off, so the
    // claim must be reusable immediately after a drain.
    let t = normal(9020, 0, 1024);
    wake_list_push(CPU_REPUSH, Arc::clone(&t));
    assert_eq!(wake_list_drain(CPU_REPUSH).len(), 1);
    wake_list_push(CPU_REPUSH, Arc::clone(&t));
    assert_eq!(wake_list_drain(CPU_REPUSH).len(), 1, "re-push after drain must work");
    assert_eq!(Arc::strong_count(&t), 1);
}

#[test]
fn out_of_range_cpu_is_a_no_op_and_drops_the_reference() {
    let t = normal(9030, 0, 1024);
    wake_list_push(cpu::MAX_CPUS as u32, Arc::clone(&t));
    assert!(wake_list_drain(cpu::MAX_CPUS as u32).is_empty());
    assert!(!t.on_wake_list.load(Ordering::Acquire), "no claim on a rejected push");
    assert_eq!(Arc::strong_count(&t), 1);
}
