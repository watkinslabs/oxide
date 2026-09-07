// The scheduler's utilisation hook must not wait on anything process context
// holds.
//
// The hook runs in hard-interrupt context on the wakeup path. Every lock it
// takes that process context takes with interrupts enabled is a wedge waiting
// for the two to meet: on a single-CPU machine the handler spins for ever, the
// console stops mid-line, and nothing else ever runs. That is not a theory —
// it was measured on an x86 guest whose transmit queue was empty, whose IER
// had transmit-empty disarmed, and whose only CPU was spinning inside the
// interrupt dispatch on the policy registry, at the same instruction across
// samples ten seconds apart.
//
// These tests hold the registry and driver slots from this thread and require
// the hook, on another, to finish anyway. Take the lock-free reads back out and
// they hang instead of passing, which is the point.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::governor::input::CAPACITY_SCALE;
use crate::{CpufreqOps, FreqEntry, FreqTable, Policy};

/// How long the hook is allowed to take before it counts as waiting on a lock.
/// Generous: the work itself is a resolution over a two-entry table.
const HOOK_DEADLINE: Duration = Duration::from_secs(5);

static FAST: AtomicUsize = AtomicUsize::new(0);

struct Fast;
impl CpufreqOps for Fast {
    fn target_index(&self, _policy: &Policy, _index: usize) -> vfs::KResult<()> { Ok(()) }
    fn fast_switch_possible(&self, _policy: &Policy) -> bool { true }
    fn fast_switch(&self, _policy: &Policy, _index: usize) -> vfs::KResult<()> {
        FAST.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn schedutil_policy() -> Arc<Policy> {
    let table = FreqTable::new(alloc::vec![FreqEntry::new(1_000_000, 0), FreqEntry::new(2_000_000, 1)])
        .expect("table");
    let policy = Policy::new(alloc::vec![0], table, 1_000, 1_000_000, "schedutil").expect("policy");
    crate::register_policy(policy).expect("register")
}

/// Run `f` on another thread and fail rather than hang if it does not return.
fn completes(f: impl FnOnce() + Send + 'static) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || { f(); let _ = tx.send(()); });
    rx.recv_timeout(HOOK_DEADLINE).is_ok()
}

#[test]
fn the_hook_finishes_while_process_context_holds_the_policy_registry() {
    let _guard = crate::driver::test_guard();
    crate::register_driver("fast", Arc::new(Fast)).expect("driver");
    let _policy = schedutil_policy();
    FAST.store(0, Ordering::Relaxed);

    let held = crate::driver::lock_registry_for_tests();
    let done = completes(|| {
        crate::util::update_util(0, CAPACITY_SCALE, CAPACITY_SCALE, false, 1_000_000_000, 4_000_000);
    });
    drop(held);
    assert!(done, "the scheduler hook waited on the policy registry");
    assert_eq!(FAST.load(Ordering::Relaxed), 1, "the hook did no work");
}

#[test]
fn the_hook_finishes_while_process_context_holds_the_driver_slot() {
    let _guard = crate::driver::test_guard();
    crate::register_driver("fast", Arc::new(Fast)).expect("driver");
    let _policy = schedutil_policy();
    FAST.store(0, Ordering::Relaxed);

    let held = crate::driver::lock_driver_for_tests();
    let done = completes(|| {
        crate::util::update_util(0, CAPACITY_SCALE, CAPACITY_SCALE, false, 2_000_000_000, 4_000_000);
    });
    drop(held);
    assert!(done, "the scheduler hook waited on the driver slot");
    assert_eq!(FAST.load(Ordering::Relaxed), 1, "the hook did no work");
}

#[test]
fn a_cpu_with_no_published_policy_does_nothing_and_reads_no_registry() {
    let _guard = crate::driver::test_guard();
    crate::register_driver("fast", Arc::new(Fast)).expect("driver");
    let _policy = schedutil_policy();
    FAST.store(0, Ordering::Relaxed);

    let held = crate::driver::lock_registry_for_tests();
    let done = completes(|| {
        crate::util::update_util(1, CAPACITY_SCALE, CAPACITY_SCALE, false, 3_000_000_000, 4_000_000);
    });
    drop(held);
    assert!(done, "an ungoverned CPU still waited on the policy registry");
    assert_eq!(FAST.load(Ordering::Relaxed), 0);
}
