// B1427 regression: `QuotaInfo::wake_kind` used to call the sched wake hook
// with no lock held, while `wait_for_kind_quiesced` checks `kind_quiesced`
// and parks under `QUOTA_WAIT_LOCK`. The dquot refcount mutation
// (`Dquot::release_ref`) that flips the condition is a lock-free atomic
// decrement, so a waiter's check (sees a nonzero ref) could race a
// concurrent `release_ref` + `wake_kind`: the wake fires into an empty wait
// list (the waiter hasn't parked yet) and is lost, then the waiter parks
// forever waiting for a quota-off that already completed.
//
// `sched::live` has no runqueue under a hosted `cargo test` build, so the
// real `WaitList::park`/`schedule` are unreachable here (same gap
// `pipe/eventfd.rs`'s B1422 test and `drv-virtio-blk`'s B1426 test hit).
// This models the exact lock-gating shape (`QUOTA_WAIT_LOCK` around the
// check+park on one side, and around the wake on the other) with a
// `LossyWaitList` stand-in — a wake is dropped if nobody is registered yet,
// unlike `std::thread::park`/`unpark` whose token persists regardless of
// call order and would validate nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

type WakeSlot = Arc<(Mutex<bool>, Condvar)>;

#[derive(Default)]
struct LossyWaitList {
    slot: Mutex<Option<WakeSlot>>,
}
impl LossyWaitList {
    fn register(&self) -> WakeSlot {
        let slot = Arc::new((Mutex::new(false), Condvar::new()));
        *self.slot.lock().unwrap() = Some(slot.clone());
        slot
    }
    fn wake_all(&self) {
        if let Some(slot) = self.slot.lock().unwrap().take() {
            *slot.0.lock().unwrap() = true;
            slot.1.notify_all();
        }
    }
}

/// Mirrors `wait_for_kind_quiesced`: check + register under the SAME gate
/// `QUOTA_WAIT_LOCK` protects (this part was already correct pre-fix).
fn wait_quiesced(refs: &AtomicUsize, gate: &Mutex<()>, waiters: &LossyWaitList) {
    loop {
        let g = gate.lock().unwrap();
        if refs.load(Ordering::Acquire) == 0 {
            drop(g);
            return;
        }
        let mine = waiters.register();
        drop(g);
        let (lock, cv) = &*mine;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
            .unwrap();
        assert!(!res.timed_out(), "waiter parked forever: lost wakeup (B1427 quota regression)");
    }
}

/// Mirrors the FIXED `dqput` → `wake_kind`: the refcount mutation stays
/// lock-free (matches `Dquot::release_ref`'s atomic CAS loop), but the wake
/// call is gated by the SAME lock `wait_quiesced` holds across its check +
/// register.
fn release_and_wake_fixed(refs: &AtomicUsize, gate: &Mutex<()>, waiters: &LossyWaitList) {
    refs.fetch_sub(1, Ordering::AcqRel);
    let g = gate.lock().unwrap();
    waiters.wake_all();
    drop(g);
}

/// Mirrors the PRE-FIX `wake_kind`: mutate, then wake with NO gate at all —
/// free to run at any time relative to a waiter's gate hold, including
/// strictly between its check and its registration.
fn release_and_wake_buggy(refs: &AtomicUsize, waiters: &LossyWaitList) {
    refs.fetch_sub(1, Ordering::AcqRel);
    waiters.wake_all();
}

/// Harness-sanity probe: holds `gate` across the check, signals `checked`,
/// waits for `proceed` (so the test can run the buggy waker in between),
/// then registers. Deterministically reproduces the pre-fix ordering.
fn wait_quiesced_probe(
    refs: &AtomicUsize, gate: &Mutex<()>, waiters: &LossyWaitList, checked: &Barrier, proceed: &Barrier,
) {
    let g = gate.lock().unwrap();
    assert_ne!(refs.load(Ordering::Acquire), 0, "harness sanity: must still be busy at check time");
    checked.wait();
    proceed.wait();
    let mine = waiters.register();
    drop(g);
    let (lock, cv) = &*mine;
    let guard = lock.lock().unwrap();
    let (_guard, res) = cv
        .wait_timeout_while(guard, Duration::from_millis(200), |woken| !*woken)
        .unwrap();
    assert!(res.timed_out(), "harness sanity: the buggy ungated wake_kind was expected to lose this wakeup");
}

#[test]
fn buggy_ungated_wake_can_lose_a_wakeup() {
    let refs = AtomicUsize::new(1);
    let gate = Mutex::new(());
    let waiters = LossyWaitList::default();
    let checked = Barrier::new(2);
    let proceed = Barrier::new(2);
    thread::scope(|s| {
        s.spawn(|| wait_quiesced_probe(&refs, &gate, &waiters, &checked, &proceed));
        checked.wait();
        // Buggy waker: mutate + wake with no gate, runs freely even though
        // the waiter holds `gate` — lands strictly between the waiter's
        // check and its registration.
        release_and_wake_buggy(&refs, &waiters);
        proceed.wait();
    });
}

#[test]
fn concurrent_release_never_leaves_waiter_parked() {
    const ITERS: usize = 4_000;
    for _ in 0..ITERS {
        let refs = AtomicUsize::new(1);
        let gate = Mutex::new(());
        let waiters = LossyWaitList::default();
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let w = s.spawn(|| { barrier.wait(); wait_quiesced(&refs, &gate, &waiters); });
            barrier.wait();
            release_and_wake_fixed(&refs, &gate, &waiters);
            w.join().expect("waiter thread must finish (no lost wakeup)");
        });
        assert_eq!(refs.load(Ordering::Acquire), 0);
    }
}
