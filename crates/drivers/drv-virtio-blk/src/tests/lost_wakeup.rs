// B1426 regression: virtio-blk's `wait_for_completion`/`acquire_turn` used to
// poll a lock-free condition, THEN register on `BLK_COMPL`/`BLK_TURN`
// (`park_blk`). Under SMP the completion IRQ can land on a DIFFERENT cpu: the
// completion softirq can observe the condition and `wake_all()` an EMPTY wait list in
// the gap between this cpu's last poll and its park() call. With exactly one
// outstanding turn/completion, no later wake ever arrives — a permanent hang
// (`fstat` parked forever under `SMP=4`, reproducing every time; never under
// `SMP=1`).
//
// `sched::live` has no runqueue under a hosted `cargo test` build, so
// `WaitList::park`/`cancel_current_park`/`schedule` (what `park_blk_checked`
// actually calls) are unreachable here — same gap `pipe/eventfd.rs`'s B1422
// test hit. This drives real OS threads against a `LossyWaitList` stand-in as
// lossy as the real one (a wake is dropped if nobody is registered yet —
// unlike `std::thread::park`/`unpark`, whose token persists regardless of
// call order and would validate nothing about the fix) exercising the SAME
// register-then-recheck shape `park_blk_checked` uses.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// One waiter's wake handle: the boolean carries the notification past a
/// `wake()` that runs before the corresponding `cv.wait()` starts.
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
    /// Mirrors `WaitList::cancel_current_park`: drop our own registration
    /// without waiting for a wake that will never come now that `done` is
    /// already true.
    fn cancel(&self, mine: &WakeSlot) {
        let mut g = self.slot.lock().unwrap();
        if let Some(cur) = g.as_ref() {
            if Arc::ptr_eq(cur, mine) { *g = None; }
        }
    }
    fn wake(&self) {
        if let Some(slot) = self.slot.lock().unwrap().take() {
            *slot.0.lock().unwrap() = true;
            slot.1.notify_all();
        }
    }
}

/// Mirrors the FIXED `park_blk_checked`: register on the wait list FIRST,
/// THEN evaluate `done`. A completer landing after registration always finds
/// us on the list (so its wake reaches us); a completer landing before we
/// even registered already made `done` true, so our post-register recheck
/// sees it and we cancel without sleeping.
fn waiter_once(done: &AtomicBool, waiters: &LossyWaitList) {
    loop {
        if done.load(Ordering::Acquire) { return; }
        let mine = waiters.register();
        if done.load(Ordering::Acquire) {
            waiters.cancel(&mine);
            return;
        }
        let (lock, cv) = &*mine;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
            .unwrap();
        assert!(!res.timed_out(), "waiter parked forever: lost wakeup (B1426 regression)");
    }
}

/// Mirrors the completion softirq (`run_completion_bottom_half`): mutate the
/// condition, THEN wake — unconditionally, with no lock shared with the
/// waiter's poll (matches the real driver's lock-free used-ring read).
fn completer(done: &AtomicBool, waiters: &LossyWaitList) {
    done.store(true, Ordering::Release);
    waiters.wake();
}

/// The OLD buggy shape (`park_blk`): poll, THEN register, THEN
/// UNCONDITIONALLY sleep — no recheck between registering and scheduling.
/// Two barriers make the poll → completer-wake → register ordering
/// deterministic (not a race that might not reproduce): the completer's
/// mutate+wake is forced to run strictly between the waiter's poll and its
/// registration, so it always lands on an empty list. Included only to prove
/// the `LossyWaitList` stand-in actually reproduces the B1426 class of bug —
/// so `concurrent_completion_never_leaves_waiter_parked` passing against the
/// FIXED ordering means something, not nothing.
fn waiter_once_buggy_check_then_park(
    done: &AtomicBool, waiters: &LossyWaitList, poll_done: &Barrier, wake_done: &Barrier,
) {
    if done.load(Ordering::Acquire) { return; }
    poll_done.wait();
    wake_done.wait();
    // Register AFTER the completer's wake already ran and found the list
    // empty — mirrors `park_blk`, which had no post-registration recheck.
    let mine = waiters.register();
    let (lock, cv) = &*mine;
    let guard = lock.lock().unwrap();
    let (_guard, res) = cv
        .wait_timeout_while(guard, Duration::from_millis(200), |woken| !*woken)
        .unwrap();
    assert!(res.timed_out(), "harness sanity: the buggy shape was expected to lose this wakeup");
}

#[test]
fn buggy_check_then_park_can_lose_a_wakeup() {
    // Harness sanity check (not a regression test on its own): proves the
    // `LossyWaitList` stand-in actually reproduces the B1426 class of bug for
    // the OLD ordering, so `concurrent_completion_never_leaves_waiter_parked`
    // failing to catch the FIXED ordering would mean something, not nothing.
    let done = AtomicBool::new(false);
    let waiters = LossyWaitList::default();
    let poll_done = Barrier::new(2);
    let wake_done = Barrier::new(2);
    thread::scope(|s| {
        s.spawn(|| waiter_once_buggy_check_then_park(&done, &waiters, &poll_done, &wake_done));
        poll_done.wait();
        // Runs the mutate+wake strictly between the waiter's poll and its
        // registration: the wake lands on an empty list and is dropped.
        completer(&done, &waiters);
        wake_done.wait();
    });
}

#[test]
fn concurrent_completion_never_leaves_waiter_parked() {
    const ITERS: usize = 4_000;
    for _ in 0..ITERS {
        let done = AtomicBool::new(false);
        let waiters = LossyWaitList::default();
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let waiter = s.spawn(|| { barrier.wait(); waiter_once(&done, &waiters); });
            barrier.wait();
            completer(&done, &waiters);
            waiter.join().expect("waiter thread must finish");
        });
        assert!(done.load(Ordering::Acquire));
    }
}

/// The turn-acquisition side (`acquire_turn`/`release_turn`) is the same
/// register-then-recheck shape guarding a different boolean (`busy`); model it
/// directly so a regression in either call site is caught.
#[test]
fn concurrent_turn_release_never_leaves_acquirer_parked() {
    const ITERS: usize = 4_000;
    for _ in 0..ITERS {
        let busy = AtomicBool::new(true);
        let waiters = LossyWaitList::default();
        let barrier = Barrier::new(2);
        thread::scope(|s| {
            let acquirer = s.spawn(|| {
                barrier.wait();
                // `done` here means "turn free", i.e. NOT busy.
                loop {
                    if !busy.load(Ordering::Acquire) { return; }
                    let mine = waiters.register();
                    if !busy.load(Ordering::Acquire) { waiters.cancel(&mine); return; }
                    let (lock, cv) = &*mine;
                    let guard = lock.lock().unwrap();
                    let (_guard, res) = cv
                        .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
                        .unwrap();
                    assert!(!res.timed_out(), "acquirer parked forever: lost wakeup (B1426 regression)");
                }
            });
            barrier.wait();
            busy.store(false, Ordering::Release);
            waiters.wake();
            acquirer.join().expect("acquirer thread must finish");
        });
    }
}

#[test]
fn kernel_wait_path_parks_without_driver_owned_polling() {
    let wait = include_str!("../modern/wait.rs");
    let state = include_str!("../modern/state.rs");
    assert!(!wait.contains("IO_SPIN_BUDGET"));
    assert!(!state.contains("IO_SPIN_BUDGET"));
    assert!(!state.contains("IO_IRQ_POLL_BUDGET"));
    assert!(!state.contains("irq_save_enable"));
    assert!(!wait.contains("for _ in 0.."));
    assert!(!wait.contains("while spun <"));
    assert!(wait.contains("park_blk_checked(&BLK_COMPL, deadline"));
    assert!(wait.contains("park_blk_checked(&BLK_TURN, 0"));
}

#[test]
fn softirq_shared_queue_state_is_bottom_half_safe() {
    let sources = [
        include_str!("../modern/state.rs"),
        include_str!("../modern/init.rs"),
        include_str!("../modern/engine.rs"),
        include_str!("../modern/wait.rs"),
    ];
    let joined = sources.join("\n");
    assert!(!joined.contains("inflight.lock()"),
        "plain queue-state lock can deadlock when block softirq interrupts it");
    assert!(!joined.contains("DEVICES.lock()"),
        "plain device registry lock can deadlock against block softirq");
    assert!(joined.contains("inflight.lock_bh::<sched::bh::SchedBh>()"));
    assert!(joined.contains("DEVICES.lock_bh::<sched::bh::SchedBh>()"));
}

/// A request queued while the synchronous owner is active has no hardware
/// completion that could kick dispatch. Releasing that owner is therefore the
/// event that must start the deferred request; merely waking another owner
/// leaves `deferred` nonempty forever and makes every later sync owner re-park.
#[test]
fn synchronous_turn_release_dispatches_deferred_before_waking_next_owner() {
    let source = include_str!("../modern/wait.rs");
    let release = source.split("pub(super) fn release_turn").nth(1)
        .expect("release_turn implementation");
    let free = release.find("busy = false").expect("turn release");
    let dispatch = release.find("self.start_deferred_requests()")
        .expect("release must kick queued async I/O");
    let wake = release.find("BLK_TURN.wake_one()")
        .expect("release must wake a synchronous waiter");
    assert!(free < dispatch && dispatch < wake,
        "free turn, dispatch already-queued I/O, then wake the next owner");
}
