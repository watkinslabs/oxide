// B1427 regression model for `sysv::sem`/`live::sysv_msg`'s IPC_RMID
// (and namespace-teardown) races.
//
// Both `sysv::sem`'s `IPC_RMID` and `sysv_msg::sys_msgctl(IPC_RMID)`
// used to remove the set/queue from the registry, then call `wake_all()`
// on its wait list(s) with NO lock held. Meanwhile the blocked side
// (`sys_semop`'s WouldBlock branch / `sys_msgsnd`/`sys_msgrcv`'s full/empty
// branch) checks its condition and registers on the SAME wait list while
// holding the set/queue's own data lock (`vals`/`q`). Since the removal's
// wake was never gated by that lock, it could fire into an EMPTY wait list
// (the waiter hadn't registered yet) and be lost. Worse than a generic
// lost-wakeup: IPC_RMID/reap_namespace wake exactly ONCE, at removal time —
// a park() landing even a moment after that one-shot wake, in ANY ordering,
// is never woken again, because the id is gone from the registry and no
// future commit (nor a second removal) can fire another wake. The fix adds
// a `removed: AtomicBool` set (under the data lock) alongside the wake, and
// has the waiter check it under the SAME lock before deciding to park —
// turning every ordering against removal into an immediate `-EIDRM` instead
// of a maybe-permanent hang.
//
// `crates/kernel/ipc/src/live/*` (where the real `sys_msgsnd`/`sys_msgrcv`
// live) is compiled only for `target_os = "oxide-kernel"` (see
// `crates/kernel/ipc/src/lib.rs`'s `#[cfg(target_os = "oxide-kernel")] pub
// mod live;`), so it does not exist at all in a hosted `cargo test` build —
// there is no way to drive the real functions here. Semaphores moved to
// `sysv::sem`, which DOES build hosted, but its park is a stub, so the
// interleaving below is still unreachable from the real body. This models the exact
// lock-gating shape with a `LossyWaitList` stand-in (a wake is dropped if
// nobody is registered yet, unlike `std::thread::park`/`unpark` whose token
// persists regardless of call order and would validate nothing), the same
// technique `pipe/eventfd.rs`'s B1422 test and `drv-virtio-blk`'s B1426 test
// use for the same reachability gap.

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Mirrors the FIXED `sys_semop`/`sys_msgsnd`/`sys_msgrcv` WouldBlock
    /// branch: under the data lock, check `removed` FIRST (immediate EIDRM
    /// if set), then the real condition, then register — never releasing
    /// the lock between the checks and the registration.
    fn wait_or_eidrm(condition_blocks: &AtomicBool, removed: &AtomicBool, gate: &Mutex<()>, waiters: &LossyWaitList) -> bool {
        loop {
            let g = gate.lock().unwrap();
            if removed.load(Ordering::Acquire) {
                drop(g);
                return false; // -EIDRM
            }
            if !condition_blocks.load(Ordering::Acquire) {
                drop(g);
                return true; // proceeded normally
            }
            let mine = waiters.register();
            drop(g);
            let (lock, cv) = &*mine;
            let guard = lock.lock().unwrap();
            let (_guard, res) = cv
                .wait_timeout_while(guard, Duration::from_secs(2), |woken| !*woken)
                .unwrap();
            assert!(!res.timed_out(), "waiter parked forever: lost wakeup (B1427 IPC_RMID regression)");
            // Loop back: re-check `removed` before trusting the wake meant
            // the ordinary condition changed.
        }
    }

    /// Mirrors the FIXED IPC_RMID/reap_namespace: set `removed` AND wake,
    /// both under the SAME gate the waiter holds across its checks + register.
    fn remove_and_wake_fixed(removed: &AtomicBool, gate: &Mutex<()>, waiters: &LossyWaitList) {
        let g = gate.lock().unwrap();
        removed.store(true, Ordering::Release);
        waiters.wake_all();
        drop(g);
    }

    /// Mirrors the PRE-FIX IPC_RMID/reap_namespace: set `removed` and wake
    /// with NO gate at all — free to run at any time relative to a waiter's
    /// gate hold, including strictly between its checks and its registration.
    fn remove_and_wake_buggy(removed: &AtomicBool, waiters: &LossyWaitList) {
        removed.store(true, Ordering::Release);
        waiters.wake_all();
    }

    /// Harness-sanity probe: holds `gate` across both checks, signals
    /// `checked`, waits for `proceed` (so the test can run the buggy
    /// remover in between), then registers. Deterministically reproduces
    /// the pre-fix ordering.
    fn wait_probe(
        condition_blocks: &AtomicBool, removed: &AtomicBool, gate: &Mutex<()>, waiters: &LossyWaitList,
        checked: &Barrier, proceed: &Barrier,
    ) {
        let g = gate.lock().unwrap();
        assert!(!removed.load(Ordering::Acquire), "harness sanity: must not be removed yet at check time");
        assert!(condition_blocks.load(Ordering::Acquire), "harness sanity: must still block at check time");
        checked.wait();
        proceed.wait();
        let mine = waiters.register();
        drop(g);
        let (lock, cv) = &*mine;
        let guard = lock.lock().unwrap();
        let (_guard, res) = cv
            .wait_timeout_while(guard, Duration::from_millis(200), |woken| !*woken)
            .unwrap();
        assert!(res.timed_out(), "harness sanity: the buggy ungated IPC_RMID wake was expected to lose this wakeup");
    }

    #[test]
    fn buggy_ungated_rmid_wake_can_lose_a_wakeup() {
        let condition_blocks = AtomicBool::new(true);
        let removed = AtomicBool::new(false);
        let gate = Mutex::new(());
        let waiters = LossyWaitList::default();
        let checked = Barrier::new(2);
        let proceed = Barrier::new(2);
        thread::scope(|s| {
            s.spawn(|| wait_probe(&condition_blocks, &removed, &gate, &waiters, &checked, &proceed));
            checked.wait();
            // Buggy remover: mutate + wake with no gate, runs freely even
            // though the waiter holds `gate` — lands strictly between the
            // waiter's checks and its registration.
            remove_and_wake_buggy(&removed, &waiters);
            proceed.wait();
        });
    }

    #[test]
    fn concurrent_rmid_never_leaves_waiter_parked() {
        const ITERS: usize = 4_000;
        for _ in 0..ITERS {
            let condition_blocks = AtomicBool::new(true);
            let removed = AtomicBool::new(false);
            let gate = Mutex::new(());
            let waiters = LossyWaitList::default();
            let barrier = Barrier::new(2);
            thread::scope(|s| {
                let w = s.spawn(|| {
                    barrier.wait();
                    wait_or_eidrm(&condition_blocks, &removed, &gate, &waiters)
                });
                barrier.wait();
                remove_and_wake_fixed(&removed, &gate, &waiters);
                let proceeded = w.join().expect("waiter thread must finish (no lost wakeup)");
                assert!(!proceeded, "a removed set/queue must report EIDRM, not proceed");
            });
        }
    }
}
