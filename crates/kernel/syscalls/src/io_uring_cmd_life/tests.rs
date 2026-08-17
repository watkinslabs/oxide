use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

static DROPPED: AtomicUsize = AtomicUsize::new(0);

struct Cmd { claims: CmdClaims }
impl CmdLifetime for Cmd { fn claims(&self) -> &CmdClaims { &self.claims } }
impl Drop for Cmd { fn drop(&mut self) { DROPPED.fetch_add(1, Ordering::SeqCst); } }

fn fresh() -> (*const Cmd, usize) {
    let base = DROPPED.load(Ordering::SeqCst);
    (Arc::into_raw(Arc::new(Cmd { claims: CmdClaims::new() })), base)
}

#[test]
fn arming_a_handoff_retains_a_reference_the_worker_runs_under() {
    let (raw, _) = fresh();
    // SAFETY: raw is this test's live command; nothing has released it.
    let handed = unsafe { arm_handoff(raw, 0x1234) }.expect("first arm wins");
    assert_eq!(handed, raw, "the hand-off reference names the same command");
    // SAFETY: raw is still live and this borrow releases nothing.
    let owner = unsafe { borrow(raw) };
    assert_eq!(Arc::strong_count(&owner), 2, "driver reference plus hand-off reference");
    // SAFETY: the hand-off reference created above, consumed exactly once.
    let (worker, cb) = unsafe { take_handoff(handed) }.expect("armed callback");
    assert_eq!(cb, 0x1234);
    assert_eq!(Arc::strong_count(&worker), 2);
    drop(worker);
    // SAFETY: raw's driver reference is still outstanding.
    drop(unsafe { Arc::from_raw(raw) });
}

#[test]
fn a_completion_during_a_handoff_does_not_free_under_the_worker() {
    let (raw, base) = fresh();
    // SAFETY: raw is this test's live command.
    let handed = unsafe { arm_handoff(raw, 0x99) }.expect("arm");
    // The driver completes on another CPU while the work is still queued.
    // SAFETY: raw is live; the driver reference has not been released.
    let terminal = unsafe { claim_terminal(raw) }.expect("first completion wins");
    drop(terminal);
    assert_eq!(DROPPED.load(Ordering::SeqCst), base, "storage outlives the completion while a hand-off is outstanding");
    // SAFETY: the hand-off reference, consumed once, still valid by the assert above.
    let (worker, cb) = unsafe { take_handoff(handed) }.expect("armed callback survives the completion");
    assert_eq!(cb, 0x99);
    drop(worker);
    assert_eq!(DROPPED.load(Ordering::SeqCst), base + 1, "the last reference frees exactly once");
}

#[test]
fn only_one_caller_wins_the_terminal_completion() {
    let (raw, base) = fresh();
    // SAFETY: raw is live for both calls; the winner's Arc is held across the second.
    let first = unsafe { claim_terminal(raw) }.expect("first wins");
    // SAFETY: `first` keeps the command alive for this losing claim.
    assert!(unsafe { claim_terminal::<Cmd>(raw) }.is_none(), "a second completion claims nothing");
    assert_eq!(Arc::strong_count(&first), 1, "a losing claim consumes no reference");
    drop(first);
    assert_eq!(DROPPED.load(Ordering::SeqCst), base + 1);
}

#[test]
fn a_second_handoff_waits_for_the_armed_callback_to_be_taken() {
    let (raw, base) = fresh();
    // SAFETY: raw is this test's live command throughout.
    let handed = unsafe { arm_handoff(raw, 7) }.expect("arm");
    // SAFETY: as above.
    assert!(unsafe { arm_handoff::<Cmd>(raw, 8) }.is_none(), "a slot already armed takes no second reference");
    // SAFETY: as above.
    let owner = unsafe { borrow(raw) };
    assert_eq!(Arc::strong_count(&owner), 2, "the refused arm retained nothing");
    // SAFETY: the one hand-off reference.
    let (worker, cb) = unsafe { take_handoff(handed) }.expect("armed");
    assert_eq!(cb, 7);
    drop(worker);
    // SAFETY: as above.
    let again = unsafe { arm_handoff(raw, 8) }.expect("the taken slot re-arms");
    // SAFETY: the second hand-off reference.
    let (worker, cb) = unsafe { take_handoff(again) }.expect("armed");
    assert_eq!(cb, 8);
    drop(worker);
    // SAFETY: the driver reference, released last.
    drop(unsafe { Arc::from_raw(raw) });
    assert_eq!(DROPPED.load(Ordering::SeqCst), base + 1);
}

#[test]
fn an_unarmed_handoff_pointer_releases_its_reference_and_runs_nothing() {
    let (raw, base) = fresh();
    // SAFETY: raw is live.
    let handed = unsafe { arm_handoff(raw, 5) }.expect("arm");
    // SAFETY: the hand-off reference; the first take consumes the callback.
    let (worker, _) = unsafe { take_handoff(handed) }.expect("armed");
    drop(worker);
    // SAFETY: raw is live; arming again to obtain a second hand-off reference.
    let handed = unsafe { arm_handoff(raw, 5) }.expect("re-arm");
    // A completion took the callback slot before the worker ran.
    // SAFETY: raw is live, held by the driver reference.
    let owner = unsafe { borrow(raw) };
    assert_ne!(owner.claims().take(), 0);
    // SAFETY: the outstanding hand-off reference, consumed once.
    assert!(unsafe { take_handoff::<Cmd>(handed) }.is_none(), "no callback to run");
    assert_eq!(Arc::strong_count(&owner), 1, "the unarmed hand-off released its reference");
    // SAFETY: the driver reference.
    drop(unsafe { Arc::from_raw(raw) });
    assert_eq!(DROPPED.load(Ordering::SeqCst), base + 1);
}

#[test]
fn racing_completions_elect_exactly_one_winner() {
    for _ in 0..512 {
        let cmd = Arc::new(Cmd { claims: CmdClaims::new() });
        let raw = Arc::into_raw(Arc::clone(&cmd)) as usize;
        let winners: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(std::sync::Barrier::new(8));
        let hands: alloc::vec::Vec<_> = (0..8).map(|_| {
            let (winners, gate) = (Arc::clone(&winners), Arc::clone(&gate));
            std::thread::spawn(move || {
                gate.wait();
                // SAFETY: the test's own Arc keeps the command alive for every racing claim.
                if let Some(w) = unsafe { claim_terminal(raw as *const Cmd) } {
                    winners.fetch_add(1, Ordering::SeqCst);
                    core::mem::forget(w);
                }
            })
        }).collect();
        for h in hands { h.join().unwrap(); }
        assert_eq!(winners.load(Ordering::SeqCst), 1, "exactly one terminal completion");
        // SAFETY: the winner leaked the driver reference; reclaim it here.
        drop(unsafe { Arc::from_raw(raw as *const Cmd) });
    }
}

#[test]
fn racing_arms_elect_exactly_one_worker_per_callback() {
    for _ in 0..512 {
        let cmd = Arc::new(Cmd { claims: CmdClaims::new() });
        let raw = Arc::into_raw(Arc::clone(&cmd)) as usize;
        let armed: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let handed: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(std::sync::Barrier::new(8));
        let hands: alloc::vec::Vec<_> = (0..8).map(|i| {
            let (armed, handed, gate) = (Arc::clone(&armed), Arc::clone(&handed), Arc::clone(&gate));
            std::thread::spawn(move || {
                gate.wait();
                // SAFETY: the test's own Arc keeps the command alive for every racing arm.
                if let Some(h) = unsafe { arm_handoff(raw as *const Cmd, i + 1) } {
                    armed.fetch_add(1, Ordering::SeqCst);
                    handed.store(h as usize, Ordering::SeqCst);
                }
            })
        }).collect();
        for h in hands { h.join().unwrap(); }
        assert_eq!(armed.load(Ordering::SeqCst), 1, "one armed callback per slot");
        assert_eq!(Arc::strong_count(&cmd), 3, "test, driver and one hand-off reference");
        // SAFETY: the single hand-off reference the winning arm took.
        let (worker, cb) = unsafe { take_handoff(handed.load(Ordering::SeqCst) as *const Cmd) }.expect("armed");
        assert!((1..=8).contains(&cb));
        drop(worker);
        // SAFETY: reclaim the reference handed out at the top of the iteration.
        drop(unsafe { Arc::from_raw(raw as *const Cmd) });
    }
}
