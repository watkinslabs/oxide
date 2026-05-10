// Hosted tests for SignalSet + SignalState per `24§2` / `24§4`.

use super::signal::*;

fn info(sig: Signal) -> SigInfo {
    SigInfo { signo: sig.as_u8(), code: 0, pid: 1, uid: 0, value: 0 }
}

// ---------------------------------------------------------------------------
// Signal numbering
// ---------------------------------------------------------------------------

#[test]
fn signal_from_u8_rejects_zero_and_glibc_reserved() {
    assert!(Signal::from_u8(0).is_none());
    assert!(Signal::from_u8(32).is_none());
    assert!(Signal::from_u8(33).is_none());
    assert!(Signal::from_u8(65).is_none());
}

#[test]
fn signal_from_u8_accepts_standard_and_rt() {
    assert_eq!(Signal::from_u8(1).unwrap().as_u8(), 1);
    assert_eq!(Signal::from_u8(31).unwrap().as_u8(), 31);
    assert_eq!(Signal::from_u8(34).unwrap().as_u8(), 34);
    assert_eq!(Signal::from_u8(64).unwrap().as_u8(), 64);
}

#[test]
fn realtime_split_at_34() {
    assert!(!Signal::SIGINT.is_realtime());
    assert!(!Signal::SIGSYS.is_realtime());
    assert!(Signal::SIGRT0.is_realtime());
    assert!(Signal::SIGRT_LAST.is_realtime());
}

#[test]
fn sigkill_sigstop_are_unmaskable() {
    assert!(!Signal::SIGKILL.is_maskable());
    assert!(!Signal::SIGSTOP.is_maskable());
    assert!(Signal::SIGTERM.is_maskable());
}

// ---------------------------------------------------------------------------
// SignalSet
// ---------------------------------------------------------------------------

#[test]
fn signalset_add_remove_contains() {
    let mut s = SignalSet::empty();
    assert!(!s.contains(Signal::SIGINT));
    s.add(Signal::SIGINT);
    assert!(s.contains(Signal::SIGINT));
    s.remove(Signal::SIGINT);
    assert!(!s.contains(Signal::SIGINT));
}

#[test]
fn signalset_all_maskable_excludes_kill_stop() {
    let m = SignalSet::all_maskable();
    assert!(!m.contains(Signal::SIGKILL));
    assert!(!m.contains(Signal::SIGSTOP));
    assert!(m.contains(Signal::SIGINT));
    assert!(m.contains(Signal::SIGRT0));
}

// ---------------------------------------------------------------------------
// SignalState
// ---------------------------------------------------------------------------

#[test]
fn send_collapses_standard_signal() {
    let mut s = SignalState::new(64);
    let was_new = s.send(Signal::SIGUSR1, info(Signal::SIGUSR1));
    assert!(was_new);
    // Second SIGUSR1: bit already set, no queue (standard signal),
    // returns false.
    let again = s.send(Signal::SIGUSR1, info(Signal::SIGUSR1));
    assert!(!again);
    assert!(s.pending().contains(Signal::SIGUSR1));
}

#[test]
fn send_queues_rt_signal_payload() {
    let mut s = SignalState::new(64);
    s.send(Signal::SIGRT0, SigInfo { signo: 34, code: 1, pid: 100, uid: 0, value: 0xAA });
    s.send(Signal::SIGRT0, SigInfo { signo: 34, code: 2, pid: 200, uid: 0, value: 0xBB });
    assert_eq!(s.queue.len(), 2);
    assert!(s.pending().contains(Signal::SIGRT0));
}

#[test]
fn pop_deliverable_returns_lowest_first() {
    let mut s = SignalState::new(64);
    s.send(Signal::SIGTERM, info(Signal::SIGTERM));
    s.send(Signal::SIGINT,  info(Signal::SIGINT));
    let (sig, _) = s.pop_deliverable().unwrap();
    assert_eq!(sig, Signal::SIGINT);
    let (sig, _) = s.pop_deliverable().unwrap();
    assert_eq!(sig, Signal::SIGTERM);
    assert!(s.pop_deliverable().is_none());
}

#[test]
fn blocked_mask_hides_pending() {
    let mut s = SignalState::new(64);
    let mut blk = SignalSet::empty();
    blk.add(Signal::SIGINT);
    s.set_blocked(blk);
    s.send(Signal::SIGINT, info(Signal::SIGINT));
    s.send(Signal::SIGUSR1, info(Signal::SIGUSR1));
    let (sig, _) = s.pop_deliverable().unwrap();
    assert_eq!(sig, Signal::SIGUSR1, "blocked SIGINT must hide");
    assert!(s.pop_deliverable().is_none());
    // Unblock; SIGINT now deliverable.
    s.set_blocked(SignalSet::empty());
    let (sig, _) = s.pop_deliverable().unwrap();
    assert_eq!(sig, Signal::SIGINT);
}

#[test]
fn set_blocked_silently_strips_kill_stop() {
    let s = SignalState::new(64);
    let mut blk = SignalSet::empty();
    blk.add(Signal::SIGKILL);
    blk.add(Signal::SIGSTOP);
    blk.add(Signal::SIGINT);
    s.set_blocked(blk);
    let actual = s.blocked();
    assert!(!actual.contains(Signal::SIGKILL), "SIGKILL must never be blocked");
    assert!(!actual.contains(Signal::SIGSTOP), "SIGSTOP must never be blocked");
    assert!(actual.contains(Signal::SIGINT));
}

#[test]
fn set_action_for_kill_stop_is_silent_noop() {
    let mut s = SignalState::new(64);
    let new = SigAction { handler: 0xdead, mask: SignalSet::empty(), flags: 0 };
    s.set_action(Signal::SIGKILL, new);
    // Action unchanged.
    assert_eq!(s.action(Signal::SIGKILL), SigAction::default());
    s.set_action(Signal::SIGSTOP, new);
    assert_eq!(s.action(Signal::SIGSTOP), SigAction::default());
    // Maskable signal accepts the change.
    s.set_action(Signal::SIGTERM, new);
    assert_eq!(s.action(Signal::SIGTERM), new);
}

#[test]
fn rt_queue_dropped_on_overflow() {
    let mut s = SignalState::new(2);
    for _ in 0..5 {
        s.send(Signal::SIGRT1, SigInfo { signo: 35, code: 0, pid: 0, uid: 0, value: 0 });
    }
    assert_eq!(s.queue.len(), 2);
    assert_eq!(
        s.queue_dropped.load(core::sync::atomic::Ordering::Relaxed),
        3
    );
}

#[test]
fn pop_rt_drains_queue_and_clears_pending() {
    let mut s = SignalState::new(64);
    for code in 0..3 {
        s.send(Signal::SIGRT0,
            SigInfo { signo: 34, code, pid: 0, uid: 0, value: code as u64 });
    }
    let (sig, info1) = s.pop_deliverable().unwrap();
    assert_eq!(sig, Signal::SIGRT0);
    assert_eq!(info1.value, 0);
    let (_, info2) = s.pop_deliverable().unwrap();
    assert_eq!(info2.value, 1);
    let (_, info3) = s.pop_deliverable().unwrap();
    assert_eq!(info3.value, 2);
    // Queue drained ⇒ pending bit cleared.
    assert!(!s.pending().contains(Signal::SIGRT0));
    assert!(s.pop_deliverable().is_none());
}

#[test]
fn reset_for_exec_clears_handlers_and_pending_only() {
    let mut s = SignalState::new(64);
    let mut blk = SignalSet::empty();
    blk.add(Signal::SIGINT);
    s.set_blocked(blk);
    s.set_action(Signal::SIGTERM, SigAction { handler: 0xfeed, mask: SignalSet::empty(), flags: 0 });
    s.send(Signal::SIGUSR1, info(Signal::SIGUSR1));

    s.reset_for_exec();
    assert!(s.pending().is_empty(), "pending cleared on exec");
    assert_eq!(s.action(Signal::SIGTERM), SigAction::default(), "handlers reset");
    // Blocked mask survives exec per POSIX.
    assert!(s.blocked().contains(Signal::SIGINT));
}
