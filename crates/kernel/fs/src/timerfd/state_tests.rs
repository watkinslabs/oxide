use alloc::sync::Arc;

use super::*;

#[test]
fn delayed_backward_step_hook_does_not_invent_an_old_domain_expiration() {
    let mut state = TimerfdState::new(0);
    let (_, canceled) = state.install(20, 80, 100, 10, true, true, 0);
    assert!(!canceled);
    assert_eq!(state.realtime_projection_ns, 40);

    assert!(state.note_clock_was_set(1, 35, 45, 50));
    assert_eq!(state.ticks, 0);
    assert_eq!(state.expiry_ns, 100);
    assert_eq!(state.realtime_projection_ns, 95);
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 45, 50, &mut output),
        Err(VfsError::Ecanceled));
    assert_eq!(state.expiry_ns, 100);
    assert_eq!(state.realtime_projection_ns, 95);
}

#[test]
fn canceled_crossed_periodic_timer_stays_inactive_after_a_backward_step() {
    let mut state = TimerfdState::new(0);
    let (_, canceled) = state.install(20, 80, 100, 10, true, true, 0);
    assert!(!canceled);

    assert!(state.note_clock_was_set(1, 45, 45, 50));
    assert_eq!(state.ticks, 1);
    assert_eq!(state.expiry_ns, 110);
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 45, 50, &mut output),
        Err(VfsError::Ecanceled));
    assert_eq!(state.expiry_ns, 0);
    assert_eq!(state.realtime_projection_ns, 0);
}

#[test]
fn canceled_forward_step_expirations_do_not_rearm_a_periodic_timer() {
    let mut state = TimerfdState::new(0);
    let (_, canceled) = state.install(20, 80, 100, 10, true, true, 0);
    assert!(!canceled);

    assert!(state.note_clock_was_set(1, 30, 30, 125));
    assert_eq!(state.ticks, 3);
    assert_eq!(state.expiry_ns, 130);
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 30, 125, &mut output),
        Err(VfsError::Ecanceled));
    assert_eq!(state.expiry_ns, 0);
    assert_eq!(state.realtime_projection_ns, 0);
}

#[test]
fn locked_state_snapshots_never_mix_transaction_fields() {
    let a = TimerfdState {
        expiry_ns: 10,
        interval_ns: 20,
        ticks: 30,
        clock_generation_seen: 40,
        cancel_enabled: true,
        cancel_pending: false,
        realtime_absolute: false, settime_flags: 0,
        realtime_projection_ns: 0,
    };
    let b = TimerfdState {
        expiry_ns: 50,
        interval_ns: 60,
        ticks: 70,
        clock_generation_seen: 80,
        cancel_enabled: false,
        cancel_pending: true,
        realtime_absolute: true, settime_flags: 0,
        realtime_projection_ns: 90,
    };
    let state = Arc::new(Spinlock::<TimerfdState, TimerLockClass>::new(a));
    let writer_state = Arc::clone(&state);
    let writer = std::thread::spawn(move || {
        for index in 0..10_000 {
            *writer_state.lock() = if index & 1 == 0 { b } else { a };
        }
    });
    for _ in 0..10_000 {
        let snapshot = *state.lock();
        assert!(snapshot == a || snapshot == b);
    }
    writer.join().unwrap();
}
