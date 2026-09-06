use super::*;

#[test]
fn desktop_ack_is_independent_and_observed_once() {
    let state = AtomicU8::new(INITIAL);
    assert!(record(&state, DESKTOP_ACK));
    assert!(!record(&state, DESKTOP_ACK));
    assert_eq!(state.load(Ordering::Acquire) & SERVER_ENTRY, 0);
    assert!(record(&state, PAINT_PRESENT));
}

#[test]
fn window_observation_does_not_require_a_server_call() {
    let state = AtomicU8::new(INITIAL);
    assert!(record(&state, UNIX_ENTRY));
    assert!(record(&state, WINDOW_CREATE));
    assert_eq!(state.load(Ordering::Acquire) & SERVER_ENTRY, 0);
    assert!(!record(&state, WINDOW_CREATE));
}

#[test]
fn synchronous_paint_is_recorded_before_message_retrieval() {
    let state = AtomicU8::new(INITIAL);
    for event in [UNIX_ENTRY, WINDOW_CREATE, PAINT_BEGIN, PAINT_PRESENT, MESSAGE_GET, SERVER_ENTRY] {
        assert!(record(&state, event));
        assert!(!record(&state, event));
    }
    assert_eq!(state.load(Ordering::Acquire), INITIAL | UNIX_ENTRY | SERVER_ENTRY | WINDOW_CREATE | MESSAGE_GET | PAINT_BEGIN | PAINT_PRESENT);
}
