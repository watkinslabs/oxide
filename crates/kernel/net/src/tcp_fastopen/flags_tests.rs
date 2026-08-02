use super::*;

#[test]
fn the_compiled_default_enables_the_client_half_and_nothing_else() {
    assert_eq!(TFO_DEFAULT, TFO_CLIENT_ENABLE);
    assert!(client_enabled(TFO_DEFAULT));
    // The server half stays off, so a host that touched no sysctl fast-opens
    // nothing it listens for.
    assert!(!listen_enables_queue(TFO_DEFAULT, 0));
}

#[test]
fn the_two_halves_are_independent_bits() {
    assert_eq!(TFO_CLIENT_ENABLE, 1);
    assert_eq!(TFO_SERVER_ENABLE, 2);
    assert_eq!(TFO_SERVER_WO_SOCKOPT1, 0x400);
    assert!(!client_enabled(TFO_SERVER_ENABLE));
    assert!(client_enabled(TFO_CLIENT_ENABLE | TFO_SERVER_ENABLE));
    assert!(!client_enabled(0));
}

#[test]
fn listen_sizes_a_queue_only_with_both_server_bits_and_no_bound_already() {
    let both = TFO_SERVER_ENABLE | TFO_SERVER_WO_SOCKOPT1;
    assert!(listen_enables_queue(both, 0));
    // Either server bit alone is not enough.
    assert!(!listen_enables_queue(TFO_SERVER_ENABLE, 0));
    assert!(!listen_enables_queue(TFO_SERVER_WO_SOCKOPT1, 0));
    // A bound already named by hand is never overwritten by `listen`.
    assert!(!listen_enables_queue(both, 1));
    assert!(!listen_enables_queue(both, 4096));
    // The client bit does not participate.
    assert!(listen_enables_queue(both | TFO_CLIENT_ENABLE, 0));
}
