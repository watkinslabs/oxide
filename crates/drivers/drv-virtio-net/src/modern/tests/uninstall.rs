use super::*;

#[test]
fn failed_netdev_unpublish_preserves_queue_and_runtime() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    MODERN_DEVS.lock().push(state(31));
    set_registered_iface(key(31), net::NetIfaceId::from_raw(131));
    install_rx_runtime(key(31), net::NetIfaceId::from_raw(131));
    let _ = ensure_net_runtime(key(31));
    set_test_unregister_netdev(false);

    assert!(!uninstall_modern(key(31)));
    assert!(is_modern_present_for(key(31)));
    assert!(registered_iface_for(key(31)).is_some());
    assert!(net_runtime_for(key(31)).is_some());
    assert_eq!(state::test_released_frames(), 0);
    assert_eq!(state::test_resets(), 0);

    set_test_unregister_netdev(true);
    assert!(uninstall_modern(key(31)));
    clear_test_state();
}

