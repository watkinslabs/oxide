use super::SockBhLock;

#[test]
fn inet_socket_net_rx_fields_use_bottom_half_safe_locks() {
    let source = include_str!("types.rs");
    assert!(source.contains("packet_rings: SockBhLock<PacketRings>"));
    assert!(source.contains("kind:       SockBhLock<SockKind>"));
}

#[test]
fn socket_bottom_half_lock_masks_local_receive_processing() {
    sched::preempt::_test_reset();
    let state = SockBhLock::new(0u8);
    {
        let _guard = state.lock();
        assert_eq!(sched::preempt::softirq_count(), sched::preempt::SOFTIRQ_DISABLE_OFFSET);
    }
    assert_eq!(sched::preempt::softirq_count(), 0);
}
