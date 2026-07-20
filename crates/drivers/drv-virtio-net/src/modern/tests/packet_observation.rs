use super::*;

#[test]
fn arp_miss_leaves_solicitation_to_net_stack() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let device_key = key(41);
    let mut observations = alloc::vec::Vec::new();

    let resolved = resolve_next_hop_mac_observed(
        device_key, [0x02, 0, 0, 0, 0, 1],
        net::pkt::TxNextHop::V4(net::Ipv4Addr::new(10, 0, 0, 2)),
        &mut |frame, protocol, header_len| {
            observations.push((frame.to_vec(), protocol, header_len));
        },
    );

    assert_eq!(resolved, None);
    assert!(observations.is_empty());
    clear_test_state();
}
