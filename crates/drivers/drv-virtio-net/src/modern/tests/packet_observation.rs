use super::*;

#[test]
fn arp_miss_publishes_one_outgoing_control_frame() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let device_key = key(41);
    let iface = net::NetIfaceId::from_raw(141);
    let _ = ensure_net_runtime(device_key);
    let _ = support::install_test_rx(device_key, iface);
    assert!(set_softirq_ip_for_iface(iface, [10, 0, 0, 1]));
    let mut observations = alloc::vec::Vec::new();

    let resolved = resolve_next_hop_mac_observed(
        device_key, [0x02, 0, 0, 0, 0, 1],
        net::pkt::TxNextHop::V4(net::Ipv4Addr::new(10, 0, 0, 2)),
        &mut |frame, protocol, header_len| {
            observations.push((frame.to_vec(), protocol, header_len));
        },
    );

    assert_eq!(resolved, None);
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].1, net::eth_p::ARP);
    assert_eq!(observations[0].2, 14);
    assert_eq!(observations[0].0.len(), 14 + net::arp::ARP_LEN);
    clear_test_state();
}
