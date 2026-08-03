use super::*;

/// A unicast miss emits nothing here. The driver has no solicitation to send
/// and no state to consult: the neighbour layer queued the packet and will
/// solicit for it, and hands this back only once the address is known.
#[test]
fn arp_miss_leaves_solicitation_to_net_stack() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    assert_eq!(
        link_address_for(net::pkt::TxNextHop::V4(net::Ipv4Addr::new(10, 0, 0, 2))),
        None);
    clear_test_state();
}
