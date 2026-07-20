use super::*;

fn assert_latched_after_enotconn(sock: &InetSocket) {
    assert_eq!(shutdown(sock, ShutdownHow::ReadWrite), Err(NetError::Enotconn));
    assert!(sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
    assert!(sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn unconnected_inet_protocols_latch_before_returning_enotconn() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    assert_latched_after_enotconn(&InetSocket::new_udp_in(owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_tcp_in(owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_raw4_in(
        crate::addr::IpProto::Icmp as u8, owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_raw6_in(
        crate::addr::IpProto::Icmpv6 as u8, owner));
}
