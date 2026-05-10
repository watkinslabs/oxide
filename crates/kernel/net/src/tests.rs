// Hosted tests for the net foundation: addressing, packet buffer,
// TCP state machine.

extern crate alloc;
use super::*;
use crate::addr::*;
use crate::pkt::*;
use crate::tcp_state::*;

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

#[test]
fn mac_broadcast_predicate() {
    assert!(MacAddr::BROADCAST.is_broadcast());
    assert!(MacAddr::BROADCAST.is_multicast()); // broadcast is multicast
    assert!(!MacAddr::ZERO.is_broadcast());
    assert!(!MacAddr::ZERO.is_multicast());
}

#[test]
fn mac_multicast_low_bit() {
    let m = MacAddr([0x01, 0, 0, 0, 0, 0]);
    assert!(m.is_multicast());
    assert!(!m.is_broadcast());
    assert!(!m.is_local());
}

#[test]
fn mac_local_admin_bit() {
    let m = MacAddr([0x02, 0, 0, 0, 0, 0]);
    assert!(m.is_local());
    assert!(!m.is_multicast());
}

// ---------------------------------------------------------------------------
// Ipv4Addr
// ---------------------------------------------------------------------------

#[test]
fn ipv4_constructor_and_octets() {
    let a = Ipv4Addr::new(192, 168, 1, 100);
    assert_eq!(a.octets(), [192, 168, 1, 100]);
    assert_eq!(a.as_u32(), 0xc0a8_0164);
}

#[test]
fn ipv4_well_known_predicates() {
    assert!(Ipv4Addr::ANY.is_unspecified());
    assert!(Ipv4Addr::LOOPBACK.is_loopback());
    assert!(Ipv4Addr::BROADCAST.is_broadcast());
    assert!(Ipv4Addr::new(127, 0, 0, 5).is_loopback());
    assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
    assert!(Ipv4Addr::new(169, 254, 1, 1).is_link_local());
    assert!(!Ipv4Addr::new(10, 0, 0, 1).is_link_local());
}

// ---------------------------------------------------------------------------
// Ipv6Addr
// ---------------------------------------------------------------------------

#[test]
fn ipv6_segment_round_trip() {
    let segs = [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1];
    let a = Ipv6Addr::from_segments(segs);
    assert_eq!(a.segments(), segs);
}

#[test]
fn ipv6_well_known_predicates() {
    assert!(Ipv6Addr::ANY.is_unspecified());
    assert!(Ipv6Addr::LOOPBACK.is_loopback());

    let ll = Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    assert!(ll.is_link_local());

    let mc = Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 1]);
    assert!(mc.is_multicast());

    let global = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    assert!(!global.is_unspecified() && !global.is_loopback()
            && !global.is_link_local() && !global.is_multicast());
}

#[test]
fn ip_addr_dispatch() {
    let v4 = IpAddr::V4(Ipv4Addr::LOOPBACK);
    let v6 = IpAddr::V6(Ipv6Addr::LOOPBACK);
    assert!(v4.is_loopback());
    assert!(v6.is_loopback());
    assert!(IpAddr::V4(Ipv4Addr::ANY).is_unspecified());
    assert!(IpAddr::V6(Ipv6Addr::ANY).is_unspecified());
}

// ---------------------------------------------------------------------------
// IpProto / NetIfaceId / eth_p
// ---------------------------------------------------------------------------

#[test]
fn ipproto_numeric_matches_ipproto_h() {
    assert_eq!(IpProto::Icmp   as u8, 1);
    assert_eq!(IpProto::Tcp    as u8, 6);
    assert_eq!(IpProto::Udp    as u8, 17);
    assert_eq!(IpProto::Icmpv6 as u8, 58);
}

#[test]
fn eth_p_constants() {
    assert_eq!(eth_p::IPV4, 0x0800);
    assert_eq!(eth_p::ARP,  0x0806);
    assert_eq!(eth_p::IPV6, 0x86dd);
}

// ---------------------------------------------------------------------------
// Pkt
// ---------------------------------------------------------------------------

#[test]
fn pkt_initial_layout() {
    let p = Pkt::new(100);
    assert_eq!(p.len(), 100);
    assert_eq!(p.headroom(), DEFAULT_HEADROOM);
    assert_eq!(p.capacity(), DEFAULT_HEADROOM + 100);
}

#[test]
fn pkt_push_consumes_headroom() {
    let mut p = Pkt::new(100);
    let pre = p.headroom();
    let h = p.push(20).unwrap();
    h[0] = 0xAB;
    assert_eq!(p.headroom(), pre - 20);
    // First byte of `data()` is now what `push` wrote.
    assert_eq!(p.data()[0], 0xAB);
    assert_eq!(p.len(), 120);
}

#[test]
fn pkt_push_too_big_returns_enobufs() {
    let mut p = Pkt::new(100);
    assert_eq!(p.push(DEFAULT_HEADROOM + 1).err(), Some(PktError::Enobufs));
}

#[test]
fn pkt_pop_advances_data() {
    let mut p = Pkt::new(100);
    p.data_mut()[0] = 0xAA;
    p.data_mut()[1] = 0xBB;
    p.pop(1).unwrap();
    assert_eq!(p.data()[0], 0xBB);
    assert_eq!(p.len(), 99);
}

#[test]
fn pkt_pop_past_tail_is_einval() {
    let mut p = Pkt::new(4);
    assert_eq!(p.pop(5).err(), Some(PktError::Einval));
}

#[test]
fn pkt_put_extends_tail() {
    let mut p = Pkt::with_capacity(8, 12);
    let n = p.put(4).unwrap();
    n.copy_from_slice(b"abcd");
    assert_eq!(p.data(), b"abcd");
    assert_eq!(p.len(), 4);
    assert_eq!(p.tailroom(), 0);
}

#[test]
fn pkt_put_too_big_returns_enobufs() {
    let mut p = Pkt::new_with_headroom(0, 4);
    assert_eq!(p.put(8).err(), Some(PktError::Enobufs));
}

#[test]
fn pkt_trim_drops_from_tail() {
    let mut p = Pkt::new(10);
    p.trim(3).unwrap();
    assert_eq!(p.len(), 7);
}

#[test]
fn pkt_trim_past_data_is_einval() {
    let mut p = Pkt::new(4);
    assert_eq!(p.trim(8).err(), Some(PktError::Einval));
}

#[test]
fn pkt_from_owned() {
    let p = Pkt::from_owned(alloc::vec::Vec::from(&b"hello"[..]));
    assert_eq!(p.data(), b"hello");
    assert_eq!(p.headroom(), 0);
    assert_eq!(p.tailroom(), 0);
}

#[test]
fn pkt_reset_returns_clean_buffer() {
    let mut p = Pkt::new(100);
    p.put(5).unwrap_err(); // already at tail; cap reached
    p.reset(16);
    assert_eq!(p.headroom(), 16);
    assert_eq!(p.len(), 0);
}

// ---------------------------------------------------------------------------
// TCP state machine (`25§7`)
// ---------------------------------------------------------------------------

#[test]
fn tcp_active_open_handshake() {
    let s = TcpState::Closed;
    let s = transition(s, TcpEvent::ActiveOpen).unwrap();
    assert_eq!(s, TcpState::SynSent);
    let s = transition(s, TcpEvent::RecvSynAck).unwrap();
    assert_eq!(s, TcpState::Established);
    assert!(s.is_established());
}

#[test]
fn tcp_passive_open_handshake() {
    let s = TcpState::Closed;
    let s = transition(s, TcpEvent::PassiveOpen).unwrap();
    assert_eq!(s, TcpState::Listen);
    let s = transition(s, TcpEvent::RecvSyn).unwrap();
    assert_eq!(s, TcpState::SynRecv);
    let s = transition(s, TcpEvent::RecvAckEstablish).unwrap();
    assert_eq!(s, TcpState::Established);
}

#[test]
fn tcp_local_close_path() {
    let s = TcpState::Established;
    let s = transition(s, TcpEvent::LocalClose).unwrap();
    assert_eq!(s, TcpState::FinWait1);
    let s = transition(s, TcpEvent::RecvFinAck).unwrap();
    assert_eq!(s, TcpState::FinWait2);
    let s = transition(s, TcpEvent::RecvFin).unwrap();
    assert_eq!(s, TcpState::TimeWait);
    let s = transition(s, TcpEvent::TimeWaitExpired).unwrap();
    assert_eq!(s, TcpState::Closed);
}

#[test]
fn tcp_remote_close_path() {
    let s = TcpState::Established;
    let s = transition(s, TcpEvent::RecvFin).unwrap();
    assert_eq!(s, TcpState::CloseWait);
    let s = transition(s, TcpEvent::LocalClose).unwrap();
    assert_eq!(s, TcpState::LastAck);
    let s = transition(s, TcpEvent::RecvFinAck).unwrap();
    assert_eq!(s, TcpState::Closed);
}

#[test]
fn tcp_simultaneous_close_via_closing() {
    let s = TcpState::Established;
    let s = transition(s, TcpEvent::LocalClose).unwrap();
    assert_eq!(s, TcpState::FinWait1);
    let s = transition(s, TcpEvent::RecvFin).unwrap();
    assert_eq!(s, TcpState::Closing);
    let s = transition(s, TcpEvent::RecvFinAck).unwrap();
    assert_eq!(s, TcpState::TimeWait);
}

#[test]
fn tcp_reset_short_circuits_to_closed() {
    for s in [TcpState::SynSent, TcpState::Established, TcpState::FinWait1,
              TcpState::CloseWait, TcpState::TimeWait]
    {
        assert_eq!(transition(s, TcpEvent::Reset), Some(TcpState::Closed));
    }
}

#[test]
fn tcp_invalid_event_returns_none() {
    assert_eq!(transition(TcpState::Closed, TcpEvent::RecvFin), None);
    assert_eq!(transition(TcpState::Listen, TcpEvent::LocalClose), None);
    assert_eq!(transition(TcpState::Established, TcpEvent::PassiveOpen), None);
}

#[test]
fn tcp_state_classifiers() {
    assert!(TcpState::Established.is_established());
    assert!(!TcpState::Closed.is_established());
    assert!(TcpState::FinWait1.is_closing());
    assert!(TcpState::CloseWait.is_closing());
    assert!(!TcpState::Established.is_closing());
}
