// F183: hosted tests for F173-F179 network correctness work.
// Catch regressions to MSS/window-scale negotiation, OOO recv
// buffering, SO_SNDBUF cap, SO_REUSEADDR conflict check, ARP
// aging, ICMP unreach handling, and output()'s multi-segment
// drain at hosted-test time — no QEMU boot required.

extern crate alloc;
use alloc::vec::Vec;
use super::*;
use crate::addr::*;
use crate::tcp_conn::{TcpConn, Endpoint};
use crate::tcp_hdr::{TcpHdr, parse_mss_option, parse_wscale_option, opt, TCP_HDR_MIN_LEN};
use crate::tcp_state::TcpState;
use crate::arp::{ArpCache, ARP_STALE_NS};
use crate::stack::NetStack;
use crate::netdev::NetError;

fn ep(ip: Ipv4Addr, port: u16) -> Endpoint { Endpoint { ip: IpAddr::V4(ip), port } }

fn lo() -> Ipv4Addr { Ipv4Addr::LOOPBACK }
fn lo_ip() -> IpAddr { IpAddr::V4(Ipv4Addr::LOOPBACK) }

// ----- F173: MSS option in active-open SYN ---------------------------

#[test]
fn f173_active_open_emits_mss_option() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let syn = c.active_open().unwrap();
    let mss = parse_mss_option(&syn);
    assert_eq!(mss, Some(1460), "active_open SYN must carry MSS=1460");
}

#[test]
fn f173_input_latches_peer_mss_from_synack() {
    // Client opens; we feed a synthesized SYN-ACK with MSS=536.
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 1460, Some(536), None);
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert_eq!(c.peer_mss, 536, "peer MSS=536 must be latched");
}

// ----- F178: window scale negotiation --------------------------------

#[test]
fn f178_active_open_emits_wscale_option() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let syn = c.active_open().unwrap();
    assert_eq!(parse_wscale_option(&syn), Some(0),
        "active_open SYN must advertise WSCALE (OWN_WSCALE=0)");
}

#[test]
fn f178_input_latches_peer_wscale_only_when_present() {
    // Peer's SYN-ACK includes WSCALE=7 → we latch rcv_wscale=7.
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let with_ws = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), Some(7));
    let _ = c.input(lo_ip(), lo_ip(), &with_ws);
    assert_eq!(c.rcv_wscale, 7);
}

#[test]
fn f178_input_no_wscale_keeps_default_zero() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let no_ws = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), None);
    let _ = c.input(lo_ip(), lo_ip(), &no_ws);
    assert_eq!(c.rcv_wscale, 0,
        "rcv_wscale stays 0 when peer omits WSCALE (RFC 7323 §1.3)");
}

#[test]
fn f178_input_non_syn_applies_rcv_wscale_to_window() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 100, Some(1460), Some(3));
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    // SYN window is unscaled; established conn snd_wnd = 100.
    assert_eq!(c.snd_wnd, 100);
    // Now an ACK with window=200 should be scaled by rcv_wscale=3.
    let ack = build_plain_ack(0x2000_0001, c.snd_nxt, 200);
    let _ = c.input(lo_ip(), lo_ip(), &ack);
    assert_eq!(c.snd_wnd, 200u32 << 3, "non-SYN window must be left-shifted by rcv_wscale");
}

// ----- F179: out-of-order receive buffer -----------------------------

#[test]
fn f179_in_order_delivers_immediately() {
    let mut c = client_established();
    let seg = build_data_segment(c.rcv_nxt, c.snd_nxt, b"hello");
    let _ = c.input(lo_ip(), lo_ip(), &seg);
    assert_eq!(c.recv_buf.iter().copied().collect::<Vec<u8>>(), b"hello");
}

#[test]
fn f179_ooo_buffered_until_gap_fills() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    // Push gap-segment first: seq = base+5..base+10 ("world").
    let ooo = build_data_segment(base.wrapping_add(5), c.snd_nxt, b"world");
    let _ = c.input(lo_ip(), lo_ip(), &ooo);
    assert!(c.recv_buf.is_empty(), "OOO data must not deliver before gap fills");
    assert_eq!(c.ooo_buf.len(), 1);
    // Now push the gap: seq = base..base+5 ("hello").
    let fill = build_data_segment(base, c.snd_nxt, b"hello");
    let _ = c.input(lo_ip(), lo_ip(), &fill);
    let got: Vec<u8> = c.recv_buf.iter().copied().collect();
    assert_eq!(got, b"helloworld",
        "in-order arrival must drain contiguous OOO chunks");
    assert!(c.ooo_buf.is_empty());
}

#[test]
fn f179_past_window_data_ignored() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    // Past-window: seq = base - 10 (already ACK'd range).
    let stale = build_data_segment(base.wrapping_sub(10), c.snd_nxt, b"stale");
    let _ = c.input(lo_ip(), lo_ip(), &stale);
    assert!(c.recv_buf.is_empty());
    assert!(c.ooo_buf.is_empty(), "past-window data must not enter ooo_buf");
}

// ----- F180a: IPv6 UDP bind + recv path -----------------------------

#[test]
fn f180a_ipv6_udp_bind_then_recv_routes_via_udp6() {
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    // bind a v6 UDP socket on port 5060.
    stack.bind_udp6(Ipv6Addr::LOOPBACK, 5060).unwrap();
    // Build a v6/UDP frame: 40 IPv6 hdr + 8 UDP hdr + 5 payload.
    let payload = b"oxv6!";
    let l4_len  = UDP_HDR_LEN + payload.len();
    let total   = IPV6_HDR_LEN + l4_len;
    let mut frame = alloc::vec![0u8; total];
    build_into_v6(33000, 5060, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        payload, &mut frame[IPV6_HDR_LEN..]);
    let h = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, l4_len as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // recv_udp6 should yield (src, src_port, payload).
    let (src, sport, body) = stack.recv_udp6(5060).expect("v6 UDP must route to bound queue");
    assert_eq!(src, Ipv6Addr::LOOPBACK);
    assert_eq!(sport, 33000);
    assert_eq!(body, payload);
}

#[test]
fn f180a_ipv6_udp_no_bind_silent_drop() {
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, build_into_v6};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let payload = b"x";
    let l4_len  = UDP_HDR_LEN + payload.len();
    let total   = IPV6_HDR_LEN + l4_len;
    let mut frame = alloc::vec![0u8; total];
    build_into_v6(1234, 9999, Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        payload, &mut frame[IPV6_HDR_LEN..]);
    let h = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, l4_len as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    // No socket bound → cleanly drop, no error.
    assert!(stack.deliver_rx_ipv6(id, &frame).is_ok());
    assert!(stack.recv_udp6(9999).is_none());
}

#[test]
fn f180a_ipv6_udp_eaddrinuse_on_dup_bind() {
    use crate::addr::Ipv6Addr;
    let stack = NetStack::new();
    stack.bind_udp6(Ipv6Addr::LOOPBACK, 8888).unwrap();
    assert_eq!(stack.bind_udp6(Ipv6Addr::LOOPBACK, 8888).err().unwrap(),
               NetError::Eaddrinuse);
}

// ----- F184: per-iface MTU → own_mss --------------------------------

#[test]
fn f184_mss_for_v4_loopback_subtracts_40() {
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // lo MTU = 65535; v4 overhead = 40 → MSS = 65495.
    assert_eq!(stack.mss_for_dst(IpAddr::V4(Ipv4Addr::LOOPBACK)), 65495);
}

#[test]
fn f184_mss_for_v6_loopback_subtracts_60() {
    use crate::addr::Ipv6Addr;
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // v6 overhead = 60 → 65475.
    assert_eq!(stack.mss_for_dst(IpAddr::V6(Ipv6Addr::LOOPBACK)), 65475);
}

#[test]
fn f184_active_open_syn_advertises_mtu_derived_mss() {
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let _ = stack.tcp_connect(Ipv4Addr::LOOPBACK, 51000, Ipv4Addr::LOOPBACK, 80).unwrap();
    let syn = lo.rx_pop().expect("SYN must be on lo");
    // strip IPv4 header (20 bytes for no options).
    let l4 = &syn.data()[20..];
    assert_eq!(parse_mss_option(l4), Some(65495),
        "SYN MSS must reflect lo's 65535 - 40 v4 overhead");
    let _ = id;
}

// ----- F180c: NDP cache + NS/NA dispatch ----------------------------

#[test]
fn f180c_na_populates_ndp_cache() {
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::NdpMsg;
    use crate::icmpv6::IPPROTO_ICMPV6;
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let neighbor_mac = MacAddr([0xde, 0xad, 0xbe, 0xef, 0, 1]);
    let na = NdpMsg::build_na(target, Ipv6Addr::LOOPBACK, neighbor_mac, target, 0);
    let total = IPV6_HDR_LEN + na.len();
    let mut frame = alloc::vec![0u8; total];
    let h = Ipv6Hdr::build(target, Ipv6Addr::LOOPBACK, IpProto::Icmpv6, na.len() as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&na);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    assert_eq!(stack.ndp.lookup(target), Some(neighbor_mac),
        "NA target_lladdr must populate NdpCache");
}

#[test]
fn f180c_ns_for_owned_addr_emits_na() {
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::{NdpMsg, NDP_NA};
    use crate::icmpv6::IPPROTO_ICMPV6;
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let our_addr = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,1]);
    stack.add_v6_addr(id, our_addr);
    let peer = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let peer_mac = MacAddr([1,2,3,4,5,6]);
    let ns = NdpMsg::build_ns(peer, our_addr, peer_mac, our_addr);
    let total = IPV6_HDR_LEN + ns.len();
    let mut frame = alloc::vec![0u8; total];
    let h = Ipv6Hdr::build(peer, our_addr, IpProto::Icmpv6, ns.len() as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ns);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // Source-lladdr from the NS should land in the cache.
    assert_eq!(stack.ndp.lookup(peer), Some(peer_mac));
    // And lo should have a frame queued — the NA reply.
    let reply = lo.rx_pop().expect("NS for owned addr must produce NA");
    let parsed = Ipv6Hdr::parse(reply.data()).unwrap();
    let body = &reply.data()[IPV6_HDR_LEN..];
    assert_eq!(body[0], NDP_NA, "reply must be NDP NA (136)");
    let _ = parsed;
}

#[test]
fn f180c_ns_for_unowned_addr_silent() {
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::NdpMsg;
    use crate::icmpv6::IPPROTO_ICMPV6;
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let unowned = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,9]);
    let peer = Ipv6Addr::LOOPBACK;
    let ns = NdpMsg::build_ns(peer, unowned, MacAddr::ZERO, unowned);
    let total = IPV6_HDR_LEN + ns.len();
    let mut frame = alloc::vec![0u8; total];
    let h = Ipv6Hdr::build(peer, unowned, IpProto::Icmpv6, ns.len() as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ns);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    assert!(lo.rx_pop().is_none(), "NS for unowned addr must not reply");
}

// ----- F180b: TCP over IPv6 -----------------------------------------

#[test]
fn f180b_tcp_listen_then_connect_over_ipv6_via_lo() {
    use crate::addr::{IpAddr, Ipv6Addr};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let listener = stack.tcp_listen_ip(IpAddr::V6(Ipv6Addr::LOOPBACK), 4444, true).unwrap();
    let client = stack.tcp_connect_ip(
        IpAddr::V6(Ipv6Addr::LOOPBACK), 50001,
        IpAddr::V6(Ipv6Addr::LOOPBACK), 4444,
    ).unwrap();
    // SYN → SYN-ACK → ACK via v6 deliver path.
    for _ in 0..3 { stack.drain_loopback(id, &lo); }
    let server = stack.tcp_accept(&listener).expect("v6 accept");
    assert_eq!(client.conn.lock().state, TcpState::Established);
    assert_eq!(server.conn.lock().state, TcpState::Established);
}

#[test]
fn f180b_tcp_demux_keys_v6_independently_of_v4() {
    use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // Same port on both families must not collide.
    stack.tcp_listen_ip(IpAddr::V4(Ipv4Addr::LOOPBACK), 7777, true).unwrap();
    stack.tcp_listen_ip(IpAddr::V6(Ipv6Addr::LOOPBACK), 7777, true).unwrap();
}

// ----- F180: IPv6 minimum-viable deliver_rx_ipv6 --------------------

#[test]
fn f180_ipv6_echo_request_produces_echo_reply_on_lo() {
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::icmpv6::{Icmp6Echo, ICMPV6_TYPE_ECHO_REQUEST, IPPROTO_ICMPV6, ICMPV6_HDR_LEN};
    let stack = NetStack::new();
    let (id, lo_dev) = stack.register_loopback();
    // Build an Echo Request: 40-byte IPv6 header + 8-byte ICMPv6
    // + 4-byte payload.
    let src = Ipv6Addr::LOOPBACK;
    let dst = Ipv6Addr::LOOPBACK;
    let payload = b"oxv6";
    let icmp_len = ICMPV6_HDR_LEN + payload.len();
    let total = IPV6_HDR_LEN + icmp_len;
    let mut frame = alloc::vec![0u8; total];
    // ICMPv6 first (so build_into can compute checksum over the body).
    let mut h = Icmp6Echo { typ: ICMPV6_TYPE_ECHO_REQUEST, code: 0, checksum: 0, id: 1, seq: 42 };
    let mut icmp_buf = alloc::vec![0u8; icmp_len];
    h.build_into(src, dst, payload, &mut icmp_buf);
    frame[IPV6_HDR_LEN..].copy_from_slice(&icmp_buf);
    // IPv6 header.
    let v6 = Ipv6Hdr::build(src, dst, crate::addr::IpProto::Icmpv6, icmp_len as u16);
    v6.write_to(&mut frame[..IPV6_HDR_LEN]);
    // Deliver — should xmit an Echo Reply onto lo.
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // Pop the reply from lo's xmit queue.
    let reply = lo_dev.rx_pop().expect("echo reply should land on lo");
    let reply_v6 = Ipv6Hdr::parse(reply.data()).unwrap();
    assert_eq!(reply_v6.next_header, IPPROTO_ICMPV6);
    let reply_icmp = &reply.data()[IPV6_HDR_LEN..];
    assert_eq!(reply_icmp[0], crate::icmpv6::ICMPV6_TYPE_ECHO_REPLY);
}

#[test]
fn f180_ipv6_udp_dropped_silently() {
    use crate::addr::Ipv6Addr;
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    // 40-byte IPv6 header advertising UDP next-header + zero payload.
    let mut frame = alloc::vec![0u8; IPV6_HDR_LEN];
    let v6 = Ipv6Hdr::build(Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK,
        crate::addr::IpProto::Udp, 0);
    v6.write_to(&mut frame);
    // No socket bound for IPv6; should drop cleanly (no error, no panic).
    let r = stack.deliver_rx_ipv6(id, &frame);
    assert!(r.is_ok(), "IPv6 UDP without socket: drop, not error");
}

#[test]
fn f180_ipv6_bad_version_rejected() {
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let mut frame = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN];
    frame[0] = 0x40;  // version 4
    let r = stack.deliver_rx_ipv6(id, &frame);
    assert!(r.is_err(), "bad-version IPv6 frame must Err(Einval)");
}

// ----- F181: per-fd targeted epoll wake -----------------------------

// InetSocket lives under #[cfg(target_os = "oxide-kernel")] in lib.rs;
// the trait-shape test below covers PollSubscribers behavior
// without requiring the sock module on hosted builds.

#[test]
fn f181_subscribe_unsubscribe_via_id() {
    use alloc::sync::{Arc, Weak};
    let subs = vfs::PollSubscribers::new();
    // Fake EpollNotify impl that records wake count.
    struct FakeEp { woken: core::sync::atomic::AtomicU32 }
    impl vfs::EpollNotify for FakeEp {
        fn notify(&self) {
            self.woken.fetch_add(1, core::sync::atomic::Ordering::Release);
        }
    }
    let ep: Arc<FakeEp> = Arc::new(FakeEp { woken: core::sync::atomic::AtomicU32::new(0) });
    let weak: Weak<dyn vfs::EpollNotify> = Arc::downgrade(&(Arc::clone(&ep) as Arc<dyn vfs::EpollNotify>));
    subs.subscribe(42, weak);
    assert!(subs.has_subscribers());
    subs.notify();
    assert_eq!(ep.woken.load(core::sync::atomic::Ordering::Acquire), 1);
    subs.unsubscribe(42);
    assert!(!subs.has_subscribers());
    subs.notify();
    assert_eq!(ep.woken.load(core::sync::atomic::Ordering::Acquire), 1,
        "after unsubscribe, notify must not fire");
}

#[test]
fn f181_dead_weak_subscribers_pruned_on_notify() {
    use alloc::sync::{Arc, Weak};
    let subs = vfs::PollSubscribers::new();
    struct FakeEp;
    impl vfs::EpollNotify for FakeEp { fn notify(&self) {} }
    let ep: Arc<FakeEp> = Arc::new(FakeEp);
    let weak: Weak<dyn vfs::EpollNotify> = Arc::downgrade(&(Arc::clone(&ep) as Arc<dyn vfs::EpollNotify>));
    subs.subscribe(1, weak);
    drop(ep);  // dropping the Arc → Weak.upgrade returns None
    subs.notify();  // GC-prunes the dead Weak
    assert!(!subs.has_subscribers());
}

// ----- F182: TCP Timestamps + PAWS ----------------------------------

#[test]
fn f182_active_open_emits_ts_option() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let syn = c.active_open().unwrap();
    let ts = crate::tcp_hdr::parse_ts_option(&syn);
    assert!(ts.is_some(), "active_open SYN must carry TSopt for negotiation");
}

#[test]
fn f182_negotiates_ts_only_when_peer_echoes() {
    // Peer's SYN-ACK includes TS → both ends enable.
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_ts(0x2000_0000, c.snd_nxt, 65535, Some(7777));
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert!(c.ts_enabled);
    assert_eq!(c.ts_recent, 7777);
}

#[test]
fn f182_no_ts_in_synack_keeps_disabled() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), None);
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert!(!c.ts_enabled, "no TS in SYN-ACK → ts disabled (don't waste bytes)");
}

#[test]
fn f182_post_negotiation_data_segments_carry_ts() {
    let mut c = client_established_with_ts();
    c.send(b"x");
    let segs = c.output(1500, true);
    let ts = crate::tcp_hdr::parse_ts_option(&segs[0]);
    assert!(ts.is_some(), "data segment must carry TSopt once enabled");
}

#[test]
fn f182_paws_drops_old_tsval() {
    let mut c = client_established_with_ts();
    c.ts_recent = 1_000_000;
    // Synthesize an in-window data segment with TSval=999 (way older).
    let base = c.rcv_nxt;
    let stale = build_data_segment_with_ts(base, c.snd_nxt, b"old", 999, 0);
    let resp = c.input(lo_ip(), lo_ip(), &stale).unwrap();
    assert!(resp.is_none(), "PAWS drop: no response, no ACK update");
    assert!(c.recv_buf.is_empty(),
        "PAWS drop must not deliver stale payload to recv_buf");
    assert_eq!(c.ts_recent, 1_000_000,
        "ts_recent must not regress on stale TSval");
}

#[test]
fn f182_paws_accepts_newer_tsval_and_updates_recent() {
    let mut c = client_established_with_ts();
    c.ts_recent = 1_000;
    let base = c.rcv_nxt;
    let fresh = build_data_segment_with_ts(base, c.snd_nxt, b"new", 2_000, 0);
    let _ = c.input(lo_ip(), lo_ip(), &fresh).unwrap();
    let got: Vec<u8> = c.recv_buf.iter().copied().collect();
    assert_eq!(got, b"new");
    assert_eq!(c.ts_recent, 2_000);
}

fn build_synack_with_ts(peer_seq: u32, peer_ack: u32, window: u16, tsval: Option<u32>) -> Vec<u8> {
    let has_ts = tsval.is_some();
    let opts_len = 4 /*MSS*/ + if has_ts { 12 /*NOPs+TS*/ } else { 0 };
    let total = TCP_HDR_MIN_LEN + opts_len;
    let mut buf = alloc::vec![0u8; total];
    let mut i = TCP_HDR_MIN_LEN;
    buf[i] = opt::MSS; buf[i+1] = 4;
    buf[i+2..i+4].copy_from_slice(&1460u16.to_be_bytes());
    i += 4;
    if let Some(ts) = tsval {
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::TIMESTAMP; buf[i+1] = 10;
        buf[i+2..i+6].copy_from_slice(&ts.to_be_bytes());
        buf[i+6..i+10].copy_from_slice(&0u32.to_be_bytes());
    }
    let data_offset = ((TCP_HDR_MIN_LEN + opts_len) / 4) as u8;
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq: peer_seq, ack: peer_ack,
        data_offset,
        flags: crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::ACK,
        window, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn build_data_segment_with_ts(seq: u32, peer_ack: u32, payload: &[u8], tsval: u32, tsecr: u32) -> Vec<u8> {
    let total = TCP_HDR_MIN_LEN + 12 + payload.len();
    let mut buf = alloc::vec![0u8; total];
    let mut i = TCP_HDR_MIN_LEN;
    buf[i] = opt::NOP; i += 1;
    buf[i] = opt::NOP; i += 1;
    buf[i] = opt::TIMESTAMP; buf[i+1] = 10;
    buf[i+2..i+6].copy_from_slice(&tsval.to_be_bytes());
    buf[i+6..i+10].copy_from_slice(&tsecr.to_be_bytes());
    buf[TCP_HDR_MIN_LEN + 12..].copy_from_slice(payload);
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq, ack: peer_ack,
        data_offset: 8,  // 20 + 12 = 32 bytes = 8 words
        flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::PSH,
        window: 65535, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn client_established_with_ts() -> TcpConn {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_ts(0x2000_0000, c.snd_nxt, 65535, Some(100));
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert!(c.ts_enabled);
    c
}

// ----- F179a: SACK option emit + consume + retx-skip ---------------

#[test]
fn f179a_sack_blocks_coalesce_contiguous_ooo() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    // OOO chunks at base+5..10 and base+10..15 should collapse
    // into a single block (left=base+5, right=base+15).
    c.ooo_buf.insert(base.wrapping_add(5), alloc::vec![0u8; 5]);
    c.ooo_buf.insert(base.wrapping_add(10), alloc::vec![0u8; 5]);
    let blocks = c.sack_blocks();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].left,  base.wrapping_add(5));
    assert_eq!(blocks[0].right, base.wrapping_add(15));
}

#[test]
fn f179a_sack_blocks_two_disjoint_runs() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    c.ooo_buf.insert(base.wrapping_add(5),  alloc::vec![0u8; 5]);
    c.ooo_buf.insert(base.wrapping_add(20), alloc::vec![0u8; 8]);
    let blocks = c.sack_blocks();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].left,  base.wrapping_add(5));
    assert_eq!(blocks[0].right, base.wrapping_add(10));
    assert_eq!(blocks[1].left,  base.wrapping_add(20));
    assert_eq!(blocks[1].right, base.wrapping_add(28));
}

#[test]
fn f179a_ack_with_ooo_carries_sack_option() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    // Push OOO then in-order; the ACK reply should carry SACK.
    let ooo = build_data_segment(base.wrapping_add(5), c.snd_nxt, b"world");
    let _ = c.input(lo_ip(), lo_ip(), &ooo);
    // Verify build_ack_with_sack emits a SACK option.
    let ack = c.build_ack_with_sack();
    let parsed = crate::tcp_hdr::parse_sack_option(&ack);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].left,  base.wrapping_add(5));
    assert_eq!(parsed[0].right, base.wrapping_add(10));
}

#[test]
fn f179a_apply_sack_marks_retx_entries() {
    let mut c = client_established();
    c.peer_mss = 10;
    c.send(b"hello-world-12345");  // 17 bytes → 2 segs (10 + 7)
    let _ = c.output(1500, true);
    assert_eq!(c.retx_q.len(), 2);
    // Synthesize SACK that covers the FIRST segment only.
    let first = &c.retx_q[0];
    let blk = crate::tcp_hdr::SackBlock {
        left: first.seq,
        right: first.seq.wrapping_add(first.payload.len() as u32),
    };
    c.apply_sack(&[blk]);
    assert!(c.retx_q[0].sacked,  "first segment must be marked sacked");
    assert!(!c.retx_q[1].sacked, "second segment NOT in block, stays unsacked");
}

#[test]
fn f179a_retransmit_due_skips_sacked() {
    let mut c = client_established();
    c.peer_mss = 10;
    c.send(b"hello-world-12345");
    let _ = c.output(1500, true);
    // Force last_sent_ns to expire RTO; sacked must still skip.
    for s in c.retx_q.iter_mut() { s.last_sent_ns = 1; }
    c.retx_q[0].sacked = true;
    let resent = c.retransmit_due(1 + c.rto_ns + 1);
    assert_eq!(resent.len(), 1, "only the non-sacked entry retransmits");
}

// ----- F176: SO_REUSEADDR + TIME_WAIT conflict ----------------------

#[test]
fn f176_listen_without_reuseaddr_blocks_on_time_wait() {
    let stack = NetStack::new();
    let (_id, _lo) = stack.register_loopback();
    // Plant a conn at (LOOPBACK, 5000, _, _) via the public ctor,
    // then mutate its state to TimeWait through the entry Arc —
    // entry.conn is `pub` so no test-only accessor needed.
    let entry = stack.tcp_connect(lo(), 5000, Ipv4Addr::new(127, 0, 0, 2), 80).unwrap();
    entry.conn.lock().state = TcpState::TimeWait;
    // listen without reuseaddr → EADDRINUSE.
    assert_eq!(stack.tcp_listen(lo(), 5000, false).err().unwrap(),
               NetError::Eaddrinuse);
    // With reuseaddr=true the same call succeeds.
    assert!(stack.tcp_listen(lo(), 5000, true).is_ok());
}

// ----- F177: ARP cache aging ----------------------------------------

#[test]
fn f177_arp_entry_within_window_returns() {
    let c = ArpCache::new();
    c.insert_at(Ipv4Addr::new(10, 0, 0, 1), MacAddr([1,2,3,4,5,6]), 1000);
    let got = c.lookup_at(Ipv4Addr::new(10, 0, 0, 1), 1000 + ARP_STALE_NS / 2);
    assert_eq!(got, Some(MacAddr([1,2,3,4,5,6])));
}

#[test]
fn f177_arp_entry_past_stale_is_dropped() {
    let c = ArpCache::new();
    c.insert_at(Ipv4Addr::new(10, 0, 0, 1), MacAddr([1,2,3,4,5,6]), 1000);
    let got = c.lookup_at(Ipv4Addr::new(10, 0, 0, 1), 1000 + ARP_STALE_NS + 1);
    assert_eq!(got, None);
    // GC at the same future time removes the entry permanently;
    // a fresh lookup at-time-zero returns None (insert never re-ran).
    c.gc(1000 + ARP_STALE_NS + 1);
    assert_eq!(c.lookup_at(Ipv4Addr::new(10, 0, 0, 1), 0), None);
}

#[test]
fn f177_arp_zero_time_disables_stale_check() {
    let c = ArpCache::new();
    c.insert_at(Ipv4Addr::new(10, 0, 0, 1), MacAddr([7,7,7,7,7,7]), 0);
    // now_ns=0 means "no clock available" — entry never stales.
    assert!(c.lookup_at(Ipv4Addr::new(10, 0, 0, 1), 999_999_999_999).is_some(),
        "inserted_ns=0 must be exempt from the stale check");
}

// ----- F164: SO_SNDBUF cap enforcement -------------------------------

#[test]
fn f164_tcp_send_accepts_up_to_cap_then_eagain() {
    let stack = NetStack::new();
    let (id, lo_dev) = stack.register_loopback();
    let _ = stack.tcp_listen(lo(), 80, true).unwrap();
    let entry = stack.tcp_connect(lo(), 50000, lo(), 80).unwrap();
    for _ in 0..3 { stack.drain_loopback(id, &lo_dev); }
    // After 3WHS: cap = 100 → first 100 bytes accepted, next call Eagain.
    let big: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    let n = stack.tcp_send(&entry, &big, 100, true).unwrap();
    assert_eq!(n, 100, "tcp_send capped at sndbuf_cap=100");
    let err = stack.tcp_send(&entry, &big, 100, true).err().unwrap();
    assert_eq!(err, NetError::Eagain,
        "tcp_send at-cap must return Eagain (caller blocks / O_NONBLOCK)");
}

// ----- F165: output() drains multi-segment + retx_q single-source ---

#[test]
fn f165_output_drains_send_buf_into_multiple_segments() {
    let mut c = client_established();
    c.peer_mss = 100;  // force MSS=100 so 350 bytes → 4 segs
    c.send(&[0u8; 350]);
    let segs = c.output(1500, true);
    assert_eq!(segs.len(), 4, "350 bytes / mss 100 → 4 segments (3*100 + 50)");
    assert!(c.send_buf.is_empty(), "output() must fully drain send_buf");
    assert_eq!(c.retx_q.len(), 4, "retx_q must own one entry per emitted segment");
}

#[test]
fn f165_retx_q_single_source_of_bytes() {
    // After output, send_buf is empty + retx_q holds the data —
    // ACK handling only touches retx_q. Validates F165's fix.
    let mut c = client_established();
    c.send(b"abc");
    let _ = c.output(1500, true);
    assert!(c.send_buf.is_empty());
    let in_flight: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
    assert_eq!(in_flight, 3);
}

// ----- F178: snd_wnd bounds output ----------------------------------

#[test]
fn f178_output_respects_peer_window() {
    let mut c = client_established();
    c.snd_wnd = 50;  // peer offers only 50 bytes
    c.peer_mss = 100;
    c.send(&[0u8; 200]);
    let segs = c.output(1500, true);
    let bytes_emitted: usize = segs.iter().map(|s| s.len() - TCP_HDR_MIN_LEN).sum();
    assert!(bytes_emitted <= 50, "must not exceed snd_wnd; got {bytes_emitted}");
}

// ----- helpers -------------------------------------------------------

fn build_synack_with_options(
    peer_seq: u32, peer_ack: u32, window: u16,
    mss: Option<u16>, wscale: Option<u8>,
) -> Vec<u8> {
    let mss_len = if mss.is_some() { 4 } else { 0 };
    let ws_len = if wscale.is_some() { 4 } else { 0 }; // 1 NOP + 3 WSCALE
    let opts_len = mss_len + ws_len;
    // pad to 4-byte alignment
    let padded = (opts_len + 3) & !3;
    let total = TCP_HDR_MIN_LEN + padded;
    let mut buf = alloc::vec![0u8; total];
    let mut i = TCP_HDR_MIN_LEN;
    if let Some(m) = mss {
        buf[i] = opt::MSS; buf[i+1] = 4;
        buf[i+2..i+4].copy_from_slice(&m.to_be_bytes());
        i += 4;
    }
    if let Some(s) = wscale {
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::WSCALE; buf[i+1] = 3; buf[i+2] = s;
    }
    let data_offset = (TCP_HDR_MIN_LEN + padded) / 4;
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq: peer_seq, ack: peer_ack,
        data_offset: data_offset as u8,
        flags: crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::ACK,
        window, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn build_plain_ack(peer_seq: u32, peer_ack: u32, window: u16) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq: peer_seq, ack: peer_ack,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::ACK,
        window, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn build_data_segment(seq: u32, peer_ack: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + payload.len()];
    buf[TCP_HDR_MIN_LEN..].copy_from_slice(payload);
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq, ack: peer_ack,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::PSH,
        window: 65535, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn client_established() -> TcpConn {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), None);
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert_eq!(c.state, TcpState::Established);
    c
}

