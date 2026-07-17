// F184-F191: per-iface MSS, CC (Reno+CUBIC), wscale autotune, ECN, PMTUD.
// Extracted from tests_correctness.rs for the 1000-line cap. Shares
// the same helpers via the parent module.

extern crate alloc;
use alloc::vec::Vec;
use crate::addr::*;
use crate::stack::NetStack;
use crate::tcp_conn::{TcpConn, Endpoint};
use crate::tcp_hdr::{TcpHdr, parse_mss_option, parse_wscale_option, TCP_HDR_MIN_LEN};
use crate::tcp_state::TcpState;
use super::{ep, lo, lo_ip, client_established, build_synack_with_options};

// ----- F195: IPv4 reassembly ----------------------------------------

#[test]
fn f195_two_fragments_reassemble_to_udp_payload() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN};
    use crate::udp::{UDP_HDR_LEN, UdpHdr};
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let endpoint = stack.bind_udp(Ipv4Addr::LOOPBACK, 12345).unwrap();
    // Build a complete UDP datagram with 1000-byte payload.
    let payload = alloc::vec![0x42u8; 1000];
    let l4_len = UDP_HDR_LEN + payload.len();
    let mut udp_buf = alloc::vec![0u8; l4_len];
    UdpHdr::build_into(7777, 12345, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        &payload, &mut udp_buf);
    // Split into 2 fragments at 512-byte boundary (must be 8-byte
    // aligned per RFC 791).
    let split = 512usize;
    // Frag 1: offset 0, len 512, MF=1
    let frag1_body = &udp_buf[..split];
    let mut f1 = alloc::vec![0u8; IPV4_HDR_LEN + frag1_body.len()];
    let mut h1 = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Udp, frag1_body.len() as u16, 42);
    h1.flags_frag = 0x2000;   // MF=1, offset=0
    h1.checksum = 0;
    let mut tmp = [0u8; IPV4_HDR_LEN];
    h1.write_to(&mut tmp);
    h1.checksum = crate::ipv4::ip_checksum(&tmp);
    h1.write_to(&mut f1[..IPV4_HDR_LEN]);
    f1[IPV4_HDR_LEN..].copy_from_slice(frag1_body);
    // Frag 2: offset 512 (=64 8-byte units), len rest, MF=0
    let frag2_body = &udp_buf[split..];
    let mut f2 = alloc::vec![0u8; IPV4_HDR_LEN + frag2_body.len()];
    let mut h2 = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Udp, frag2_body.len() as u16, 42);
    h2.flags_frag = (split as u16) / 8;  // MF=0, offset = 64
    h2.checksum = 0;
    h2.write_to(&mut tmp);
    h2.checksum = crate::ipv4::ip_checksum(&tmp);
    h2.write_to(&mut f2[..IPV4_HDR_LEN]);
    f2[IPV4_HDR_LEN..].copy_from_slice(frag2_body);
    // Deliver both fragments.
    stack.deliver_rx(id, &f1).unwrap();
    stack.deliver_rx(id, &f2).unwrap();
    // Receiver should see the full reassembled datagram.
    let (_src, _sp, _, _, _, body) = endpoint.recv(false).expect("reassembled UDP delivered");
    assert_eq!(body.len(), 1000);
    assert_eq!(body, payload);
}

// ----- F194: SO_LINGER abortive close -------------------------------

#[test]
fn f194_build_rst_probe_carries_rst_flag() {
    let mut c = client_established();
    let seg = c.build_keepalive_probe_with_flag(crate::tcp_hdr::flags::RST);
    // Flags byte at offset 13.
    assert!(seg[13] & 0x04 != 0, "RST flag set on linger=0 probe");
}

// ----- F193: TCP keepalive probes -----------------------------------

#[test]
fn f193_no_probe_before_idle_threshold() {
    let mut c = client_established();
    c.ka_enabled  = true;
    c.ka_idle_ns  = 1_000_000_000;
    c.last_rx_ns  = 0;
    assert!(c.keepalive_due(500_000_000).is_none(), "below threshold = no probe");
}

#[test]
fn f193_probe_fires_after_idle_threshold() {
    let mut c = client_established();
    c.ka_enabled  = true;
    c.ka_idle_ns  = 1_000_000_000;
    c.last_rx_ns  = 0;
    assert!(c.keepalive_due(2_000_000_000).is_some(), "past idle = probe");
    assert_eq!(c.ka_count, 1);
}

#[test]
fn f193_disabled_never_fires() {
    let mut c = client_established();
    c.ka_enabled = false;
    c.last_rx_ns = 0;
    assert!(c.keepalive_due(60_000_000_000_000).is_none());
}

#[test]
fn f193_probe_count_increments_per_call() {
    let mut c = client_established();
    c.ka_enabled  = true;
    c.ka_idle_ns  = 1_000_000_000;
    c.ka_intvl_ns = 100_000_000;
    c.last_rx_ns  = 0;
    let _ = c.keepalive_due(2_000_000_000).unwrap();
    let _ = c.keepalive_due(3_000_000_000).unwrap();
    let _ = c.keepalive_due(4_000_000_000).unwrap();
    assert_eq!(c.ka_count, 3);
}

// ----- F192: listen backlog cap + SO_REUSEPORT distribute -----------

#[test]
fn f192_default_backlog_is_128() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let le = stack.tcp_listen(Ipv4Addr::LOOPBACK, 7100, true).unwrap();
    assert_eq!(le.backlog.load(core::sync::atomic::Ordering::Acquire), 128);
}

#[test]
fn f192_set_backlog_clamps_to_somaxconn() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let le = stack.tcp_listen(Ipv4Addr::LOOPBACK, 7101, true).unwrap();
    le.set_backlog(99999, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(le.backlog.load(core::sync::atomic::Ordering::Acquire), crate::sysctl::DEFAULT_SOMAXCONN);
    le.set_backlog(0, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(le.backlog.load(core::sync::atomic::Ordering::Acquire), 0);
    le.set_backlog(-5, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(le.backlog.load(core::sync::atomic::Ordering::Acquire), crate::sysctl::DEFAULT_SOMAXCONN);
}

#[test]
fn f192_backlog_reservation_counts_half_open_children() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let le = stack.tcp_listen(Ipv4Addr::LOOPBACK, 7103, true).unwrap();
    le.set_backlog(1, crate::sysctl::DEFAULT_SOMAXCONN);
    assert!(le.reserve_backlog());
    assert!(!le.reserve_backlog());
    le.syn_backlog_used.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    assert!(le.reserve_backlog());
}

#[test]
fn f192_reuseport_allows_duplicate_listeners() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let le1 = stack.tcp_listen_ip_with(IpAddr::V4(Ipv4Addr::LOOPBACK), 7102, false, true).unwrap();
    let le2 = stack.tcp_listen_ip_with(IpAddr::V4(Ipv4Addr::LOOPBACK), 7102, false, true).unwrap();
    let le3 = stack.tcp_listen_ip_with(IpAddr::V4(Ipv4Addr::LOOPBACK), 7102, false, true).unwrap();
    assert!(!alloc::sync::Arc::ptr_eq(&le1, &le2));
    assert!(!alloc::sync::Arc::ptr_eq(&le2, &le3));
}

#[test]
fn f192_non_reuseport_blocks_duplicate() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    let _le1 = stack.tcp_listen(Ipv4Addr::LOOPBACK, 7103, true).unwrap();
    let err = stack.tcp_listen(Ipv4Addr::LOOPBACK, 7103, true).err().unwrap();
    assert_eq!(err, crate::netdev::NetError::Eaddrinuse);
}

// ----- F191: Path MTU Discovery -------------------------------------

#[test]
fn f191_v4_zero_mtu_uses_effective_floor_for_tcp_send_mss() {
    let _domain = crate::hosted_fixture::init_net_domain();
    // Build an ICMP frag-needed message: type=3 code=4 + MTU hint
    // in bytes 6..8, followed by orig IPv4 hdr + 8 L4 bytes.
    use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    // Set up a conn so PMTUD has someone to clamp.
    let entry = stack.tcp_connect(Ipv4Addr::LOOPBACK, 60000, Ipv4Addr::LOOPBACK, 80).unwrap();
    let quoted_seq = entry.conn.lock().snd_una;
    // Build the ICMP message.
    let mut icmp = alloc::vec![0u8; 8 + IPV4_HDR_LEN + 8];
    icmp[0] = 3;            // type = Destination Unreachable
    icmp[1] = 4;            // code = Fragmentation Needed
    icmp[6..8].copy_from_slice(&0u16.to_be_bytes());
    // Echo a v4 hdr describing the conn (src=us 50000→80).
    let h = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Tcp, 20 + 8, 0);
    h.write_to(&mut icmp[8..8 + IPV4_HDR_LEN]);
    let l4 = &mut icmp[8 + IPV4_HDR_LEN..];
    l4[0..2].copy_from_slice(&60_000u16.to_be_bytes());
    l4[2..4].copy_from_slice(&80u16.to_be_bytes());
    l4[4..8].copy_from_slice(&quoted_seq.to_be_bytes());
    // Fix the ICMP checksum.
    let cs = crate::ipv4::ip_checksum(&icmp);
    icmp[2..4].copy_from_slice(&cs.to_be_bytes());
    // Wrap in IPv4 and deliver.
    let total = IPV4_HDR_LEN + icmp.len();
    let mut frame = alloc::vec![0u8; total];
    let ip = Ipv4Hdr::build(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
        IpProto::Icmp, icmp.len() as u16, 1);
    ip.write_to(&mut frame[..IPV4_HDR_LEN]);
    frame[IPV4_HDR_LEN..].copy_from_slice(&icmp);
    stack.deliver_rx(id, &frame).unwrap();
    let _ = lo;
    assert_eq!(entry.conn.lock().own_mss, 512);
}

// ----- F190: ECN (RFC 3168) -----------------------------------------

#[test]
fn f190_active_open_syn_carries_ece_cwr() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let syn = c.active_open().unwrap();
    // TCP flags byte at offset 13.
    let flags = syn[13];
    assert!(flags & 0x40 != 0, "ECE must be set on ECN-negotiating SYN");
    assert!(flags & 0x80 != 0, "CWR must be set on ECN-negotiating SYN");
}

#[test]
fn f190_syn_ack_ece_only_enables_ecn() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    // Build SYN-ACK with ECE flag from scratch (proper checksum).
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
    let mut h = TcpHdr {
        src_port: 80, dst_port: 5000,
        seq: 0x2000_0000, ack: c.snd_nxt, data_offset: 5,
        flags: crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::ECE,
        window: 65535, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    let _ = c.input(lo_ip(), lo_ip(), &buf);
    assert!(c.ecn_enabled, "ECE-only SYN-ACK must enable ECN");
}

#[test]
fn f190_ece_triggers_one_loss_event_per_rtt() {
    let mut c = client_established();
    c.peer_mss = 1460;
    c.ecn_enabled = true;
    c.cwnd = 30_000;
    c.ssthresh = u32::MAX;
    crate::tcp_cc::on_ece(&mut c);
    let after = c.cwnd;
    assert!(after < 30_000, "ECN reduction must shrink cwnd");
    // Immediate second ECE within the rate-limit window: cwnd unchanged.
    crate::tcp_cc::on_ece(&mut c);
    assert_eq!(c.cwnd, after, "ECN rate-limit prevents double-reduce");
    assert!(c.send_cwr, "send_cwr armed");
}

// ----- F187: CUBIC congestion control -------------------------------

#[test]
fn f187_loss_sets_w_max_to_cwnd() {
    let mut c = client_established();
    c.peer_mss = 1460;
    c.cwnd = 30_000;
    c.cc_on_rto();
    assert_eq!(c.cubic_w_max, 30_000,
        "W_max snapshotted at the cwnd value at loss");
}

#[test]
fn f187_beta_07_not_05() {
    // CUBIC β=0.7 yields a bigger post-loss cwnd than Reno's /2,
    // making faster recovery on capacity probes.
    let mut c = client_established();
    c.peer_mss = 1460;
    c.cwnd = 100_000;
    c.cc_on_rto();
    // 100000 × 717/1024 = 70019. Way above Reno's 50000.
    assert!(c.ssthresh > 50_000 && c.ssthresh < 80_000);
}

#[test]
fn f187_icbrt_handles_small_inputs() {
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(0), 0);
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(1), 1);
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(8), 2);
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(27), 3);
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(125), 5);
    assert_eq!(crate::tcp_conn::TcpConn::icbrt_test(1000), 10);
}

// ----- F186: OWN_WSCALE=7 + recv-buf autotune -----------------------

#[test]
fn f186_own_wscale_advertised_is_7() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 1000);
    let syn = c.active_open().unwrap();
    assert_eq!(parse_wscale_option(&syn), Some(7));
}

#[test]
fn f186_current_rcv_window_scales_with_snd_wscale() {
    let mut c = client_established();
    c.snd_wscale = 7;
    c.rcv_buf_cap = 65536;
    // No data in recv_buf → free = 65536; advertised = 65536 >> 7 = 512.
    assert_eq!(c.current_rcv_window(), 512);
}

#[test]
fn f186_autotune_doubles_cap_when_peak_exceeds_half() {
    let mut c = client_established();
    c.rcv_buf_cap = 65_536;
    c.recv_buf.extend(core::iter::repeat(0u8).take(40_000));
    c.rcv_autotune();
    assert_eq!(c.rcv_buf_cap, 131_072);
}

#[test]
fn f186_autotune_caps_at_rcv_buf_max() {
    let mut c = client_established();
    c.rcv_buf_cap = 2 * 1024 * 1024;
    c.rcv_buf_max = 4 * 1024 * 1024;
    c.recv_buf.extend(core::iter::repeat(0u8).take(2 * 1024 * 1024 - 10));
    c.rcv_autotune();
    assert_eq!(c.rcv_buf_cap, 4 * 1024 * 1024, "cap clamps at max");
}

// ----- F185: TCP Reno congestion control ----------------------------

#[test]
fn f185_initial_cwnd_is_iw10() {
    let c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 1000);
    assert_eq!(c.cwnd, 10 * 1460,
        "RFC 6928 IW=10 init window in bytes");
    assert_eq!(c.ssthresh, u32::MAX);
}

#[test]
fn f185_slow_start_grows_cwnd_per_acked_byte() {
    let mut c = client_established();
    let before = c.cwnd;
    // Synthesize a cumulative ACK that newly acks 500 bytes.
    c.cc_on_ack(500, 0);
    assert_eq!(c.cwnd, before + 500,
        "slow-start cwnd += bytes_acked (capped at MSS)");
}

#[test]
fn f185_slow_start_caps_at_mss_per_ack() {
    let mut c = client_established();
    c.peer_mss = 1460;
    let before = c.cwnd;
    c.cc_on_ack(5_000, 0);
    assert_eq!(c.cwnd, before + 1460,
        "single-ACK growth capped at MSS");
}

#[test]
fn f185_three_dup_acks_fast_retransmit_halves_cwnd() {
    let mut c = client_established();
    c.peer_mss = 1460;
    c.cwnd = 20_000;
    c.ssthresh = u32::MAX;
    c.cc_on_ack(0, 0);
    c.cc_on_ack(0, 0);
    assert_eq!(c.dup_acks, 2);
    c.cc_on_ack(0, 0);
    assert_eq!(c.dup_acks, 3);
    // F187: CUBIC β=0.7 → 20000×717/1024 ≈ 14003.
    assert!(c.ssthresh >= 13_900 && c.ssthresh <= 14_100,
        "ssthresh ≈ cwnd·0.7 (CUBIC β), got {}", c.ssthresh);
    assert_eq!(c.cwnd, c.ssthresh + 3 * 1460);
}

#[test]
fn f185_rto_drops_cwnd_to_one_mss() {
    let mut c = client_established();
    c.peer_mss = 1460;
    c.cwnd = 20_000;
    c.cc_on_rto();
    assert_eq!(c.cwnd, 1460, "RTO drops cwnd to MSS");
    assert!(c.ssthresh >= 13_900 && c.ssthresh <= 14_100,
        "RTO ssthresh ≈ cwnd·0.7 (CUBIC β), got {}", c.ssthresh);
    assert_eq!(c.dup_acks, 0);
}

#[test]
fn f185_ca_phase_grows_non_negative() {
    // F187: CUBIC CA growth shape depends on tcp_now_ms epoch (stubbed
    // to 0 in hosted). cwnd must not shrink.
    let mut c = client_established();
    c.peer_mss = 1460;
    c.cwnd = 14_600;
    c.ssthresh = 14_600;
    let start = c.cwnd;
    for _ in 0..10 { c.cc_on_ack(1460, 0); }
    assert!(c.cwnd >= start);
}

// ----- F184: per-iface MTU → own_mss --------------------------------

#[test]
fn f184_mss_for_v4_loopback_subtracts_40() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // lo MTU = 65535; v4 overhead = 40 → MSS = 65495.
    assert_eq!(stack.mss_for_dst(IpAddr::V4(Ipv4Addr::LOOPBACK)), 65495);
}

#[test]
fn f184_mss_for_v6_loopback_subtracts_60() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::Ipv6Addr;
    let stack = NetStack::new();
    let _ = stack.register_loopback();
    // v6 overhead = 60 → 65475.
    assert_eq!(stack.mss_for_dst(IpAddr::V6(Ipv6Addr::LOOPBACK)), 65475);
}

#[test]
fn f184_active_open_syn_advertises_mtu_derived_mss() {
    let _domain = crate::hosted_fixture::init_net_domain();
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
