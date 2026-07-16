use super::*;
pub(super) fn ep(ip: Ipv4Addr, port: u16) -> Endpoint { Endpoint { ip: IpAddr::V4(ip), port } }

pub(super) fn lo() -> Ipv4Addr { Ipv4Addr::LOOPBACK }
pub(super) fn lo_ip() -> IpAddr { IpAddr::V4(Ipv4Addr::LOOPBACK) }

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
    let _ = c.output(1500, true, false);
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
    let _ = c.output(1500, true, false);
    // Force last_sent_ns to expire RTO; sacked must still skip.
    for s in c.retx_q.iter_mut() { s.last_sent_ns = 1; }
    c.retx_q[0].sacked = true;
    let resent = c.retransmit_due(1 + c.rto_ns + 1);
    assert_eq!(resent.len(), 1, "only the non-sacked entry retransmits");
}

// ----- F176: SO_REUSEADDR + TIME_WAIT conflict ----------------------

#[test]
fn f176_listen_without_reuseaddr_blocks_on_time_wait() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (_id, _lo) = stack.register_loopback();
    // Plant a conn at (LOOPBACK, 5000, _, _) via the public ctor,
    // then mutate its state to TimeWait through the entry Arc —
    // entry.conn is `pub` so no test-only accessor needed.
    let bind = stack.tcp_reserve(IpAddr::V4(lo()), 5000, None, true, false, 0, false).unwrap();
    let entry = stack.tcp_connect_reserved(&bind, IpAddr::V4(lo()),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 80,
        alloc::sync::Arc::new(crate::SocketError::new())).unwrap();
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
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (id, lo_dev) = stack.register_loopback();
    let _ = stack.tcp_listen(lo(), 80, true).unwrap();
    let entry = stack.tcp_connect(lo(), 50000, lo(), 80).unwrap();
    for _ in 0..3 { stack.drain_loopback(id, &lo_dev); }
    // After 3WHS: cap = 100 → first 100 bytes accepted, next call Eagain.
    let big: Vec<u8> = (0..200).map(|i| (i & 0xFF) as u8).collect();
    let n = stack.tcp_send(&entry, &big, 100, true, false).unwrap();
    assert_eq!(n, 100, "tcp_send capped at sndbuf_cap=100");
    let err = stack.tcp_send(&entry, &big, 100, true, false).err().unwrap();
    assert_eq!(err, NetError::Eagain,
        "tcp_send at-cap must return Eagain (caller blocks / O_NONBLOCK)");
}

// ----- F165: output() drains multi-segment + retx_q single-source ---

#[test]
fn f165_output_drains_send_buf_into_multiple_segments() {
    let mut c = client_established();
    c.peer_mss = 100;  // force MSS=100 so 350 bytes → 4 segs
    c.send(&[0u8; 350]);
    let segs = c.output(1500, true, false);
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
    let _ = c.output(1500, true, false);
    assert!(c.send_buf.is_empty());
    let in_flight: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
    assert_eq!(in_flight, 3);
}

#[test]
fn tcp_cork_holds_partial_segment_until_uncork() {
    let mut c = client_established();
    c.peer_mss = 100;
    c.send(&[1u8; 50]);
    assert!(c.output(1500, true, true).is_empty());
    assert_eq!(c.send_buf.len(), 50);
    c.send(&[2u8; 100]);
    let segs = c.output(1500, true, true);
    assert_eq!(segs.len(), 1);
    assert_eq!(c.send_buf.len(), 50);
    let tail = c.output(1500, true, false);
    assert_eq!(tail.len(), 1);
    assert!(c.send_buf.is_empty());
}

// ----- F178: snd_wnd bounds output ----------------------------------

#[test]
fn f178_output_respects_peer_window() {
    let mut c = client_established();
    c.snd_wnd = 50;  // peer offers only 50 bytes
    c.peer_mss = 100;
    c.send(&[0u8; 200]);
    let segs = c.output(1500, true, false);
    let bytes_emitted: usize = segs.iter().map(|s| s.len() - TCP_HDR_MIN_LEN).sum();
    assert!(bytes_emitted <= 50, "must not exceed snd_wnd; got {bytes_emitted}");
}

// ----- helpers -------------------------------------------------------

pub(super) fn build_synack_with_options(
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

pub(super) fn build_plain_ack(peer_seq: u32, peer_ack: u32, window: u16) -> Vec<u8> {
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

pub(super) fn build_data_segment(seq: u32, peer_ack: u32, payload: &[u8]) -> Vec<u8> {
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

pub(super) fn client_established() -> TcpConn {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), None);
    let _ = c.input(lo_ip(), lo_ip(), &synack);
    assert_eq!(c.state, TcpState::Established);
    c
}
