use super::*;
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
