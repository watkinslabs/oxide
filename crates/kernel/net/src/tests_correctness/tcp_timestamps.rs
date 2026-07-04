use super::*;
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
    let segs = c.output(1500, true, false);
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
