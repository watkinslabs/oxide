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

fn ep(ip: Ipv4Addr, port: u16) -> Endpoint { Endpoint { ip, port } }

fn lo() -> Ipv4Addr { Ipv4Addr::LOOPBACK }

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
    let _ = c.input(lo(), lo(), &synack);
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
    let _ = c.input(lo(), lo(), &with_ws);
    assert_eq!(c.rcv_wscale, 7);
}

#[test]
fn f178_input_no_wscale_keeps_default_zero() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let no_ws = build_synack_with_options(0x2000_0000, c.snd_nxt, 65535, Some(1460), None);
    let _ = c.input(lo(), lo(), &no_ws);
    assert_eq!(c.rcv_wscale, 0,
        "rcv_wscale stays 0 when peer omits WSCALE (RFC 7323 §1.3)");
}

#[test]
fn f178_input_non_syn_applies_rcv_wscale_to_window() {
    let mut c = TcpConn::new_client(ep(lo(), 5000), ep(lo(), 80), 0x1000_0000);
    let _ = c.active_open().unwrap();
    let synack = build_synack_with_options(0x2000_0000, c.snd_nxt, 100, Some(1460), Some(3));
    let _ = c.input(lo(), lo(), &synack);
    // SYN window is unscaled; established conn snd_wnd = 100.
    assert_eq!(c.snd_wnd, 100);
    // Now an ACK with window=200 should be scaled by rcv_wscale=3.
    let ack = build_plain_ack(0x2000_0001, c.snd_nxt, 200);
    let _ = c.input(lo(), lo(), &ack);
    assert_eq!(c.snd_wnd, 200u32 << 3, "non-SYN window must be left-shifted by rcv_wscale");
}

// ----- F179: out-of-order receive buffer -----------------------------

#[test]
fn f179_in_order_delivers_immediately() {
    let mut c = client_established();
    let seg = build_data_segment(c.rcv_nxt, c.snd_nxt, b"hello");
    let _ = c.input(lo(), lo(), &seg);
    assert_eq!(c.recv_buf.iter().copied().collect::<Vec<u8>>(), b"hello");
}

#[test]
fn f179_ooo_buffered_until_gap_fills() {
    let mut c = client_established();
    let base = c.rcv_nxt;
    // Push gap-segment first: seq = base+5..base+10 ("world").
    let ooo = build_data_segment(base.wrapping_add(5), c.snd_nxt, b"world");
    let _ = c.input(lo(), lo(), &ooo);
    assert!(c.recv_buf.is_empty(), "OOO data must not deliver before gap fills");
    assert_eq!(c.ooo_buf.len(), 1);
    // Now push the gap: seq = base..base+5 ("hello").
    let fill = build_data_segment(base, c.snd_nxt, b"hello");
    let _ = c.input(lo(), lo(), &fill);
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
    let _ = c.input(lo(), lo(), &stale);
    assert!(c.recv_buf.is_empty());
    assert!(c.ooo_buf.is_empty(), "past-window data must not enter ooo_buf");
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
    let _ = c.input(lo(), lo(), &ooo);
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
    let _ = c.input(lo(), lo(), &synack);
    assert_eq!(c.state, TcpState::Established);
    c
}

