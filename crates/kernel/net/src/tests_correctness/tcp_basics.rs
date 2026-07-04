use super::*;
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
    assert_eq!(parse_wscale_option(&syn), Some(7),
        "active_open SYN must advertise WSCALE (F186: OWN_WSCALE=7)");
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

