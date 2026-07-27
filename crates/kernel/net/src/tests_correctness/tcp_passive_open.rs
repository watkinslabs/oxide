// B1454: passive open's third ACK. Linux `tcp_rcv_state_process`
// (`net/ipv4/tcp_input.c:7200-7253`) runs `tcp_ack` — hence
// `tcp_clean_rtx_queue` — BEFORE the `case TCP_SYN_RECV:` arm, and that arm
// then installs `tp->snd_una` AND
// `tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale`.
//
// Skipping the retransmit-queue trim leaves the SYN-ACK unacked forever, so
// `output`'s Nagle guard (`!nodelay && !retx_q.is_empty() && send_buf < mss`)
// holds every sub-MSS write on an accepted socket until some unrelated inbound
// segment triggers the `nodelay=true` post-input drain. That is the
// `tcp_recv_sarestart` differential divergence: a parked TCP receiver is never
// roused because the peer's bytes are never transmitted.

use super::*;

const PEER_SEQ: u32 = 0x3000_0000;
const PEER_WSCALE: u8 = 7;
const THIRD_ACK_WINDOW: u16 = 501;

fn build_syn(seq: u32, window: u16, wscale: Option<u8>) -> Vec<u8> {
    let opts_len = 4 + if wscale.is_some() { 4 } else { 0 };
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + opts_len];
    let mut i = TCP_HDR_MIN_LEN;
    buf[i] = opt::MSS; buf[i + 1] = 4;
    buf[i + 2..i + 4].copy_from_slice(&1460u16.to_be_bytes());
    i += 4;
    if let Some(s) = wscale {
        buf[i] = opt::NOP; i += 1;
        buf[i] = opt::WSCALE; buf[i + 1] = 3; buf[i + 2] = s;
    }
    let mut h = TcpHdr {
        src_port: 5000, dst_port: 80,
        seq, ack: 0,
        data_offset: ((TCP_HDR_MIN_LEN + opts_len) / 4) as u8,
        flags: crate::tcp_hdr::flags::SYN,
        window, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

fn build_third_ack(seq: u32, ack: u32, window: u16) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
    let mut h = TcpHdr {
        src_port: 5000, dst_port: 80,
        seq, ack,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::ACK,
        window, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo(), lo(), &mut buf);
    buf
}

/// Drive `Listen -> SynRecv -> Established` the way the demux does.
fn passive_established() -> TcpConn {
    let mut c = TcpConn::new_listener(ep(lo(), 80));
    let syn = build_syn(PEER_SEQ, 65535, Some(PEER_WSCALE));
    let synack = c.input(lo_ip(), lo_ip(), &syn).expect("SYN accepted");
    assert!(synack.is_some(), "passive open answers the SYN with a SYN-ACK");
    assert_eq!(c.state, TcpState::SynRecv);
    assert_eq!(c.retx_q.len(), 1, "the SYN-ACK is queued for retransmission");
    let third = build_third_ack(PEER_SEQ.wrapping_add(1), c.snd_nxt, THIRD_ACK_WINDOW);
    let _ = c.input(lo_ip(), lo_ip(), &third).expect("third ACK accepted");
    assert_eq!(c.state, TcpState::Established);
    c
}

#[test]
fn b1454_third_ack_retires_the_syn_ack_from_the_retransmit_queue() {
    let c = passive_established();
    assert!(c.retx_q.is_empty(),
        "`tcp_ack` runs before the TCP_SYN_RECV arm: the third ACK acknowledges \
         the SYN-ACK, so an established passive conn owns no unacked bytes");
    assert_eq!(c.snd_una, c.snd_nxt, "everything sent has been acknowledged");
}

#[test]
fn b1454_third_ack_installs_the_peer_scaled_send_window() {
    let c = passive_established();
    // `tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale` — the SYN's
    // window was unscaled, the third ACK's is scaled by the peer's factor.
    assert_eq!(c.snd_wnd, (THIRD_ACK_WINDOW as u32) << PEER_WSCALE);
}

#[test]
fn b1454_nagle_does_not_hold_the_first_write_on_an_accepted_conn() {
    let mut c = passive_established();
    c.send(b"hello");
    // nodelay=false is the default socket state the differential probe uses.
    // With no unacknowledged data in flight, Nagle must transmit immediately.
    let segs = c.output(1500, false, false);
    assert_eq!(segs.len(), 1,
        "an idle conn has nothing in flight, so Nagle cannot hold a sub-MSS write");
    assert!(c.send_buf.is_empty(), "output must drain the accepted bytes");
}

#[test]
fn b1454_loopback_accepted_socket_delivers_a_small_nagle_write() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev) = stack.register_loopback();
    let listener = stack.tcp_listen(lo(), 93, true).unwrap();
    let client = stack.tcp_connect(lo(), 50_093, lo(), 93).unwrap();
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    let server = stack.tcp_accept(&listener).expect("three-way handshake accepted");
    assert!(server.conn.lock().retx_q.is_empty(),
        "accepted socket must start with an empty retransmit queue");
    // The `wait_diff` `tcp_recv_sarestart` shape: the accepting side writes a
    // 5-byte payload through the default (Nagle-on) path.
    assert_eq!(stack.tcp_send(&server, b"hello", 65_536, false, false), Ok(5));
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    assert_eq!(stack.tcp_recv(&client, 64), b"hello");
}
