// Rebuilding a connection from a cookie, at the state-machine level: the
// reconstructed request has to be indistinguishable from one the listener held
// all along, because the acknowledgement completing it is processed by the
// same code either way.

use super::*;
use crate::addr::{IpAddr, Ipv4Addr};
use crate::syncookies::{Decoded, Rebuild};
use crate::tcp_conn::Endpoint;
use crate::tcp_hdr::{flags, TcpHdr};

const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const SERVER_PORT: u16 = 443;
const CLIENT_PORT: u16 = 45_123;
const COOKIE: u32 = 0x5a5a_1234;
const PEER_ISN: u32 = 0x1111_0000;

fn rebuild(opts: Decoded) -> Rebuild {
    Rebuild {
        isn: COOKIE, peer_isn: PEER_ISN, mss: 1440, opts,
        ts_recent: 0x0708_0900, ts_off: 0, window: 8_192,
    }
}

/// The acknowledgement a peer sends to finish a cookie handshake.
fn ack(payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
    buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
    let mut hdr = TcpHdr {
        src_port: CLIENT_PORT, dst_port: SERVER_PORT,
        seq: PEER_ISN.wrapping_add(1), ack: COOKIE.wrapping_add(1),
        data_offset: (crate::tcp_hdr::TCP_HDR_MIN_LEN / 4) as u8,
        flags: flags::ACK, window: 8_192, checksum: 0, urg_ptr: 0,
    };
    hdr.build_into_ip(SERVER, CLIENT, &mut buf);
    buf
}

fn opened(opts: Decoded) -> TcpConn {
    let mut conn = TcpConn::new_listener(Endpoint { ip: SERVER, port: SERVER_PORT });
    conn.open_from_cookie(CLIENT, CLIENT_PORT, &rebuild(opts));
    conn
}

#[test]
fn the_rebuilt_request_sits_exactly_where_the_vanished_syn_ack_left_it() {
    let conn = opened(Decoded::default());
    assert_eq!(conn.state, crate::tcp_state::TcpState::SynRecv);
    // The cookie was the sequence number sent, and the SYN flag consumed one
    // past it; getting this wrong makes the peer's acknowledgement look like
    // it covers a segment nobody sent.
    assert_eq!((conn.snd_una, conn.snd_nxt), (COOKIE, COOKIE.wrapping_add(1)));
    assert_eq!(conn.rcv_nxt, PEER_ISN.wrapping_add(1));
    assert_eq!(conn.peer_mss, 1440);
    assert_eq!(conn.remote, Endpoint { ip: CLIENT, port: CLIENT_PORT });
    // Nothing is queued for retransmit: there is no request being timed out,
    // because there never was one.
    assert!(conn.retx_q.is_empty());
}

#[test]
fn the_acknowledgement_that_carried_the_cookie_completes_the_handshake() {
    let mut conn = opened(Decoded::default());
    let resp = conn.input(CLIENT, SERVER, &ack(&[])).expect("the acknowledgement is accepted");
    assert_eq!(conn.state, crate::tcp_state::TcpState::Established);
    assert!(resp.is_none(), "a bare acknowledgement needs no answer");
    assert_eq!(conn.snd_una, COOKIE.wrapping_add(1));
}

#[test]
fn an_acknowledgement_carrying_data_delivers_it() {
    // A client that writes its request immediately puts the bytes on the third
    // acknowledgement. Rebuilding the request and then feeding it the same
    // segment is what keeps that working without a second code path.
    let mut conn = opened(Decoded::default());
    conn.input(CLIENT, SERVER, &ack(b"GET / HTTP/1.1\r\n")).expect("accepted");
    assert_eq!(conn.state, crate::tcp_state::TcpState::Established);
    assert_eq!(conn.recv_buf.len, 16);
}

#[test]
fn the_options_the_timestamp_carried_back_are_installed() {
    let opts = Decoded { tstamp_ok: true, sack_ok: true, wscale: Some(7), ecn_ok: true };
    let conn = opened(opts);
    assert!(conn.ts_enabled);
    assert_eq!(conn.ts_recent, 0x0708_0900);
    assert!(conn.wscale_ok);
    assert_eq!(conn.rcv_wscale, 7);
    assert_eq!(conn.snd_wscale, crate::tcp_conn::OWN_WSCALE);
    assert!(conn.sack_ok);
    assert!(conn.ecn_enabled);
    // The peer's window is scaled by the scale IT announced, so a rebuild that
    // dropped the scale would under-read the peer's window by 128x.
    assert_eq!(conn.snd_wnd, 8_192 << 7);
}

#[test]
fn a_handshake_that_negotiated_nothing_installs_nothing() {
    let conn = opened(Decoded::default());
    assert!(!conn.ts_enabled);
    assert!(!conn.wscale_ok);
    assert!(!conn.sack_ok);
    assert!(!conn.ecn_enabled);
    assert_eq!(conn.rcv_wscale, 0);
    assert_eq!(conn.snd_wnd, 8_192);
}

#[test]
fn a_cookie_syn_ack_smuggles_the_options_into_its_timestamp() {
    // The emit side of the same contract: the SYN-ACK this side sends has to
    // carry the negotiation, because nothing else will remember it.
    let mut conn = TcpConn::new_listener(Endpoint { ip: SERVER, port: SERVER_PORT });
    conn.set_syncookie(crate::syncookies::Request { isn: COOKIE, mss: 1440 });
    conn.ts_enabled = true;
    conn.wscale_ok = true;
    conn.rcv_wscale = 6;
    conn.sack_ok = true;
    conn.ecn_enabled = false;
    let opts = conn.syn_options(flags::SYN | flags::ACK);
    let (tsval, _) = opts.timestamp.expect("a cookie SYN-ACK carries a timestamp");
    let decoded = crate::syncookies::tsopt::decode(true, tsval, crate::syncookies::Permitted::ALL)
        .expect("permitted");
    assert_eq!(decoded.wscale, Some(6));
    assert!(decoded.sack_ok);
    assert!(!decoded.ecn_ok);
}

#[test]
fn an_ordinary_syn_ack_carries_the_plain_clock() {
    // Only a cookie handshake spends the low bits; every other segment's
    // timestamp has to remain a timestamp.
    let mut conn = TcpConn::new_listener(Endpoint { ip: SERVER, port: SERVER_PORT });
    conn.ts_enabled = true;
    conn.ts_off = 0x1000;
    let (tsval, _) = conn.syn_options(flags::SYN | flags::ACK).timestamp.expect("timestamp");
    assert_eq!(tsval, crate::tcp_conn::tcp_now_ms().wrapping_add(0x1000));
}
