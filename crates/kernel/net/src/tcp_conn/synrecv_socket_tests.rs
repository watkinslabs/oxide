// The acceptability gate a full socket in SYN-RECEIVED applies to an
// acknowledgement, driven through the real input path.

use super::*;
use crate::addr::{IpAddr, Ipv4Addr};
use crate::tcp_conn::Endpoint;

fn ep(port: u16) -> Endpoint { Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port } }
fn lo() -> IpAddr { IpAddr::V4(Ipv4Addr::LOOPBACK) }

fn head(seg: &[u8]) -> crate::tcp_hdr::TcpHdr {
    crate::tcp_hdr::TcpHdr::parse(seg, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK).expect("header")
}

/// A listener that has answered a SYN and is waiting for the handshake to
/// finish, plus the sequence its SYN-ACK carried.
fn half_open() -> (TcpConn, u32) {
    let mut client = TcpConn::new_client(ep(5_000), ep(80), 1_000);
    let mut server = TcpConn::new_listener(ep(80));
    let syn = client.active_open().expect("SYN");
    let synack = server.input(lo(), lo(), &syn).expect("input").expect("SYN-ACK");
    let seq = head(&synack).seq;
    assert_eq!(server.state, TcpState::SynRecv);
    (server, seq)
}

fn bare_ack(seq: u32, ack: u32) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    crate::tcp_hdr::TcpHdr {
        src_port: 5_000, dst_port: 80, seq, ack, data_offset: 5,
        flags: flags::ACK, window: 65_535, checksum: 0, urg_ptr: 0,
    }.build_into(Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, &mut buf);
    buf
}

#[test]
fn a_socket_in_syn_received_establishes_on_the_acknowledgement_of_its_syn_ack() {
    let (mut server, synack_seq) = half_open();
    let rcv_nxt = server.rcv_nxt;
    let resp = server.input(lo(), lo(), &bare_ack(rcv_nxt, synack_seq.wrapping_add(1)))
        .expect("input");
    assert!(resp.is_none());
    assert_eq!(server.state, TcpState::Established);
}

#[test]
fn a_socket_in_syn_received_refuses_an_acknowledgement_of_what_it_never_sent() {
    // Without this gate a segment that guessed the 4-tuple and the receive
    // window established a connection whose acknowledgement named a sequence
    // this side never put on the wire, and `snd_una` was advanced to it
    // (B2050).
    let (mut server, synack_seq) = half_open();
    let rcv_nxt = server.rcv_nxt;
    let snd_una = server.snd_una;
    let forged = synack_seq.wrapping_add(9_000);
    let resp = server.input(lo(), lo(), &bare_ack(rcv_nxt, forged)).expect("input");

    assert_eq!(server.state, TcpState::SynRecv, "the handshake did not finish");
    assert_eq!(server.snd_una, snd_una, "nothing was marked acknowledged");
    let rst = head(&resp.expect("one reset answers it"));
    assert_eq!(rst.flags & (flags::RST | flags::ACK), flags::RST,
        "the answer is one reset, not a challenge acknowledgement");
    assert_eq!(rst.seq, forged, "the reset is built at the sequence the segment claimed");
}

#[test]
fn a_socket_in_syn_received_refuses_an_acknowledgement_older_than_its_send_una() {
    let (mut server, synack_seq) = half_open();
    let rcv_nxt = server.rcv_nxt;
    let resp = server.input(lo(), lo(), &bare_ack(rcv_nxt, synack_seq.wrapping_sub(1)))
        .expect("input");
    assert_eq!(server.state, TcpState::SynRecv);
    assert!(resp.is_some(), "a stale acknowledgement in a half-open state is reset");
}
