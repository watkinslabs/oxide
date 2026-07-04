#![allow(dead_code)]

use super::*;

fn ep(ip: crate::addr::Ipv4Addr, port: u16) -> Endpoint {
    Endpoint {
        ip: crate::addr::IpAddr::V4(ip),
        port,
    }
}

fn lo_ip() -> crate::addr::IpAddr {
    crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::LOOPBACK)
}

#[test]
fn three_way_handshake_completes() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));

    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().expect("SYN-ACK");
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().expect("ACK");
    let resp = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    assert!(resp.is_none());

    assert_eq!(client.state, crate::tcp_state::TcpState::Established);
    assert_eq!(server.state, crate::tcp_state::TcpState::Established);
}

#[test]
fn data_round_trip_after_handshake() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();

    client.send(b"oxide-tcp");
    let segs = client.output(1500, true, false);
    assert_eq!(segs.len(), 1);
    let server_ack = server.input(lo_ip(), lo_ip(), &segs[0]).unwrap().unwrap();
    let _ = client.input(lo_ip(), lo_ip(), &server_ack).unwrap();

    let got = server.recv(64);
    assert_eq!(&got[..], b"oxide-tcp");
}

#[test]
fn graceful_close_local_then_remote() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();

    let fin = client.local_close().unwrap();
    assert_eq!(client.state, crate::tcp_state::TcpState::FinWait1);
    let server_ack = server.input(lo_ip(), lo_ip(), &fin).unwrap().unwrap();
    let server_fin = server.local_close().unwrap();
    assert_eq!(server.state, crate::tcp_state::TcpState::LastAck);
    let client_ack = client.input(lo_ip(), lo_ip(), &server_fin).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &client_ack).unwrap();
    assert_eq!(server.state, crate::tcp_state::TcpState::Closed);
    let _ = server_ack;
}

#[test]
fn retransmit_due_re_emits_after_rto() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _ = c.active_open().unwrap();
    assert_eq!(c.retransmit_due(0).len(), 0);
    assert_eq!(c.retransmit_due(2_000_000_000).len(), 1, "after 2s, SYN re-emitted");
    assert!(c.rto_ns >= 2_000_000_000);
}

#[test]
fn ack_clears_retx_queue() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    assert_eq!(client.retx_q.len(), 1);
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let _ = client.input(lo_ip(), lo_ip(), &synack).unwrap();
    assert_eq!(client.retx_q.len(), 0);
}

#[test]
fn update_rtt_smooths() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 1), ep(lo, 2), 0);
    c.update_rtt(50_000_000);
    let r1 = c.rto_ns;
    c.update_rtt(60_000_000);
    let r2 = c.rto_ns;
    assert!(r1 >= 200_000_000 && r1 <= 60_000_000_000);
    assert!(r2 >= 200_000_000 && r2 <= 60_000_000_000);
    assert!(c.srtt_ns > 0);
}

#[test]
fn rst_jumps_to_closed() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _ = conn.active_open().unwrap();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut h = crate::tcp_hdr::TcpHdr {
        src_port: 80,
        dst_port: 5000,
        seq: 0,
        ack: 1001,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::RST,
        window: 0,
        checksum: 0,
        urg_ptr: 0,
    };
    h.build_into(lo, lo, &mut buf);
    let _ = conn.input(lo_ip(), lo_ip(), &buf);
    assert_eq!(conn.state, crate::tcp_state::TcpState::Closed);
}
