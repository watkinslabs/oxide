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
fn urgent_flag_records_latest_urgent_byte_for_oob_owner() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5002), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    let seq = server.rcv_nxt;
    let payload = b"abc";
    let mut hdr = crate::tcp_hdr::TcpHdr { src_port: 5002, dst_port: 80,
        seq, ack: 0, data_offset: 5, flags: crate::tcp_hdr::flags::ACK
            | crate::tcp_hdr::flags::URG, window: 65535, checksum: 0, urg_ptr: 2 };
    let mut wire = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
    hdr.build_into(lo, lo, &mut wire[..crate::tcp_hdr::TCP_HDR_MIN_LEN]);
    wire[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
    let _ = server.input_prevalidated(lo_ip(), lo_ip(), &wire).unwrap();
    assert!(!server.at_urgent_mark());
    assert_eq!(server.recv(1), b"a");
    assert!(server.at_urgent_mark());
    assert_eq!(server.take_urgent(), Some((seq + 1, b'b')));
    assert!(!server.has_urgent());
}

#[test]
fn urgent_send_emits_one_urg_segment_and_tracks_retransmission() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5003), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    let before = client.snd_nxt;
    let wire = client.send_urgent(b'!');
    let hdr = crate::tcp_hdr::parse_prevalidated(&wire).unwrap();
    assert_eq!(hdr.seq, before);
    assert_eq!(hdr.flags & crate::tcp_hdr::flags::URG, crate::tcp_hdr::flags::URG);
    assert_eq!(hdr.urg_ptr, 1);
    assert_eq!(&wire[hdr.payload_offset()..], b"!");
    assert_eq!(client.retx_q.back().unwrap().payload, b"!");
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

#[test]
fn recv_with_fault_and_peek_preserve_stream_bytes() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    conn.recv_buf.extend(b"transaction".iter().copied());
    assert!(matches!(conn.recv_with(64, false, |_| Err::<((), usize), _>(7u8)), Err(7)));
    let partial = conn.recv_with(64, false, |bytes| Ok::<_, ()>((bytes[..4].to_vec(), 4))).unwrap().unwrap();
    assert_eq!(partial, b"tran");
    let peeked = conn.recv_with(64, true, |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap().unwrap();
    assert_eq!(peeked, b"saction");
    let consumed = conn.recv_with(64, false, |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap().unwrap();
    assert_eq!(consumed, b"saction");
    assert!(conn.recv_buf.is_empty());
}

#[test]
fn peek_offset_reads_waitall_suffix_without_consuming() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5001), ep(lo, 80), 1000);
    conn.recv_buf.extend(b"abcdef".iter().copied());
    let first = conn.recv_with_offset(3, true, 0, |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap().unwrap();
    let second = conn.recv_with_offset(3, true, 3, |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap().unwrap();
    assert_eq!(first, b"abc");
    assert_eq!(second, b"def");
    assert_eq!(conn.recv(6), b"abcdef");
}
