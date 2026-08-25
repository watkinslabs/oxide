use super::*;

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
    let normal = server.recv_with_offset_oob(3, false, 0, false,
        |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap();
    assert_eq!(normal, Some(b"a".to_vec()));
    assert!(server.at_urgent_mark());
    assert_eq!(server.take_urgent(), Some((seq + 1, b'b')));
    assert!(!server.has_urgent());
}

#[test]
fn repeated_urg_replaces_unconsumed_urgent_byte() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5003), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    let seq = server.rcv_nxt;
    for (seq, payload, urg_ptr) in [(seq, b"abc".as_slice(), 2),
        (seq + 3, b"xyz".as_slice(), 1)] {
        let mut hdr = crate::tcp_hdr::TcpHdr { src_port: 5003, dst_port: 80,
            seq, ack: 0, data_offset: 5, flags: crate::tcp_hdr::flags::ACK
                | crate::tcp_hdr::flags::URG, window: 65535, checksum: 0, urg_ptr };
        let mut wire = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
        hdr.build_into(lo, lo, &mut wire[..crate::tcp_hdr::TCP_HDR_MIN_LEN]);
        wire[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
        let _ = server.input_prevalidated(lo_ip(), lo_ip(), &wire).unwrap();
    }
    assert_eq!(server.take_urgent(), Some((seq + 3, b'x')));
}

#[test]
fn oobinline_consumes_urgent_byte_without_later_oob_duplicate() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5005), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    let seq = server.rcv_nxt;
    let payload = b"abc";
    let mut hdr = crate::tcp_hdr::TcpHdr { src_port: 5005, dst_port: 80,
        seq, ack: 0, data_offset: 5, flags: crate::tcp_hdr::flags::ACK
            | crate::tcp_hdr::flags::URG, window: 65535, checksum: 0, urg_ptr: 2 };
    let mut wire = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
    hdr.build_into(lo, lo, &mut wire[..crate::tcp_hdr::TCP_HDR_MIN_LEN]);
    wire[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
    let _ = server.input_prevalidated(lo_ip(), lo_ip(), &wire).unwrap();

    let inline = server.recv_with_offset_oob(3, false, 0, true,
        |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap();
    assert_eq!(inline, Some(b"abc".to_vec()));
    assert!(!server.has_urgent());
    assert!(!server.at_urgent_mark());
}

#[test]
fn out_of_order_urgent_waits_for_stream_gap_before_publication() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5004), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();
    let seq = server.rcv_nxt;

    let make = |seq: u32, payload: &[u8], urg_ptr: u16| {
        let mut hdr = crate::tcp_hdr::TcpHdr { src_port: 5004, dst_port: 80,
            seq, ack: 0, data_offset: 5,
            flags: crate::tcp_hdr::flags::ACK
                | if urg_ptr != 0 { crate::tcp_hdr::flags::URG } else { 0 },
            window: 65535, checksum: 0, urg_ptr };
        let mut wire = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + payload.len()];
        hdr.build_into(lo, lo, &mut wire[..crate::tcp_hdr::TCP_HDR_MIN_LEN]);
        wire[crate::tcp_hdr::TCP_HDR_MIN_LEN..].copy_from_slice(payload);
        wire
    };

    let ooo = make(seq.wrapping_add(1), b"bc", 1);
    let _ = server.input_prevalidated(lo_ip(), lo_ip(), &ooo).unwrap();
    assert!(!server.has_urgent(), "URG must not bypass an unfilled receive gap");
    assert_eq!(server.rcv_ooopack, 1);

    let first = make(seq, b"a", 0);
    let _ = server.input_prevalidated(lo_ip(), lo_ip(), &first).unwrap();
    assert_eq!(server.bytes_received, 3, "bytes count when the gap becomes contiguous");
    assert_eq!(server.take_urgent(), Some((seq.wrapping_add(1), b'b')));
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
