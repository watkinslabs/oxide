use super::*;

#[test]
fn recv_with_fault_and_peek_preserve_stream_bytes() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    conn.recv_buf.push_payload(b"transaction", 0);
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
    conn.recv_buf.push_payload(b"abcdef", 0);
    let first = conn.recv_with_offset(3, true, 0, |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap().unwrap();
    let second = conn.recv_with_offset(3, true, 3, |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap().unwrap();
    assert_eq!(first, b"abc");
    assert_eq!(second, b"def");
    assert_eq!(conn.recv(6), b"abcdef");
}

#[test]
fn receive_timestamp_follows_the_first_unread_segment() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5002), ep(lo, 80), 1000);
    conn.state = crate::tcp_state::TcpState::Established;
    conn.rcv_nxt = 7_000;
    conn.snd_nxt = conn.rcv_nxt;
    let first = conn.build_segment(crate::tcp_hdr::flags::ACK, b"abc");
    let _ = conn.input_prevalidated_at(lo_ip(), lo_ip(), &first, 111).unwrap();
    assert_eq!(conn.recv_timestamp(), Some(111));
    conn.snd_nxt = conn.rcv_nxt;
    let second = conn.build_segment(crate::tcp_hdr::flags::ACK, b"def");
    let _ = conn.input_prevalidated_at(lo_ip(), lo_ip(), &second, 222).unwrap();
    assert_eq!(conn.recv_timestamp(), Some(111));
    assert_eq!(conn.recv(3), b"abc");
    assert_eq!(conn.recv_timestamp(), Some(222));
}

// ---- what a passive open records off the opening header -------------------

