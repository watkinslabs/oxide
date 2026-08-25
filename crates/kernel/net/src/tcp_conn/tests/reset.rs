use super::*;

#[test]
fn rst_without_ack_is_ignored_in_syn_sent() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _ = conn.active_open().unwrap();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut h = crate::tcp_hdr::TcpHdr {
        src_port: 80,
        dst_port: 5000,
        seq: 0,
        ack: 0,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::RST,
        window: 0,
        checksum: 0,
        urg_ptr: 0,
    };
    h.build_into(lo, lo, &mut buf);
    assert_eq!(conn.input(lo_ip(), lo_ip(), &buf).unwrap(), None);
    assert_eq!(conn.state, crate::tcp_state::TcpState::SynSent);
}

#[test]
fn valid_rst_closes_syn_sent() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _ = conn.active_open().unwrap();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut h = crate::tcp_hdr::TcpHdr {
        src_port: 80, dst_port: 5000, seq: 0, ack: 1001,
        data_offset: 5, flags: crate::tcp_hdr::flags::RST | crate::tcp_hdr::flags::ACK,
        window: 0, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo, lo, &mut buf);
    assert!(matches!(conn.input(lo_ip(), lo_ip(), &buf),
        Err(crate::tcp_conn::TcpConnError::Reset)));
    assert_eq!(conn.state, crate::tcp_state::TcpState::Closed);
}
#[test]
fn stale_rst_is_ignored_in_established() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    conn.state = crate::tcp_state::TcpState::Established;
    conn.rcv_nxt = 10_000;
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut h = crate::tcp_hdr::TcpHdr {
        src_port: 80, dst_port: 5000, seq: 9_000, ack: 0,
        data_offset: 5, flags: crate::tcp_hdr::flags::RST,
        window: 0, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo, lo, &mut buf);
    assert_eq!(conn.input(lo_ip(), lo_ip(), &buf).unwrap(), None);
    assert_eq!(conn.state, crate::tcp_state::TcpState::Established);
}

#[test]
fn rst_sequence_acceptance_wraps_at_u32_boundary() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut conn = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    conn.state = crate::tcp_state::TcpState::Established;
    conn.rcv_nxt = u32::MAX - 4;
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    let mut h = crate::tcp_hdr::TcpHdr {
        src_port: 80, dst_port: 5000, seq: 2, ack: 0,
        data_offset: 5, flags: crate::tcp_hdr::flags::RST,
        window: 0, checksum: 0, urg_ptr: 0,
    };
    h.build_into(lo, lo, &mut buf);
    assert!(matches!(conn.input(lo_ip(), lo_ip(), &buf),
        Err(crate::tcp_conn::TcpConnError::Reset)));
    assert_eq!(conn.state, crate::tcp_state::TcpState::Closed);
}
