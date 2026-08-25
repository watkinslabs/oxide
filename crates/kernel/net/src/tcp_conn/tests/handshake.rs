use super::*;

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
    assert_eq!(server.segs_in, 3, "SYN, completing ACK, and data each count once");
    assert_eq!(server.bytes_received, b"oxide-tcp".len() as u64);
    assert_eq!(client.bytes_acked, 1 + b"oxide-tcp".len() as u64,
        "the SYN and delivered payload advance snd_una exactly once");
}

#[test]
fn receive_snapshot_commits_only_after_process_copy() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5006), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let synack = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let ack = client.input(lo_ip(), lo_ip(), &synack).unwrap().unwrap();
    let _ = server.input(lo_ip(), lo_ip(), &ack).unwrap();

    client.send(b"snapshot");
    let segment = client.output(1500, true, false).remove(0);
    let _ = server.input(lo_ip(), lo_ip(), &segment).unwrap();

    let snapshot = server.snapshot_recv_with_offset_oob(8, 0, true).unwrap();
    assert_eq!(&snapshot.bytes, b"snapshot");
    assert_eq!(server.recv_buf.len, 8, "snapshot does not consume state");
    server.commit_recv_snapshot(&snapshot, snapshot.bytes.len(), false, true);
    assert_eq!(server.recv_buf.len, 0, "commit consumes only after copy succeeds");
}

#[test]
fn receiver_mss_uses_live_policy_then_validated_payload() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1);
    c.own_mss = 1_200;
    c.rcv_buf_cap = 400;
    assert_eq!(c.rcv_mss(), 200);
    c.note_rcv_mss(150);
    assert_eq!(c.rcv_mss(), 200);
    c.note_rcv_mss(800);
    assert_eq!(c.rcv_mss(), 800);
    c.own_mss = 600;
    assert_eq!(c.rcv_mss(), 600);
}

#[test]
fn receive_ssthresh_caps_the_advertised_window_and_tracks_growth() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1);
    c.rcv_buf_cap = 4_000;
    c.rcv_ssthresh = 1_000;
    assert_eq!(c.advertised_rcv_wnd(), 1_000);
    c.rcv_peak = 3_000;
    c.rcv_autotune();
    assert_eq!(c.rcv_ssthresh, 8_000);
}

#[test]
fn tcp_info_notsent_bytes_follow_the_canonical_send_queue() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5001), ep(lo, 80), 1000);
    client.state = crate::tcp_state::TcpState::Established;
    client.send(b"queued");
    assert_eq!(client.notsent_bytes(), 6);
    let _ = client.output(1500, true, false);
    assert_eq!(client.notsent_bytes(), 0);
}

#[test]
fn advertised_receive_window_uses_the_same_scale_as_tcp_headers() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5005), ep(lo, 80), 1000);
    c.rcv_buf_cap = 65_536;
    c.window_clamp = 65_536;
    c.snd_wscale = 4;
    assert_eq!(c.current_rcv_window(), 4_096);
    assert_eq!(c.advertised_rcv_wnd(), 65_536);
}


