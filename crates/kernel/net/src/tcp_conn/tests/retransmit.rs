use super::*;

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
fn shutdown_write_cancels_active_open_without_fin() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _syn = client.active_open().expect("active open");

    assert_eq!(client.shutdown_write(), Ok(None));
    assert_eq!(client.state, crate::tcp_state::TcpState::Closed);
    assert!(client.retx_q.is_empty());
}

#[test]
fn retransmit_due_re_emits_after_rto() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5000), ep(lo, 80), 1000);
    let _ = c.active_open().unwrap();
    assert_eq!(c.retransmit_due(0).len(), 0);
    assert_eq!(c.retransmit_due(2_000_000_000).len(), 1, "after 2s, SYN re-emitted");
    assert_eq!(c.bytes_retrans, 0, "control-only retransmits carry no payload bytes");
    assert!(c.rto_ns >= 2_000_000_000);
}

#[test]
fn retransmit_due_counts_retransmitted_payload_bytes() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5004), ep(lo, 80), 1000);
    c.state = crate::tcp_state::TcpState::Established;
    c.send(b"retry");
    assert_eq!(c.output(1500, true, false).len(), 1);
    assert_eq!(c.retransmit_due(c.rto_ns).len(), 1);
    assert_eq!(c.bytes_retrans, 5);
}

#[test]
fn listener_retransmits_exact_synack_for_duplicate_syn() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut client = TcpConn::new_client(ep(lo, 5002), ep(lo, 80), 1000);
    let mut server = TcpConn::new_listener(ep(lo, 80));
    let syn = client.active_open().unwrap();
    let first = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    let duplicate = server.input(lo_ip(), lo_ip(), &syn).unwrap().unwrap();
    assert_eq!(first, duplicate, "duplicate SYN must retransmit the same SYN-ACK");
    assert_eq!(server.retx_q.len(), 1, "duplicate SYN must not add a child retransmit");
    assert_eq!(server.state, crate::tcp_state::TcpState::SynRecv);
}

#[test]
fn retransmit_backoff_delays_next_retry_and_counts_attempts() {
    let lo = crate::addr::Ipv4Addr::LOOPBACK;
    let mut c = TcpConn::new_client(ep(lo, 5001), ep(lo, 80), 1000);
    let _ = c.active_open().unwrap();
    let first_rto = c.rto_ns;
    assert_eq!(c.retransmit_due(first_rto).len(), 1);
    assert_eq!(c.retx_q.front().unwrap().retries, 1);
    assert_eq!(c.retransmit_due(first_rto + 1).len(), 0,
        "backoff must prevent an immediate second retry");
    let second_due = first_rto.saturating_add(c.rto_ns);
    assert_eq!(c.retransmit_due(second_due).len(), 1);
    assert_eq!(c.retx_q.front().unwrap().retries, 2);
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
