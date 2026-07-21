use super::*;

fn established_loopback(port: u16, client_port: u16)
    -> (NetStack, crate::NetIfaceId, alloc::sync::Arc<crate::LoopbackDev>, alloc::sync::Arc<crate::stack::TcpEntry>, alloc::sync::Arc<crate::stack::TcpEntry>)
{
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo_dev) = stack.register_loopback();
    let listener = stack.tcp_listen(lo(), port, true).unwrap();
    let client = stack.tcp_connect(lo(), client_port, lo(), port).unwrap();
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    let server = stack.tcp_accept(&listener).expect("three-way handshake accepted");
    (stack, iface, lo_dev, client, server)
}

#[test]
fn f699_loopback_ack_drains_retx_queue_after_established_write() {
    let (stack, iface, lo_dev, client, server) = established_loopback(90, 50_090);
    assert_eq!(stack.tcp_send(&client, b"ack-me", 65_536, true, false), Ok(6));
    assert!(!client.conn.lock().retx_q.is_empty(), "write must publish unacked bytes first");
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    assert_eq!(stack.tcp_recv(&server, 64), b"ack-me");
    assert!(client.conn.lock().retx_q.is_empty(), "peer ACK must retire the exact sent bytes");
}

#[test]
fn f699_loopback_preserves_order_across_ack_drained_writes() {
    let (stack, iface, lo_dev, client, server) = established_loopback(91, 50_091);
    assert_eq!(stack.tcp_send(&client, b"first-", 65_536, true, false), Ok(6));
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    assert!(client.conn.lock().retx_q.is_empty());
    assert_eq!(stack.tcp_send(&client, b"second", 65_536, true, false), Ok(6));
    for _ in 0..3 { stack.drain_loopback(iface, &lo_dev); }
    assert_eq!(stack.tcp_recv(&server, 64), b"first-second");
    assert!(client.conn.lock().retx_q.is_empty());
}
