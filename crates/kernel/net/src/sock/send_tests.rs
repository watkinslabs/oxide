use super::*;
use core::sync::atomic::Ordering;

use crate::send_control::SendControl;
use crate::stack::TcpEntry;
use crate::tcp_conn::{Endpoint, TcpConn};
use crate::{IpAddr, Ipv4Addr};

fn established_socket() -> (InetSocket, alloc::sync::Arc<TcpEntry>) {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 42_071 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 42_072 };
    let mut conn = TcpConn::new_client(local, remote, 9);
    conn.state = crate::tcp_state::TcpState::Established;
    let entry = alloc::sync::Arc::new(TcpEntry::new(conn));
    let socket = InetSocket::new_tcp_in(crate::net_ns::initial_namespace());
    socket.opts.tcp_nodelay.store(1, Ordering::Release);
    *socket.kind.lock() = SockKind::TcpConn(entry.clone());
    (socket, entry)
}

fn flags(more: bool) -> SendControl {
    let mut control = SendControl::default();
    control.apply_flags(if more { crate::uapi::MSG_MORE } else { 0 });
    control
}

#[test]
fn sendmsg_more_reaches_the_tcp_transport_and_the_final_send_flushes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let _loopback = crate::global_stack().register_loopback();
    let (socket, entry) = established_socket();

    assert_eq!(super::send::sendto(&socket, b"AAAA", None, SenderCreds::default(),
        &flags(true), None), Ok(4));
    {
        let conn = entry.conn.lock();
        assert_eq!(conn.send_buf.len(), 4, "MSG_MORE holds the first write");
        assert!(conn.retx_q.is_empty(), "a corked write has not reached the wire");
    }

    assert_eq!(super::send::sendto(&socket, b"BBBB", None, SenderCreds::default(),
        &flags(true), None), Ok(4));
    assert_eq!(entry.conn.lock().send_buf.len(), 8, "the second corked write coalesces");

    assert_eq!(super::send::sendto(&socket, b"CCCC", None, SenderCreds::default(),
        &flags(false), None), Ok(4));
    let conn = entry.conn.lock();
    assert!(conn.send_buf.is_empty(), "the first non-MSG_MORE send releases the cork");
    assert_eq!(conn.retx_q.len(), 1, "all three writes leave as one TCP segment");
    assert_eq!(conn.retx_q.front().unwrap().payload.len(), 12);
}
