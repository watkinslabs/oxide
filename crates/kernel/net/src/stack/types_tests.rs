use alloc::sync::Arc;

use super::{NetStack, TcpEntry, UdpRxQueue, tcp_send_closed, tcp_transmit_ready};
use crate::addr::{IpAddr, Ipv4Addr};
use crate::tcp_conn::{Endpoint, TcpConn};

#[test]
fn tcp_connection_lock_excludes_network_bottom_halves() {
    let source = include_str!("types.rs");
    assert!(source.contains("self.0.lock_bh::<sched::bh::SchedBh>()"),
        "TCP state shared by socket syscalls and NET_RX must use spin_lock_bh semantics");
}

#[test]
fn shared_network_state_lock_excludes_network_bottom_halves() {
    sched::preempt::_test_reset();
    let state = super::StackBhLock::new(0u8);
    {
        let _guard = state.lock();
        assert_eq!(sched::preempt::softirq_count(),
            sched::preempt::SOFTIRQ_DISABLE_OFFSET);
    }
    assert_eq!(sched::preempt::softirq_count(), 0);
}

const TEST_SNDBUF: usize = crate::sock::TCP_SNDBUF_DEFAULT as usize;

#[test]
fn entry_and_socket_owner_share_canonical_error() {
    let error = Arc::new(crate::SocketError::new());
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40000 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
    let entry = TcpEntry::new_with_error(TcpConn::new_client(local, remote, 1), error.clone());
    assert!(Arc::ptr_eq(&entry.error, &error));
    entry.set_error(syscall::errno::Errno::Econnreset as i32);
    assert_eq!(error.take(), syscall::errno::Errno::Econnreset as i32);
}

#[test]
fn udp_queue_and_socket_owner_share_canonical_error() {
    let error = Arc::new(crate::SocketError::new());
    let queue = UdpRxQueue::new_with_error(Ipv4Addr::ANY, 40001, error.clone());
    assert!(Arc::ptr_eq(&queue.error, &error));
    queue.set_error(syscall::errno::Errno::Econnrefused as i32);
    assert_eq!(error.take(), syscall::errno::Errno::Econnrefused as i32);
    assert!(!queue.error.has());
}

#[test]
fn failed_initial_syn_drops_canonical_error_owner() {
    let stack = NetStack::new();
    let error = Arc::new(crate::SocketError::new());
    let result = stack.tcp_connect_ip_bound(
        IpAddr::V4(Ipv4Addr::LOOPBACK), 40003,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80, None, error.clone());
    assert!(result.is_err());
    assert!(stack.inet_tables(0).tcp_conns.lock().is_empty());
    assert!(!error.has());
}

#[test]
fn syn_sent_is_not_writable_until_connect_completes() {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40002 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
    let mut conn = TcpConn::new_client(local, remote, 2);
    conn.active_open().unwrap();
    let entry = TcpEntry::new(conn);
    assert_eq!(entry.poll_mask(TEST_SNDBUF) & vfs::POLL_OUT, 0);
    entry.conn.lock().state = crate::tcp_state::TcpState::Established;
    assert_ne!(entry.poll_mask(TEST_SNDBUF) & vfs::POLL_OUT, 0);
}

#[test]
fn peer_name_rejects_syn_sent_and_closed_but_accepts_established() {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40006 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
    let mut conn = TcpConn::new_client(local, remote, 5);
    conn.active_open().expect("fresh client enters SYN-SENT");
    let entry = TcpEntry::new(conn);
    assert!(!entry.peer_name_connected());
    entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
    assert!(!entry.peer_name_connected());
    entry.conn.lock().state = crate::tcp_state::TcpState::Established;
    assert!(entry.peer_name_connected());
}

#[test]
fn tcp_close_wakes_poll_subscribers() {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40005 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
    let entry = TcpEntry::new(TcpConn::new_client(local, remote, 4));
    let poll = Arc::new(vfs::PollSubscribers::new());
    entry.register_poll_subs(&poll);
    let before = poll.generation();
    entry.close_and_wake();
    assert!(poll.generation() > before);
    assert_ne!(entry.poll_mask(TEST_SNDBUF) & vfs::POLL_HUP, 0);
}

#[test]
fn transmit_wait_recheck_tracks_exact_send_buffer_capacity() {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40004 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 80 };
    let mut conn = TcpConn::new_client(local, remote, 3);
    assert!(tcp_transmit_ready(&conn, 2));
    conn.send_buf.extend([1, 2]);
    assert!(!tcp_transmit_ready(&conn, 2));
    conn.send_buf.pop_front();
    assert!(tcp_transmit_ready(&conn, 2));
    assert!(tcp_send_closed(crate::tcp_state::TcpState::FinWait1));
    assert!(!tcp_send_closed(crate::tcp_state::TcpState::Established));
}

#[test]
fn tcp_transport_state_retains_one_owner_arc() {
    let owner = crate::SocketOwner::root(network_namespace::initial(), 1234);
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40007 };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), port: 443 };
    let bind = Arc::new(super::TcpBindReservation::new_owned(
        owner.clone(), local, None, false, false, false));
    let entry = TcpEntry::new_bound_with_error(
        TcpConn::new_client(local, remote, 6), Arc::new(crate::SocketError::new()),
        Some(bind.clone()));
    let listener = super::TcpListenEntry::new(bind);
    assert!(Arc::ptr_eq(&entry.owner, &owner));
    assert!(Arc::ptr_eq(&listener.owner, &owner));
}
