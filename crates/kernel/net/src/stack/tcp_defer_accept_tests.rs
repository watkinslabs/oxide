// `TCP_DEFER_ACCEPT` hand-over behaviour at the accept queue: a completed
// connection carrying no data is queued but withheld, and the connections
// behind it are unaffected.

use super::*;

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

fn listener(stack: &NetStack, owner: &network_namespace::NetworkNamespaceRef, port: u16)
    -> Arc<TcpListenEntry>
{
    let bind = stack.tcp_reserve_in(owner.id().as_u64(),
        IpAddr::V4(Ipv4Addr::LOOPBACK), port, None, false, false, 0, false)
        .expect("reserve listener bind");
    stack.tcp_listen_reserved(&bind).expect("publish listener")
}

/// One completed passive child, queued for accept. `deferred` stamps the
/// deferral the delivery path installs when a handshake completes with an
/// empty receive queue.
fn queued_child(stack: &NetStack, listener: &Arc<TcpListenEntry>, remote_port: u16,
                deferred: bool) -> Arc<TcpEntry>
{
    assert!(listener.reserve_backlog(), "reserve passive child backlog");
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port: remote_port };
    let mut conn = TcpConn::new_listener(listener.local);
    conn.remote = remote;
    conn.state = crate::tcp_state::TcpState::Established;
    if deferred {
        conn.defer_deadline_ns = crate::tcp_conn::defer::deadline_ns(
            listener.defer_window_secs.load(::core::sync::atomic::Ordering::Acquire),
            crate::tcp_conn::ka_now_ns());
        assert_ne!(conn.defer_deadline_ns, 0, "the listener must actually be deferring");
    }
    let key = TcpKey {
        local_ip: listener.local.ip, local_port: listener.local.port,
        remote_ip: remote.ip, remote_port: remote.port,
    };
    let child = Arc::new(TcpEntry::new_bound_with_filter_listener(
        conn, Arc::new(crate::SocketError::new()), Some(listener.bind.clone()),
        Arc::new(crate::bpf_filter::SocketFilter::inherited(&listener.bpf_filter)),
        listener.ip_mtu_discover.clone(), listener.ipv6_mtu_discover.clone(),
        Some(Arc::downgrade(listener)),
    ));
    let tables = stack.inet_tables(listener.bind.net_ns());
    assert!(super::tcp_listener::publish_passive_child(&tables, listener, key, &child));
    assert!(child.promote_to_accept_backlog());
    assert!(listener.enqueue_accepted(child.clone()));
    child
}

fn defer_for(listener: &Arc<TcpListenEntry>, seconds: i32) {
    let count = crate::sock_opts::sol_tcp::secs_to_retrans(seconds,
        crate::sock_opts::sol_tcp::TCP_TIMEOUT_INIT_S,
        crate::sock_opts::sol_tcp::TCP_RTO_MAX_SEC);
    listener.defer_window_secs.store(crate::sock_opts::sol_tcp::defer::window_secs(count),
        ::core::sync::atomic::Ordering::Release);
}

#[test]
fn a_listener_that_did_not_defer_hands_a_silent_connection_over_at_once() {
    let stack = NetStack::new();
    let owner = namespace();
    let l = listener(&stack, &owner, 42_101);
    let child = queued_child(&stack, &l, 52_101, false);
    assert!(child.acceptable());
    assert!(stack.tcp_accept(&l).is_some(), "no deferral means no wait");
}

#[test]
fn a_deferred_connection_is_queued_but_not_handed_over_until_data_arrives() {
    let stack = NetStack::new();
    let owner = namespace();
    let l = listener(&stack, &owner, 42_102);
    defer_for(&l, 30);
    let child = queued_child(&stack, &l, 52_102, true);
    assert_eq!(l.accept_q.lock().len(), 1, "the child is queued, just not acceptable");
    assert!(!child.acceptable());
    assert!(stack.tcp_accept(&l).is_none(), "accept must not see a silent connection");

    // The client sends its request; that is what the server was waiting for.
    child.conn.lock().recv_buf.extend(b"GET / HTTP/1.1\r\n".iter().copied());
    assert!(child.acceptable());
    let accepted = stack.tcp_accept(&l).expect("data makes the connection acceptable");
    assert!(Arc::ptr_eq(&accepted, &child));
    // The bytes that released it are the first thing a reader sees.
    assert_eq!(accepted.conn.lock().recv_buf.len(), 16);
}

#[test]
fn a_deferred_connection_does_not_hold_back_the_ones_behind_it() {
    let stack = NetStack::new();
    let owner = namespace();
    let l = listener(&stack, &owner, 42_103);
    defer_for(&l, 30);
    let silent = queued_child(&stack, &l, 52_103, true);
    let talking = queued_child(&stack, &l, 52_104, true);
    talking.conn.lock().recv_buf.push_back(b'x');

    let accepted = stack.tcp_accept(&l).expect("the connection with data is acceptable");
    assert!(Arc::ptr_eq(&accepted, &talking), "the head of the queue must not block it");
    assert!(stack.tcp_accept(&l).is_none(), "the silent one is still deferred");
    assert_eq!(l.accept_q.lock().len(), 1);
    assert!(!silent.acceptable());
}

#[test]
fn the_window_the_listener_waits_is_the_one_the_option_reports() {
    let stack = NetStack::new();
    let owner = namespace();
    let l = listener(&stack, &owner, 42_105);
    for requested in [1, 5, 30] {
        defer_for(&l, requested);
        let window = l.defer_window_secs.load(::core::sync::atomic::Ordering::Acquire);
        let count = crate::sock_opts::sol_tcp::secs_to_retrans(requested,
            crate::sock_opts::sol_tcp::TCP_TIMEOUT_INIT_S,
            crate::sock_opts::sol_tcp::TCP_RTO_MAX_SEC);
        // The seconds the hand-over waits and the seconds `getsockopt`
        // publishes come from the same stored count.
        assert_eq!(window, crate::sock_opts::sol_tcp::retrans_to_secs(count,
            crate::sock_opts::sol_tcp::TCP_TIMEOUT_INIT_S,
            crate::sock_opts::sol_tcp::TCP_RTO_MAX_SEC));
        assert!(window >= requested);
    }
}

#[test]
fn a_deferral_that_has_run_out_is_acceptable_with_nothing_received() {
    // The wall-clock arm of the rule, driven directly because the hosted
    // clock does not advance.
    let deadline = crate::tcp_conn::defer::deadline_ns(30, 1_000);
    assert!(!crate::tcp_conn::defer::acceptable(deadline, 0, deadline - 1));
    assert!(crate::tcp_conn::defer::acceptable(deadline, 0, deadline));
}
