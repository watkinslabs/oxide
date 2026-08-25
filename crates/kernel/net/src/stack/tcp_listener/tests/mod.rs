use super::*;

/// `max(SO_SNDBUF, TCP_SNDBUF_DEFAULT)` — the cap `InetSocket::poll` supplies.
const TEST_SNDBUF: usize = crate::sock::TCP_SNDBUF_DEFAULT as usize;

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

fn listener(stack: &NetStack, owner: &network_namespace::NetworkNamespaceRef,
            port: u16) -> Arc<TcpListenEntry> {
    let bind = stack.tcp_reserve_in(owner.id().as_u64(),
        IpAddr::V4(Ipv4Addr::LOOPBACK), port, None, false, false, 0, false)
        .expect("reserve listener bind");
    stack.tcp_listen_reserved(&bind).expect("publish listener")
}

fn reserved_child(listener: &Arc<TcpListenEntry>, remote_port: u16,
                  state: crate::tcp_state::TcpState)
    -> (TcpKey, Arc<TcpEntry>)
{
    assert!(listener.reserve_backlog(), "reserve passive child backlog");
    let remote = Endpoint {
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        port: remote_port,
    };
    let mut conn = TcpConn::new_listener(listener.local);
    conn.remote = remote;
    conn.state = state;
    if state == crate::tcp_state::TcpState::SynRecv {
        // A child in SYN-RECEIVED has put exactly its SYN-ACK on the wire, so
        // the only acknowledgement that finishes it names one past that. The
        // fixture has to say so, because the completing acknowledgement is
        // checked against this send state rather than accepted on sight.
        conn.snd_una = 0;
        conn.snd_nxt = 1;
    }
    let key = TcpKey {
        local_ip: listener.local.ip,
        local_port: listener.local.port,
        remote_ip: remote.ip,
        remote_port: remote.port,
    };
    let child = Arc::new(TcpEntry::new_bound_with_filter_listener(
        conn,
        Arc::new(crate::SocketError::new()),
        Some(listener.bind.clone()),
        Arc::new(crate::bpf_filter::SocketFilter::inherited(&listener.bpf_filter)),
        listener.ip_mtu_discover.clone(),
        listener.ipv6_mtu_discover.clone(),
        Some(Arc::downgrade(listener)),
    ));
    (key, child)
}

fn passive_child(stack: &NetStack, listener: &Arc<TcpListenEntry>, remote_port: u16,
                 state: crate::tcp_state::TcpState, completed: bool)
    -> (TcpKey, Arc<TcpEntry>)
{
    let (key, child) = reserved_child(listener, remote_port, state);
    let tables = stack.inet_tables(listener.bind.net_ns());
    assert!(publish_passive_child(&tables, listener, key, &child), "publish passive child");
    if completed {
        assert!(child.promote_to_accept_backlog(), "reserve completed accept backlog");
        assert!(listener.enqueue_accepted(child.clone()), "queue completed passive child");
    }
    (key, child)
}

#[path = "backlog.rs"]
mod backlog;
#[path = "wait.rs"]
mod wait;
