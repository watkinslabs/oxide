use super::*;

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::install_final_drop_pending_notifier().expect("install notifier");
    network_namespace::allocate(0).expect("allocate namespace")
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
        assert!(listener.enqueue_accepted(child.clone()), "queue completed passive child");
    }
    (key, child)
}

#[test]
fn listener_close_reaps_half_open_and_completed_unaccepted_children() {
    let stack = NetStack::new();
    let owner = namespace();
    let id = owner.id();
    let listener = listener(&stack, &owner, 41_001);
    let (syn_key, syn_child) = passive_child(
        &stack, &listener, 51_001, crate::tcp_state::TcpState::SynRecv, false);
    let (queued_key, queued_child) = passive_child(
        &stack, &listener, 51_002, crate::tcp_state::TcpState::Established, true);

    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "listener transport state pins owner");
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 2);
    stack.tcp_unlisten_entry(&listener);

    assert!(listener.accept_q.lock().is_empty());
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    {
        let tables = stack.inet_tables(id.as_u64());
        let conns = tables.tcp_conns.lock();
        assert!(!conns.contains_key(&syn_key));
        assert!(!conns.contains_key(&queued_key));
    }
    assert_eq!(syn_child.conn.lock().state, crate::tcp_state::TcpState::Closed);
    assert_eq!(queued_child.conn.lock().state, crate::tcp_state::TcpState::Closed);

    drop(syn_child);
    drop(queued_child);
    drop(listener);
    assert!(network_namespace::lookup(id).is_none(), "final passive transport owner releases namespace");
}

#[test]
fn accepted_child_survives_listener_close_until_connection_release() {
    let stack = NetStack::new();
    let owner = namespace();
    let id = owner.id();
    let listener = listener(&stack, &owner, 41_002);
    let (key, child) = passive_child(
        &stack, &listener, 51_003, crate::tcp_state::TcpState::Established, true);
    let accepted = stack.tcp_accept(&listener).expect("accept completed child");

    drop(owner);
    stack.tcp_unlisten_entry(&listener);
    {
        let tables = stack.inet_tables(id.as_u64());
        assert!(tables.tcp_conns.lock().contains_key(&key),
            "accepted child ownership is independent from listener");
    }
    assert_eq!(accepted.conn.lock().state, crate::tcp_state::TcpState::Established);
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);

    stack.tcp_disconnect_entry(&accepted);
    drop(child);
    drop(accepted);
    drop(listener);
    assert!(network_namespace::lookup(id).is_none(), "accepted connection final release drops owner");
}

#[test]
fn closed_listener_rejects_new_backlog_and_accept_publication() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_003);
    stack.tcp_unlisten_entry(&listener);

    assert!(!listener.reserve_backlog());
    let mut conn = TcpConn::new_listener(listener.local);
    conn.state = crate::tcp_state::TcpState::Established;
    let child = Arc::new(TcpEntry::new_bound_with_filter_listener(
        conn,
        Arc::new(crate::SocketError::new()),
        Some(listener.bind.clone()),
        listener.bpf_filter.clone(),
        listener.ip_mtu_discover.clone(),
        listener.ipv6_mtu_discover.clone(),
        None,
    ));
    assert!(!listener.enqueue_accepted(child));
    assert!(stack.tcp_accept(&listener).is_none());
}

#[test]
fn close_after_reservation_rejects_late_child_publication() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_004);
    let (key, child) = reserved_child(
        &listener, 51_004, crate::tcp_state::TcpState::SynRecv);

    stack.tcp_unlisten_entry(&listener);
    let tables = stack.inet_tables(owner.id().as_u64());
    assert!(!publish_passive_child(&tables, &listener, key, &child));
    assert!(!tables.tcp_conns.lock().contains_key(&key));
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(child.conn.lock().state, crate::tcp_state::TcpState::Closed);
}

#[test]
fn duplicate_tuple_publication_preserves_first_child_and_one_backlog_slot() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_005);
    let (key, first) = passive_child(
        &stack, &listener, 51_005, crate::tcp_state::TcpState::SynRecv, false);
    let (duplicate_key, duplicate) = reserved_child(
        &listener, 51_005, crate::tcp_state::TcpState::SynRecv);
    assert_eq!(key, duplicate_key);

    let tables = stack.inet_tables(owner.id().as_u64());
    assert!(!publish_passive_child(&tables, &listener, duplicate_key, &duplicate));
    assert!(tables.tcp_conns.lock().get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, &first)));
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(duplicate.conn.lock().state, crate::tcp_state::TcpState::Closed);
}

#[test]
fn stale_exact_removal_does_not_delete_tuple_replacement() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_006);
    let (key, stale) = passive_child(
        &stack, &listener, 51_006, crate::tcp_state::TcpState::SynRecv, false);
    let (_replacement_key, replacement) = reserved_child(
        &listener, 51_006, crate::tcp_state::TcpState::SynRecv);
    let tables = stack.inet_tables(owner.id().as_u64());
    tables.tcp_conns.lock().insert(key, replacement.clone());

    assert!(!remove_tcp_entry_exact(&tables, &key, &stale));
    assert!(tables.tcp_conns.lock().get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, &replacement)));
    stale.release_backlog();
    replacement.release_backlog();
}

#[test]
fn synack_transmit_failure_rolls_back_child_and_backlog() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_007);
    let remote = Endpoint {
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        port: 51_007,
    };
    let mut client = TcpConn::new_client(remote, listener.local, 7);
    let syn = client.active_open().expect("build client SYN");
    let key = TcpKey {
        local_ip: listener.local.ip,
        local_port: listener.local.port,
        remote_ip: remote.ip,
        remote_port: remote.port,
    };

    let result = stack.deliver_tcp(owner.id().as_u64(), NetIfaceId::from_raw(1),
        remote.ip, listener.local.ip, &syn);
    assert!(result.is_err(), "stack without an output route rejects SYN-ACK transmit");
    let tables = stack.inet_tables(owner.id().as_u64());
    assert!(!tables.tcp_conns.lock().contains_key(&key));
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
}

#[test]
fn duplicate_final_ack_publishes_passive_child_once() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_008);
    let (key, child) = passive_child(
        &stack, &listener, 51_008, crate::tcp_state::TcpState::SynRecv, false);
    let (remote, local) = match (key.remote_ip, key.local_ip) {
        (IpAddr::V4(remote), IpAddr::V4(local)) => (remote, local),
        _ => unreachable!(),
    };
    let mut ack = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN];
    crate::tcp_hdr::TcpHdr {
        src_port: key.remote_port,
        dst_port: key.local_port,
        seq: 1,
        ack: 1,
        data_offset: 5,
        flags: crate::tcp_hdr::flags::ACK,
        window: 65_535,
        checksum: 0,
        urg_ptr: 0,
    }.build_into(remote, local, &mut ack);

    stack.deliver_tcp(owner.id().as_u64(), NetIfaceId::from_raw(1),
        key.remote_ip, key.local_ip, &ack).expect("first final ACK");
    stack.deliver_tcp(owner.id().as_u64(), NetIfaceId::from_raw(1),
        key.remote_ip, key.local_ip, &ack).expect("duplicate final ACK");

    assert_eq!(listener.accept_q.lock().len(), 1);
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(child.conn.lock().state, crate::tcp_state::TcpState::Established);
}
