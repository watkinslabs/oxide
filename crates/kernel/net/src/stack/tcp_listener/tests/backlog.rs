use super::*;

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
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    stack.tcp_unlisten_entry(&listener);

    assert!(listener.accept_q.lock().is_empty());
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
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
fn listener_poll_matches_linux_readiness() {
    assert_eq!(listener_poll_mask(false, 0), 0);
    assert_eq!(listener_poll_mask(true, 0), vfs::POLL_IN);
    assert_eq!(listener_poll_mask(false, vfs::POLL_HUP), vfs::POLL_HUP);
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
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);

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
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(child.conn.lock().state, crate::tcp_state::TcpState::Closed);
    assert_eq!(child.arm_connect_wait_with(|| panic!("closed child was re-armed")),
        TcpConnectWait::Closed);
}

#[test]
fn listen_backlog_cap_reopens_after_passive_child_release() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_014);
    listener.set_backlog(1, 1);
    let (_key, child) = reserved_child(&listener, 51_014, crate::tcp_state::TcpState::SynRecv);
    // Backlog 1 holds two requests, so the second still fits and the third
    // does not.
    assert!(listener.reserve_backlog(), "a backlog of one holds a second request");
    assert!(!listener.reserve_backlog(), "configured backlog cap exceeded");
    assert_eq!(listener.syn_backlog_used.load(
        ::core::sync::atomic::Ordering::Acquire), 2);

    child.release_backlog();
    listener.syn_backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
    assert_eq!(listener.syn_backlog_used.load(
        ::core::sync::atomic::Ordering::Acquire), 0);
    assert!(listener.reserve_backlog(), "released backlog slot not reusable");
    stack.tcp_unlisten_entry(&listener);
}

#[test]
fn syn_and_accept_backlogs_exhaust_and_release_independently() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_016);
    listener.set_backlog(1, 1);

    // Each queue is bounded by the same backlog, and each holds one more than
    // the number it was given.
    assert!(listener.reserve_backlog(), "SYN-RECV slot available");
    assert!(listener.reserve_backlog(), "a backlog of one holds a second request");
    assert!(!listener.reserve_backlog(), "SYN-RECV queue exhausted");
    assert!(listener.reserve_accept_backlog(), "accept queue has independent capacity");
    assert!(listener.reserve_accept_backlog(), "accept queue holds a second child too");
    assert!(!listener.reserve_accept_backlog(), "accept queue exhausted independently");

    listener.syn_backlog_used.fetch_sub(2, ::core::sync::atomic::Ordering::AcqRel);
    listener.accept_backlog_used.fetch_sub(2, ::core::sync::atomic::Ordering::AcqRel);
    assert!(listener.reserve_backlog(), "released SYN-RECV slot reusable");
    assert!(listener.reserve_accept_backlog(), "released accept slot reusable");
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    stack.tcp_unlisten_entry(&listener);
}

#[test]
fn concurrent_syn_reservations_never_exceed_backlog_cap() {
    use std::sync::{Arc as StdArc, Barrier};
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_015);
    let cap = 4usize;
    let workers = 32usize;
    listener.set_backlog(cap as i32, cap);
    let gate = StdArc::new(Barrier::new(workers));
    let outcomes = (0..workers).map(|_| {
        let gate = gate.clone();
        let listener = listener.clone();
        std::thread::spawn(move || { gate.wait(); listener.reserve_backlog() })
    }).collect::<Vec<_>>();
    let reserved = outcomes.into_iter().map(|worker| worker.join().unwrap())
        .filter(|reserved| *reserved).count();
    // A backlog of `cap` holds `cap + 1`: the fullness test is `>`, which is
    // what makes `listen(fd, 0)` admit one connection.
    assert_eq!(reserved, cap + 1);
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), cap + 1);
    stack.tcp_unlisten_entry(&listener);
}

#[test]
fn reuseport_selection_is_stable_and_flow_sensitive() {
    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let same = super::select_reuseport_listener(src, 41_000, 80, 3);
    assert_eq!(same, super::select_reuseport_listener(src, 41_000, 80, 3));
    assert!(same < 3);
    let changed_port = super::select_reuseport_listener(src, 41_001, 80, 3);
    let changed_address = super::select_reuseport_listener(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 41_000, 80, 3);
    assert!(changed_port < 3);
    assert!(changed_address < 3);
    assert_eq!(super::select_reuseport_listener(src, 41_000, 80, 0), 0);
    assert_eq!(super::select_reuseport_listener(src, 41_000, 80, 1), 0);
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
        .and_then(crate::stack::TcpSlot::sock)
        .is_some_and(|current| Arc::ptr_eq(current, &first)));
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(duplicate.conn.lock().state, crate::tcp_state::TcpState::Closed);
    assert_eq!(duplicate.arm_connect_wait_with(|| panic!("duplicate child was re-armed")),
        TcpConnectWait::Closed);
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
    tables.tcp_conns.lock().insert(key, crate::stack::TcpSlot::Sock(replacement.clone()));

    assert!(!remove_tcp_entry_exact(&tables, &key, &stale));
    assert!(tables.tcp_conns.lock().get(&key)
        .and_then(crate::stack::TcpSlot::sock)
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
    assert_eq!(listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 0);
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
    assert_eq!(listener.accept_backlog_used.load(::core::sync::atomic::Ordering::Acquire), 1);
    assert_eq!(child.conn.lock().state, crate::tcp_state::TcpState::Established);
}

