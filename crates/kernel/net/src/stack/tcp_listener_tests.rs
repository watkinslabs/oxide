use super::*;

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
fn listen_backlog_cap_reopens_after_passive_child_release() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_014);
    listener.set_backlog(1, 1);
    let (_key, child) = reserved_child(&listener, 51_014, crate::tcp_state::TcpState::SynRecv);
    assert!(!listener.reserve_backlog(), "configured backlog cap exceeded");
    assert_eq!(listener.backlog_used.load(
        ::core::sync::atomic::Ordering::Acquire), 1);

    child.release_backlog();
    assert_eq!(listener.backlog_used.load(
        ::core::sync::atomic::Ordering::Acquire), 0);
    assert!(listener.reserve_backlog(), "released backlog slot not reusable");
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
    assert_eq!(reserved, cap);
    assert_eq!(listener.backlog_used.load(::core::sync::atomic::Ordering::Acquire), cap);
    stack.tcp_unlisten_entry(&listener);
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

#[test]
fn accept_wait_classifies_ready_and_closed_without_arming() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_009);
    let (_key, _child) = passive_child(
        &stack, &listener, 51_009, crate::tcp_state::TcpState::Established, true);

    assert_eq!(listener.arm_accept_wait_with(|| panic!("ready listener armed")),
        TcpAcceptWait::Ready);
    stack.tcp_unlisten_entry(&listener);
    assert_eq!(listener.arm_accept_wait_with(|| panic!("closed listener armed")),
        TcpAcceptWait::Closed);
}

#[test]
fn accept_close_serializes_with_wait_arm_and_wakes_after_publication() {
    use std::sync::mpsc;
    use std::time::Duration;

    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_010);
    let (armed_tx, armed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closer_tx, closer_rx) = mpsc::channel();
    let (wake_tx, wake_rx) = mpsc::channel();

    std::thread::scope(|scope| {
        let waiter = listener.clone();
        scope.spawn(move || {
            assert_eq!(waiter.arm_accept_wait_with(|| {
                armed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }), TcpAcceptWait::Parked);
        });
        armed_rx.recv_timeout(Duration::from_secs(2)).expect("accept wait armed");

        let closing = listener.clone();
        scope.spawn(move || {
            closer_tx.send(()).unwrap();
            let drained = closing.close_accept_queue_with(|| {
                assert!(closing.is_closed(), "closed state precedes wake");
                wake_tx.send(()).unwrap();
            });
            assert!(drained.is_empty());
        });
        closer_rx.recv_timeout(Duration::from_secs(2)).expect("accept close started");
        assert!(wake_rx.try_recv().is_err(), "close cannot pass the arm lock");
        release_tx.send(()).unwrap();
        wake_rx.recv_timeout(Duration::from_secs(2)).expect("accept close wake");
    });
}

#[test]
fn connect_close_serializes_with_wait_arm_and_wakes_after_publication() {
    use std::sync::mpsc;
    use std::time::Duration;

    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_011);
    let (_key, entry) = reserved_child(
        &listener, 51_011, crate::tcp_state::TcpState::SynSent);
    entry.conn.lock().state = crate::tcp_state::TcpState::Established;
    assert_eq!(entry.arm_connect_wait_with(|| panic!("established connect armed")),
        TcpConnectWait::Established);
    entry.conn.lock().state = crate::tcp_state::TcpState::SynSent;
    let (armed_tx, armed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closer_tx, closer_rx) = mpsc::channel();
    let (wake_tx, wake_rx) = mpsc::channel();

    std::thread::scope(|scope| {
        let waiter = entry.clone();
        scope.spawn(move || {
            assert_eq!(waiter.arm_connect_wait_with(|| {
                armed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }), TcpConnectWait::Parked);
        });
        armed_rx.recv_timeout(Duration::from_secs(2)).expect("connect wait armed");

        let closing = entry.clone();
        scope.spawn(move || {
            closer_tx.send(()).unwrap();
            closing.close_with(|| {
                assert_eq!(closing.conn.lock().state, crate::tcp_state::TcpState::Closed,
                    "closed state precedes wake");
                wake_tx.send(()).unwrap();
            });
        });
        closer_rx.recv_timeout(Duration::from_secs(2)).expect("connect close started");
        assert!(wake_rx.try_recv().is_err(), "close cannot pass the arm lock");
        release_tx.send(()).unwrap();
        wake_rx.recv_timeout(Duration::from_secs(2)).expect("connect close wake");
    });

    assert_eq!(entry.arm_connect_wait_with(|| panic!("closed connect armed")),
        TcpConnectWait::Closed);
}

#[test]
fn connect_wait_classifies_pending_reset_as_terminal() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_016);
    let (_key, entry) = reserved_child(
        &listener, 51_016, crate::tcp_state::TcpState::SynSent);
    entry.set_error(syscall::errno::Errno::Econnrefused as i32);
    assert_eq!(entry.arm_connect_wait_with(|| panic!("errored connect armed")),
        TcpConnectWait::Closed);
    assert_eq!(entry.error.take(), syscall::errno::Errno::Econnrefused as i32);
}

#[test]
fn transmit_wait_rechecks_terminal_state_under_connection_lock() {
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Duration;

    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_012);
    let (_key, entry) = reserved_child(
        &listener, 51_012, crate::tcp_state::TcpState::Established);
    let write_shut = AtomicBool::new(false);
    let (armed_tx, armed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (wake_tx, wake_rx) = mpsc::channel();

    std::thread::scope(|scope| {
        let waiter = entry.clone();
        let write_shut = &write_shut;
        scope.spawn(move || {
            assert!(waiter.arm_transmit_wait_with(write_shut, 0, || {
                armed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }));
        });
        armed_rx.recv_timeout(Duration::from_secs(2)).expect("transmit wait armed");

        let closing = entry.clone();
        scope.spawn(move || closing.close_with(|| { wake_tx.send(()).unwrap(); }));
        assert!(wake_rx.try_recv().is_err(), "close cannot pass the arm lock");
        release_tx.send(()).unwrap();
        wake_rx.recv_timeout(Duration::from_secs(2)).expect("transmit close wake");
    });

    assert!(!entry.arm_transmit_wait_with(&write_shut, 0,
        || panic!("closed transmitter armed")));
}

#[test]
fn transmit_wait_rechecks_shutdown_error_and_capacity_before_arm() {
    use ::core::sync::atomic::AtomicBool;

    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_013);
    let (_key, entry) = reserved_child(&listener, 51_013, crate::tcp_state::TcpState::Established);
    let shut = AtomicBool::new(true);
    assert!(!entry.arm_transmit_wait_with(&shut, 0, || panic!("shutdown transmitter armed")));

    shut.store(false, ::core::sync::atomic::Ordering::Release);
    entry.set_error(syscall::errno::Errno::Econnreset as i32);
    assert!(!entry.arm_transmit_wait_with(&shut, 0, || panic!("errored transmitter armed")));

    assert_eq!(entry.error.take(), syscall::errno::Errno::Econnreset as i32);
    entry.conn.lock().send(b"ready");
    assert!(!entry.arm_transmit_wait_with(&shut, 1024,
        || panic!("capacity-ready transmitter armed")));
}

#[test]
fn error_publication_does_not_hold_connection_lock_while_waking() {
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Duration;

    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_015);
    let (_key, entry) = reserved_child(
        &listener, 51_015, crate::tcp_state::TcpState::Established);
    let (armed_tx, armed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (published_tx, published_rx) = mpsc::channel();
    let write_shut = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let waiter = entry.clone();
        scope.spawn(move || {
            assert!(waiter.arm_transmit_wait_with(
                &write_shut, 0, || {
                    armed_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }));
        });
        armed_rx.recv_timeout(Duration::from_secs(2)).expect("waiter armed");

        let publisher = entry.clone();
        scope.spawn(move || {
            assert!(publisher.set_error(syscall::errno::Errno::Econnreset as i32));
            published_tx.send(()).unwrap();
        });
        published_rx.recv_timeout(Duration::from_secs(2))
            .expect("error publication must not deadlock on connection lock");
        release_tx.send(()).unwrap();
    });
}
