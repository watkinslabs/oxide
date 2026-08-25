use super::*;

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
fn tcp_accept_arms_the_listener_socket_queue_on_a_host() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_019);
    assert_eq!(listener.arm_accept_wait(u64::MAX), TcpAcceptWait::Parked);
    assert!(listener.accept_waiters.has_waiters());
    listener.accept_waiters.cancel_current_park();
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
fn transport_error_exposes_failed_connect_writable_readiness() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_017);
    let (_key, entry) = reserved_child(&listener, 51_017, crate::tcp_state::TcpState::SynSent);
    assert_eq!(entry.poll_mask(TEST_SNDBUF) & (vfs::POLL_OUT | vfs::POLL_ERR), 0);
    entry.set_error(syscall::errno::Errno::Econnrefused as i32);
    assert_eq!(entry.poll_mask(TEST_SNDBUF) & (vfs::POLL_OUT | vfs::POLL_ERR),
        vfs::POLL_OUT | vfs::POLL_ERR);
}

#[test]
fn peer_half_close_is_readable_rdhup_but_remains_writable() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_018);
    let (_key, entry) = reserved_child(&listener, 51_018, crate::tcp_state::TcpState::CloseWait);
    let mask = entry.poll_mask(TEST_SNDBUF);
    assert_ne!(mask & vfs::POLL_OUT, 0);
    assert_ne!(mask & vfs::POLL_IN, 0);
    assert_ne!(mask & vfs::POLL_RDHUP, 0);
    assert_eq!(mask & vfs::POLL_HUP, 0);
}

#[test]
fn local_half_close_does_not_report_full_hangup_before_peer_fin() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = listener(&stack, &owner, 41_019);
    for (port, state) in [(51_019, crate::tcp_state::TcpState::FinWait1),
                          (51_020, crate::tcp_state::TcpState::FinWait2)] {
        let (_key, entry) = reserved_child(&listener, port, state);
        let mask = entry.poll_mask(TEST_SNDBUF);
        assert_ne!(mask & vfs::POLL_OUT, 0);
        assert_eq!(mask & vfs::POLL_HUP, 0);
    }
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
        release_tx.send(()).unwrap();
        published_rx.recv_timeout(Duration::from_secs(2))
            .expect("error publication completes after connection-lock release");
    });
}

