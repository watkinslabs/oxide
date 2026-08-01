use super::*;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

#[derive(Default)]
struct TxState { entered: bool, release: bool, block_op: u16, ops: Vec<u16> }

fn state() -> &'static (Mutex<TxState>, Condvar) {
    static STATE: OnceLock<(Mutex<TxState>, Condvar)> = OnceLock::new();
    STATE.get_or_init(|| (Mutex::new(TxState::default()), Condvar::new()))
}

fn owner(raw: u32) -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(raw).expect("nonzero owner")
}

fn tx_block_rw(_: vsock::VsockOwner, frame: &[u8]) -> bool {
    let op = vsock::VsockHdr::decode(frame).expect("transmit header").op;
    let (lock, cv) = state();
    let mut tx = lock.lock().unwrap_or_else(|error| error.into_inner());
    tx.ops.push(op);
    if op == tx.block_op {
        tx.entered = true;
        cv.notify_all();
        while !tx.release {
            tx = cv.wait(tx).unwrap_or_else(|error| error.into_inner());
        }
    }
    true
}

fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }

fn tx_reenter_rst(owner: vsock::VsockOwner, frame: &[u8]) -> bool {
    let sent = vsock::VsockHdr::decode(frame).expect("transmit header");
    if matches!(sent.op, vsock::VIRTIO_VSOCK_OP_RW | vsock::VIRTIO_VSOCK_OP_SHUTDOWN
        | vsock::VIRTIO_VSOCK_OP_RESPONSE)
    {
        let rst = vsock::VsockHdr {
            src_cid: sent.dst_cid, dst_cid: sent.src_cid,
            src_port: sent.dst_port, dst_port: sent.src_port,
            len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
            op: vsock::VIRTIO_VSOCK_OP_RST, flags: 0,
            buf_alloc: sent.buf_alloc, fwd_cnt: sent.fwd_cnt,
        };
        vsock::deliver_rx_from(owner, &rst, &[]);
    }
    true
}

fn tx_fail_response(_: vsock::VsockOwner, frame: &[u8]) -> bool {
    vsock::VsockHdr::decode(frame).expect("transmit header").op
        != vsock::VIRTIO_VSOCK_OP_RESPONSE
}

fn setup(raw: u32, cid: u64, port: u32) -> (Arc<VsockSocket>, Arc<VsockConn>) {
    let transport = owner(raw);
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_block_rw, rx_noop));
    let conn = Arc::new(VsockConn::new(transport, cid, port, 2, 1024,
        VsockState::Connected));
    conn.tx.lock().credit.observe_peer(8192, 0);
    assert!(vsock::TABLE.insert(conn.clone()));
    let sock = Arc::new(VsockSocket::new());
    sock.attach_conn(conn.clone()).expect("attach connection");
    *state().0.lock().unwrap_or_else(|error| error.into_inner()) = TxState {
        block_op: vsock::VIRTIO_VSOCK_OP_RW, ..TxState::default()
    };
    (sock, conn)
}

fn wait_for_rw() {
    let (lock, cv) = state();
    let mut tx = lock.lock().unwrap_or_else(|error| error.into_inner());
    while !tx.entered {
        tx = cv.wait(tx).unwrap_or_else(|error| error.into_inner());
    }
}

fn release_rw() {
    let (lock, cv) = state();
    lock.lock().unwrap_or_else(|error| error.into_inner()).release = true;
    cv.notify_all();
}

fn block_terminal() {
    let mut tx = state().0.lock().unwrap_or_else(|error| error.into_inner());
    tx.entered = false;
    tx.release = false;
    tx.block_op = vsock::VIRTIO_VSOCK_OP_SHUTDOWN;
}

fn inbound_shutdown(conn: &VsockConn) -> vsock::VsockHdr {
    vsock::VsockHdr {
        src_cid: conn.peer_cid, dst_cid: conn.local_cid,
        src_port: conn.peer_port, dst_port: conn.local_port,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_SHUTDOWN,
        flags: vsock::VIRTIO_VSOCK_SHUTDOWN_RCV,
        buf_alloc: 8192, fwd_cnt: 0,
    }
}

#[test]
fn local_shutdown_completion_waits_for_admitted_rw_transmit() {
    let _guard = vsock::tests::test_domain();
    let (sock, conn) = setup(0x0c00_0001, 0x5c00_0001, 63_001);
    let writer = {
        let sock = sock.clone();
        std::thread::spawn(move || sock.write_nonblock(0, b"before shutdown"))
    };
    wait_for_rw();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let shutdown = {
        let sock = sock.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = sock.shutdown(crate::uapi::ShutdownHow::Write);
            done_tx.send(result).unwrap();
        })
    };
    started_rx.recv().unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
    release_rw();
    assert_eq!(writer.join().unwrap(), Ok(15));
    assert_eq!(done_rx.recv().unwrap(), Ok(()));
    shutdown.join().unwrap();
    assert_eq!(sock.write_nonblock(0, b"after"), Err(vfs::VfsError::Epipe));
    let ops = state().0.lock().unwrap_or_else(|error| error.into_inner()).ops.clone();
    assert_eq!(ops.first(), Some(&vsock::VIRTIO_VSOCK_OP_RW));
    assert!(!ops[1..].contains(&vsock::VIRTIO_VSOCK_OP_RW));
    sock.release_file();
    assert!(vsock::driver_uninstall(conn.owner));
}

#[test]
fn peer_receive_shutdown_publication_waits_for_admitted_rw_transmit() {
    let _guard = vsock::tests::test_domain();
    let (sock, conn) = setup(0x0c00_0002, 0x5c00_0002, 63_002);
    let writer = {
        let sock = sock.clone();
        std::thread::spawn(move || sock.write_nonblock(0, b"before peer shutdown"))
    };
    wait_for_rw();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let delivery = {
        let conn = conn.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            vsock::deliver_rx_from(conn.owner, &inbound_shutdown(&conn), &[]);
            done_tx.send(()).unwrap();
        })
    };
    started_rx.recv().unwrap();
    done_rx.recv_timeout(Duration::from_millis(20)).expect("peer shutdown publishes during TX");
    release_rw();
    assert_eq!(writer.join().unwrap(), Ok(20));
    delivery.join().unwrap();
    assert_eq!(sock.write_nonblock(0, b"after"), Err(vfs::VfsError::Epipe));
    let ops = state().0.lock().unwrap_or_else(|error| error.into_inner()).ops.clone();
    assert_eq!(ops, vec![vsock::VIRTIO_VSOCK_OP_RW]);
    sock.release_file();
    assert!(vsock::driver_uninstall(conn.owner));
}

#[test]
fn disconnect_hides_reusable_state_until_exact_tuple_removal() {
    let _guard = vsock::tests::test_domain();
    let (sock, conn) = setup(0x0c00_0003, 0x5c00_0003, 63_003);
    block_terminal();
    let disconnect = {
        let sock = sock.clone();
        std::thread::spawn(move || sock.disconnect())
    };
    wait_for_rw();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let reconnect = {
        let sock = sock.clone();
        std::thread::spawn(move || done_tx.send(sock.connect_transport(2, 1024, true)).unwrap())
    };
    assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
    release_rw();
    assert_eq!(disconnect.join().unwrap(), Ok(()));
    assert_eq!(done_rx.recv().unwrap(), Ok(()));
    reconnect.join().unwrap();
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(conn.owner));
}

#[test]
fn release_keeps_bind_reserved_until_exact_tuple_removal() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0c00_0004);
    let cid = 0x5c00_0004;
    let port = 63_004;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_block_rw, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    let conn = Arc::new(VsockConn::new(transport, cid, port, 2, 1024,
        VsockState::Connected));
    assert!(vsock::TABLE.insert(conn.clone()));
    sock.attach_conn(conn).unwrap();
    *state().0.lock().unwrap_or_else(|error| error.into_inner()) = TxState {
        block_op: vsock::VIRTIO_VSOCK_OP_SHUTDOWN, ..TxState::default()
    };
    let release = {
        let sock = sock.clone();
        std::thread::spawn(move || sock.release_file())
    };
    wait_for_rw();
    let replacement = VsockSocket::new();
    assert_eq!(replacement.bind(crate::socket_args::AF_VSOCK as u16, port, cid),
        Err(crate::NetError::Eaddrinuse));
    release_rw();
    release.join().unwrap();
    assert_eq!(replacement.bind(crate::socket_args::AF_VSOCK as u16, port, cid), Ok(()));
    replacement.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn transport_rst_reenters_send_shutdown_close_and_accept_response() {
    let _guard = vsock::tests::test_domain();
    for (raw, port, action) in [(0x0c00_0005, 63_005, 0u8), (0x0c00_0006, 63_006, 1u8),
        (0x0c00_0007, 63_007, 2u8)]
    {
        let transport = owner(raw);
        let cid = 0x5c00_0000 + u64::from(action);
        assert!(vsock::driver_install(transport, cid, tx_reenter_rst, rx_noop));
        let conn = Arc::new(VsockConn::new(transport, cid, port, 2, 1024,
            VsockState::Connected));
        conn.tx.lock().credit.observe_peer(8192, 0);
        assert!(vsock::TABLE.insert(conn.clone()));
        let sock = Arc::new(VsockSocket::new());
        sock.attach_conn(conn.clone()).unwrap();
        match action {
            0 => assert_eq!(vsock::send(&conn, b"reentrant"), Ok(9)),
            1 => assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Ok(())),
            _ => sock.release_file(),
        }
        if action != 2 { sock.release_file(); }
        assert!(vsock::TABLE.find(conn.key()).is_none());
        assert!(vsock::driver_uninstall(transport));
    }

    let transport = owner(0x0c00_0008);
    let cid = 0x5c00_0008;
    let port = 63_008;
    assert!(vsock::driver_install(transport, cid, tx_reenter_rst, rx_noop));
    let listener = VsockSocket::new();
    listener.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    listener.listen().unwrap();
    let request = vsock::VsockHdr {
        src_cid: 2, dst_cid: cid, src_port: 1024, dst_port: port,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(transport, &request, &[]);
    assert!(matches!(listener.accept(), Err(crate::NetError::Eagain)));
    assert!(vsock::TABLE.find(vsock::ConnKey {
        owner: transport, local_cid: cid, local_port: port, peer_cid: 2, peer_port: 1024,
    }).is_none());
    listener.release_file();
    assert!(vsock::driver_uninstall(transport));
}


#[test]
fn failed_accept_response_rolls_back_hidden_child() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0c00_0009);
    let cid = 0x5c00_0009;
    let port = 63_009;
    assert!(vsock::driver_install(transport, cid, tx_fail_response, rx_noop));
    let listener = VsockSocket::new();
    listener.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    listener.listen().unwrap();
    let request = vsock::VsockHdr {
        src_cid: 2, dst_cid: cid, src_port: 1025, dst_port: port,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(transport, &request, &[]);
    assert!(matches!(listener.accept(), Err(crate::NetError::Eagain)));
    assert_eq!(listener.poll() & vfs::POLL_IN, 0);
    assert!(vsock::TABLE.find(vsock::ConnKey {
        owner: transport, local_cid: cid, local_port: port, peer_cid: 2, peer_port: 1025,
    }).is_none());
    listener.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn deferred_credit_update_cannot_cross_tuple_reuse() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0c00_000a);
    let cid = 0x5c00_000a;
    let port = 63_010;
    assert!(vsock::driver_install(transport, cid, tx_block_rw, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    let old = Arc::new(VsockConn::new(transport, cid, port, 2, 1026,
        VsockState::Connected));
    old.rx.lock().push_back(7);
    assert!(vsock::TABLE.insert(old.clone()));
    sock.attach_conn(old.clone()).unwrap();
    *state().0.lock().unwrap_or_else(|error| error.into_inner()) = TxState::default();

    let emit = old.hold_emission_for_test();
    let reader = {
        let old = old.clone();
        std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            (vsock::recv(&old, &mut byte), byte)
        })
    };
    assert_eq!(reader.join().unwrap(), (Ok(1), [7]));
    assert!(old.credit_update_pending.load(core::sync::atomic::Ordering::Acquire));
    let disconnect = {
        let sock = sock.clone();
        std::thread::spawn(move || sock.disconnect())
    };
    drop(emit);
    assert_eq!(disconnect.join().unwrap(), Ok(()));
    assert!(!old.credit_update_pending.load(core::sync::atomic::Ordering::Acquire));

    sock.connect_transport(2, 1026, true).unwrap();
    let replacement = sock.conn().unwrap();
    assert_eq!(replacement.key(), old.key());
    assert!(!Arc::ptr_eq(&replacement, &old));
    let ops = state().0.lock().unwrap_or_else(|error| error.into_inner()).ops.clone();
    assert!(!ops.contains(&vsock::VIRTIO_VSOCK_OP_CREDIT_UPDATE));
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn credit_request_in_final_unlock_window_is_drained() {
    let _guard = vsock::tests::test_domain();
    let (sock, conn) = setup(0x0c00_000b, 0x5c00_000b, 63_011);
    state().0.lock().unwrap_or_else(|error| error.into_inner()).release = true;
    vsock::inject_tail_credit_for_test(&conn);
    assert_eq!(vsock::send(&conn, b"tail"), Ok(4));
    let ops = state().0.lock().unwrap_or_else(|error| error.into_inner()).ops.clone();
    assert_eq!(ops, [vsock::VIRTIO_VSOCK_OP_RW, vsock::VIRTIO_VSOCK_OP_CREDIT_UPDATE]);
    sock.release_file();
    assert!(vsock::driver_uninstall(conn.owner));
}
