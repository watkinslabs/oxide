use super::*;
use crate::vsock::{ConnKey, VsockState};

fn owner(raw: u32) -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(raw).expect("test owner is nonzero")
}

fn tx_ok(_: vsock::VsockOwner, _: &[u8]) -> bool { true }
fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }

fn inbound(conn: &VsockConn, op: u16, flags: u32, len: u32) -> vsock::VsockHdr {
    vsock::VsockHdr {
        src_cid: conn.peer_cid, dst_cid: conn.local_cid,
        src_port: conn.peer_port, dst_port: conn.local_port,
        len, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM, op, flags,
        buf_alloc: 8192, fwd_cnt: 0,
    }
}

fn connected(raw: u32, port: u32) -> (Arc<VsockSocket>, Arc<VsockConn>) {
    let conn = Arc::new(VsockConn::new(owner(raw), 3, port, 2, 1024, VsockState::Connected));
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    (sock, conn)
}

fn serial() -> vsock::tests::TestDomain {
    vsock::tests::test_domain()
}

fn shut_read(sock: &VsockSocket) {
    sock.shutdown(crate::uapi::ShutdownHow::Read).expect("connected shutdown read");
}

fn shut_write(sock: &VsockSocket) {
    sock.shutdown(crate::uapi::ShutdownHow::Write).expect("connected shutdown write");
}

#[test]
fn blocked_scalar_io_observes_shutdown_at_retry_boundary() {
    let _guard = serial();
    let (read_sock, _) = connected(0x0b00_0001, 62_001);
    *read_sock.read_retry_hook.lock() = Some(shut_read);
    assert_eq!(read_sock.read(0, &mut [0u8; 1]), Ok(0));

    let (write_sock, _) = connected(0x0b00_0002, 62_002);
    *write_sock.write_retry_hook.lock() = Some(shut_write);
    assert_eq!(write_sock.write(0, b"blocked"), Err(vfs::VfsError::Epipe));
}

#[test]
fn local_send_shutdown_suppresses_writable_poll_readiness() {
    let _guard = serial();
    let (sock, _) = connected(0x0b00_0003, 62_003);

    sock.shutdown(crate::uapi::ShutdownHow::Write).expect("shutdown write");
    assert_eq!(sock.poll() & vfs::POLL_OUT, 0);
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP), 0);

    sock.shutdown(crate::uapi::ShutdownHow::Read).expect("shutdown read");
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP | vfs::POLL_RDHUP),
        vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
}

#[test]
fn duplicate_explicit_bind_fails_at_bind() {
    let _guard = serial();
    let first = VsockSocket::new();
    let duplicate = VsockSocket::new();
    let port = 62_010;
    assert_eq!(first.bind(crate::socket_args::AF_VSOCK as u16, port,
        vsock::VMADDR_CID_ANY), Ok(()));
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, port,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Eaddrinuse));
    assert!(matches!(*duplicate.kind.lock(), VsockKind::Init));
    first.release_file();
}

#[test]
fn concurrent_explicit_bind_has_one_atomic_winner() {
    let table = Arc::new(vsock::VsockTable::new());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let run = |table: Arc<vsock::VsockTable>, barrier: Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            table.reserve_bind(None, Some(62_018))
        })
    };
    let left = run(table.clone(), barrier.clone());
    let right = run(table.clone(), barrier.clone());
    barrier.wait();
    let left = left.join().unwrap();
    let right = right.join().unwrap();
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let winner = left.ok().or_else(|| right.ok()).expect("one bind winner");
    assert!(table.release_bind(&winner));
}

#[test]
fn ephemeral_bind_skips_canonical_identity_conflicts() {
    let table = vsock::VsockTable::new();
    let explicit = table.reserve_bind(None, Some(1024)).expect("explicit reservation");
    let ephemeral = table.reserve_bind(None, None).expect("ephemeral reservation");
    assert_eq!(ephemeral.port, 1025);
    assert!(table.release_bind(&explicit));
    assert!(table.release_bind(&ephemeral));
}

#[test]
fn exact_release_preserves_replacement_and_allows_reuse() {
    let table = vsock::VsockTable::new();
    let old = table.reserve_bind(None, Some(62_011)).expect("old reservation");
    assert!(table.release_bind(&old));
    let replacement = table.reserve_bind(None, Some(62_011)).expect("replacement reservation");
    assert!(!table.release_bind(&old));
    assert!(matches!(table.reserve_bind(None, Some(62_011)),
        Err(crate::NetError::Eaddrinuse)));
    assert!(table.release_bind(&replacement));
    let reused = table.reserve_bind(None, Some(62_011)).expect("released identity reusable");
    assert!(table.release_bind(&reused));
}

#[test]
fn listener_promotion_requires_the_exact_bind_token() {
    let table = vsock::VsockTable::new();
    let old = table.reserve_bind(None, Some(62_016)).expect("old reservation");
    assert!(table.add_listener(None, 62_016).is_none());
    assert!(table.release_bind(&old));
    let replacement = table.reserve_bind(None, Some(62_016)).expect("replacement reservation");
    assert!(table.promote_bind(&old).is_none());
    assert!(matches!(table.reserve_bind(None, Some(62_016)),
        Err(crate::NetError::Eaddrinuse)));
    let listener = table.promote_bind(&replacement).expect("exact promotion");
    assert!(table.remove_listener_exact(&listener));
}

#[test]
fn socket_listen_consumes_its_own_reservation() {
    let _guard = serial();
    let sock = VsockSocket::new();
    assert_eq!(sock.bind(crate::socket_args::AF_VSOCK as u16, 62_017,
        vsock::VMADDR_CID_ANY), Ok(()));
    assert_eq!(sock.listen(), Ok(()));
    let listener = match &*sock.kind.lock() {
        VsockKind::Listener(listener) => listener.clone(),
        _ => panic!("expected listener"),
    };
    assert!(Arc::ptr_eq(&listener.bpf_filter, &sock.bpf_filter));
    sock.bpf_filter.attach(crate::bpf_filter::FilterProgram {
        kind: crate::bpf_filter::FilterKind::Ebpf, insns: alloc::vec![1],
    }).unwrap();
    assert!(listener.bpf_filter.is_attached());
    assert_eq!(sock.listen(), Ok(()));
    let duplicate = VsockSocket::new();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, 62_017,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Eaddrinuse));
    sock.release_file();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, 62_017,
        vsock::VMADDR_CID_ANY), Ok(()));
    duplicate.release_file();
}

#[test]
fn accept_transition_notifies_inode_poll_source() {
    let _guard = serial();
    let transport = owner(0x0b00_0010);
    let guest_cid = 0x5b00_0010;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, guest_cid, tx_ok, rx_noop));
    let listener = vsock::TABLE.add_listener(Some(transport), 62_012)
        .expect("listener reservation");
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Listener(listener);
    let inode = make_vsock_socket_inode(sock.clone());
    let file = vfs::File::new(inode.clone(), vfs::Dentry::new(None,
        alloc::string::String::from("vsock-listener"), inode), vfs::OpenFlags::O_RDWR);
    let source = file.poll_subscribers().expect("listener poll source");
    let before = source.generation();
    let request = vsock::VsockHdr {
        src_cid: 2, dst_cid: guest_cid, src_port: 1024, dst_port: 62_012,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(transport, &request, &[]);
    assert!(source.generation() > before);
    assert_ne!(sock.poll() & vfs::POLL_IN, 0);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn connection_rx_credit_shutdown_and_reset_notify_poll_source() {
    let _guard = serial();
    let transport = owner(0x0b00_0011);
    let guest_cid = 0x5b00_0011;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, guest_cid, tx_ok, rx_noop));
    let conn = Arc::new(VsockConn::new(transport, guest_cid, 62_013, 2, 1024,
        VsockState::Connected));
    assert!(vsock::TABLE.insert(conn.clone()));
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    let inode = make_vsock_socket_inode(sock.clone());
    let file = vfs::File::new(inode.clone(), vfs::Dentry::new(None,
        alloc::string::String::from("vsock-conn"), inode), vfs::OpenFlags::O_RDWR);
    let source = file.poll_subscribers().expect("connection poll source");

    let mut generation = source.generation();
    vsock::deliver_rx_from(transport,
        &inbound(&conn, vsock::VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0, 0), &[]);
    assert!(source.generation() > generation);
    assert_ne!(sock.poll() & vfs::POLL_OUT, 0);
    generation = source.generation();
    vsock::deliver_rx_from(transport, &inbound(&conn, vsock::VIRTIO_VSOCK_OP_RW, 0, 1), b"x");
    assert!(source.generation() > generation);
    assert_ne!(sock.poll() & vfs::POLL_IN, 0);
    generation = source.generation();
    vsock::deliver_rx_from(transport,
        &inbound(&conn, vsock::VIRTIO_VSOCK_OP_RST, 0, 0), &[]);
    assert!(source.generation() > generation);
    assert_ne!(sock.poll() & vfs::POLL_HUP, 0);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn peer_receive_shutdown_blocks_writes_but_peer_send_shutdown_does_not() {
    let _guard = serial();
    let recv_owner = owner(0x0b00_0012);
    let send_owner = owner(0x0b00_0013);
    let recv_cid = 0x5b00_0012;
    let send_cid = 0x5b00_0013;
    let _ = vsock::driver_uninstall(recv_owner);
    let _ = vsock::driver_uninstall(send_owner);
    assert!(vsock::driver_install(recv_owner, recv_cid, tx_ok, rx_noop));
    assert!(vsock::driver_install(send_owner, send_cid, tx_ok, rx_noop));

    let recv_conn = Arc::new(VsockConn::new(recv_owner, recv_cid, 62_014, 2, 1024,
        VsockState::Connected));
    assert!(vsock::TABLE.insert(recv_conn.clone()));
    let recv_sock = VsockSocket::new();
    *recv_sock.kind.lock() = VsockKind::Conn(recv_conn.clone());
    vsock::deliver_rx_from(recv_owner, &inbound(&recv_conn,
        vsock::VIRTIO_VSOCK_OP_SHUTDOWN, vsock::VIRTIO_VSOCK_SHUTDOWN_RCV, 0), &[]);
    assert_eq!(recv_sock.write(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(recv_sock.write_nonblock(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(recv_sock.read_nonblock(0, &mut [0u8; 1]), Err(vfs::VfsError::Eagain));
    assert_eq!(recv_sock.poll() & vfs::POLL_OUT, 0);

    let send_conn = Arc::new(VsockConn::new(send_owner, send_cid, 62_015, 2, 1024,
        VsockState::Connected));
    assert!(vsock::TABLE.insert(send_conn.clone()));
    let send_sock = VsockSocket::new();
    *send_sock.kind.lock() = VsockKind::Conn(send_conn.clone());
    vsock::deliver_rx_from(send_owner, &inbound(&send_conn,
        vsock::VIRTIO_VSOCK_OP_SHUTDOWN, vsock::VIRTIO_VSOCK_SHUTDOWN_SEND, 0), &[]);
    assert_eq!(send_sock.read_nonblock(0, &mut [0u8; 1]), Ok(0));
    assert_eq!(send_sock.write_nonblock(0, b"writable"), Ok(8));
    assert_ne!(send_sock.poll() & vfs::POLL_OUT, 0);
    assert_ne!(send_sock.poll() & vfs::POLL_RDHUP, 0);

    recv_sock.release_file();
    send_sock.release_file();
    assert!(vsock::driver_uninstall(recv_owner));
    assert!(vsock::driver_uninstall(send_owner));
}

#[test]
fn bind_is_typed_one_way_state_transition_and_cannot_orphan_records() {
    let _guard = serial();
    let init = VsockSocket::new();
    assert_eq!(init.bind(1, 62_004, vsock::VMADDR_CID_ANY), Err(crate::NetError::Eafnosupport));
    assert!(matches!(*init.kind.lock(), VsockKind::Init));
    assert_eq!(init.bind(crate::socket_args::AF_VSOCK as u16, vsock::VMADDR_PORT_ANY,
        vsock::VMADDR_CID_ANY), Ok(()));
    let bound_port = match *init.kind.lock() {
        VsockKind::Bound { port, owner: None } => port,
        _ => panic!("expected wildcard bound endpoint"),
    };
    assert_ne!(bound_port, vsock::VMADDR_PORT_ANY);
    assert_eq!(init.bind(crate::socket_args::AF_VSOCK as u16, 62_005,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Einval));
    assert_eq!(init.local_addr(), Ok((bound_port, vsock::VMADDR_CID_ANY)));

    let (connected_sock, conn) = connected(0x0b00_0004, 62_006);
    let key = ConnKey { owner: conn.owner, local_cid: conn.local_cid,
        local_port: conn.local_port, peer_cid: conn.peer_cid, peer_port: conn.peer_port };
    assert!(vsock::TABLE.insert(conn.clone()));
    assert_eq!(connected_sock.bind(crate::socket_args::AF_VSOCK as u16, 62_007,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Einval));
    assert!(Arc::ptr_eq(&vsock::TABLE.find(key).expect("connection retained"), &conn));

    let listener_owner = owner(0x0b00_0005);
    let listener = vsock::TABLE.add_listener(Some(listener_owner), 62_008)
        .expect("listener inserted");
    let listener_sock = VsockSocket::new();
    *listener_sock.kind.lock() = VsockKind::Listener(listener.clone());
    assert_eq!(listener_sock.bind(crate::socket_args::AF_VSOCK as u16, 62_009,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Einval));
    assert!(vsock::TABLE.is_listening(listener_owner, 62_008));

    connected_sock.release_file();
    listener_sock.release_file();
}
