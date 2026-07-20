use super::*;
use crate::vsock::{ConnKey, VsockState};

fn owner(raw: u32) -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(raw).expect("test owner is nonzero")
}

fn tx_ok(_: vsock::VsockOwner, _: &[u8]) -> bool { true }
fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }
fn deny_vsock_receive(ctx: security::network::Context) -> security::network::Verdict {
    assert_eq!(ctx.family, crate::socket_args::AF_VSOCK as u16);
    security::network::Verdict::Deny
}
fn deny_vsock_send(ctx: security::network::Context) -> security::network::Verdict {
    assert_eq!(ctx.family, crate::socket_args::AF_VSOCK as u16);
    security::network::Verdict::Deny
}

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

fn file_with_flags(sock: Arc<VsockSocket>, flags: vfs::OpenFlags) -> Arc<vfs::File> {
    let inode = make_vsock_socket_inode(sock);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
    vfs::File::new(inode, dentry, flags)
}

fn file(sock: Arc<VsockSocket>) -> Arc<vfs::File> {
    file_with_flags(sock, vfs::OpenFlags::O_RDWR)
}

#[test]
fn inode_is_a_nonseekable_socket() {
    let sock = Arc::new(VsockSocket::new());
    let file = file(sock.clone());
    assert_eq!(file.inode().file_type(), vfs::FileType::Socket);
    assert!(Arc::ptr_eq(&file.poll_subscribers().expect("VSOCK poll source"),
        &sock.poll_subs));
    assert!(!file.f_mode().contains(vfs::Fmode::LSEEK));
    assert!(!file.f_mode().contains(vfs::Fmode::PREAD));
    assert!(!file.f_mode().contains(vfs::Fmode::PWRITE));
}

#[test]
fn virtio_dgram_retains_linux_transport_and_shutdown_contracts() {
    const EPHEMERAL_PORT: u32 = 0;
    const FILE_OFFSET: u64 = 0;
    let sock = VsockSocket::new_type(crate::socket_args::SOCK_DGRAM);
    assert_eq!(sock.socket_type(), VsockSocketType::Datagram);
    assert_eq!(sock.bind(crate::socket_args::AF_VSOCK as u16, EPHEMERAL_PORT,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Eopnotsupp));
    assert_eq!(sock.read_nonblock(FILE_OFFSET, &mut []), Err(vfs::VfsError::Eopnotsupp));
    assert_eq!(sock.write_nonblock(FILE_OFFSET, &[]), Err(vfs::VfsError::Eopnotsupp));
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Read), Err(crate::NetError::Enotconn));
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_RDHUP),
        vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_RDHUP);
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Err(crate::NetError::Enotconn));
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP | vfs::POLL_RDHUP),
        vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
    assert_eq!(sock.write_nonblock(FILE_OFFSET, &[]), Err(vfs::VfsError::Epipe));
}

#[test]
fn vsock_buffer_options_enforce_linux_relationships() {
    const BELOW_MINIMUM_BUFFER_SIZE: i32 = 64;
    const REDUCED_MAXIMUM_BUFFER_SIZE: i32 = 1024;
    const ABOVE_REDUCED_MAXIMUM_BUFFER_SIZE: i32 = 2048;
    const INVALID_INTERMEDIATE_BUFFER_SIZE: i32 = 512;
    const INVALID_REDUCED_MAXIMUM_BUFFER_SIZE: i32 = 256;
    const UNKNOWN_VSOCK_OPTION: u64 = 99;
    let sock = VsockSocket::new();
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_SIZE));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MIN_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_MIN_SIZE));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MAX_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_MAX_SIZE));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        BELOW_MINIMUM_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_MIN_SIZE));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MAX_SIZE,
        REDUCED_MAXIMUM_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(REDUCED_MAXIMUM_BUFFER_SIZE as u64));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MIN_SIZE,
        ABOVE_REDUCED_MAXIMUM_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(REDUCED_MAXIMUM_BUFFER_SIZE as u64));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MIN_SIZE,
        REDUCED_MAXIMUM_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        INVALID_INTERMEDIATE_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(REDUCED_MAXIMUM_BUFFER_SIZE as u64));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_MAX_SIZE,
        INVALID_REDUCED_MAXIMUM_BUFFER_SIZE as u64), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(INVALID_REDUCED_MAXIMUM_BUFFER_SIZE as u64));
    assert_eq!(sock.get_vsock_buffer_option(UNKNOWN_VSOCK_OPTION),
        Err(crate::NetError::Enoprotoopt));
}

fn connection(raw_owner: u32, port: u32) -> (ConnKey, Arc<VsockConn>) {
    let owner = owner(raw_owner);
    let key = ConnKey { owner, local_cid: 3, local_port: port, peer_cid: 2, peer_port: 1024 };
    vsock::TABLE.remove(key);
    let conn = Arc::new(VsockConn::new(owner, key.local_cid, key.local_port,
        key.peer_cid, key.peer_port, VsockState::Connected));
    assert!(vsock::TABLE.insert(conn.clone()));
    (key, conn)
}

fn accepted_connection(raw_owner: u32, port: u32)
    -> (ConnKey, Arc<VsockConn>, Arc<VsockSocket>)
{
    let owner = owner(raw_owner);
    let key = ConnKey { owner, local_cid: 0x3000_0000 + raw_owner as u64,
        local_port: port, peer_cid: 2, peer_port: 1024 };
    vsock::TABLE.remove(key);
    let _ = vsock::TABLE.remove_listener(Some(owner), port);
    let _ = vsock::driver_uninstall(owner);
    assert!(vsock::driver_install(owner, key.local_cid, tx_ok, rx_noop));
    let listener_record = vsock::TABLE.add_listener(Some(owner), port)
        .expect("listener registration");
    let listener = Arc::new(VsockSocket::new());
    *listener.kind.lock() = VsockKind::Listener(listener_record);
    let request = vsock::VsockHdr {
        src_cid: key.peer_cid, dst_cid: key.local_cid,
        src_port: key.peer_port, dst_port: key.local_port,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_REQUEST, flags: 0,
        buf_alloc: 8192, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(owner, &request, &[]);
    let conn = vsock::TABLE.find(key).expect("RX passive child publication");
    let accepted = listener.accept().expect("accept published VSOCK child");
    drop(listener);
    assert!(vsock::TABLE.find(key).is_some(), "accepted child outlives listener");
    (key, conn, accepted)
}

#[test]
fn socket_retains_concrete_namespace_owner() {
    let namespace = namespace();
    let id = namespace.id();
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace.clone());
    drop(namespace);
    assert!(network_namespace::lookup(id).is_some(), "socket pins namespace lifetime");
    drop(sock);
    assert!(network_namespace::lookup(id).is_none(), "last socket drop releases namespace");
}

#[test]
fn accepted_socket_clones_listener_namespace_owner() {
    const ACCEPTED_BUFFER_SIZE: u64 = 64 * 1024;
    const ACCEPTED_TIMEOUT_SECONDS: u64 = 3;
    const ACCEPTED_TIMEOUT_NANOSECONDS: u64 = ACCEPTED_TIMEOUT_SECONDS
        * crate::uapi::VSOCK_NANOSECONDS_PER_SECOND;
    let namespace = namespace();
    let listener = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace.clone());
    assert_eq!(listener.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        ACCEPTED_BUFFER_SIZE), Ok(()));
    listener.set_vsock_connect_timeout_ns(ACCEPTED_TIMEOUT_NANOSECONDS);
    let accepted = VsockSocket::new_accepted(&listener);
    assert!(Arc::ptr_eq(&listener.net_namespace, &accepted.net_namespace));
    assert_eq!(accepted.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(ACCEPTED_BUFFER_SIZE));
    assert_eq!(accepted.vsock_connect_timeout_ns(), ACCEPTED_TIMEOUT_NANOSECONDS);
    drop(namespace); drop(listener);
    assert!(network_namespace::lookup(accepted.net_namespace.id()).is_some());
}

#[test]
fn receive_admission_uses_socket_namespace_and_operation() {
    let namespace = namespace();
    let id = crate::net_ns::namespace_id(&namespace);
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    assert_eq!(security::network::install(id, security::network::Operation::Receive,
        deny_vsock_receive), None);
    assert_eq!(sock.check_receive(), Err(crate::NetError::Eacces));
    assert_eq!(security::network::counters(id, security::network::Operation::Receive), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Receive).is_some());
    assert_eq!(sock.check_receive(), Ok(()));
}

#[test]
fn send_admission_uses_socket_namespace_and_operation() {
    let namespace = namespace();
    let id = crate::net_ns::namespace_id(&namespace);
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    assert_eq!(security::network::install(id, security::network::Operation::Send,
        deny_vsock_send), None);
    assert_eq!(sock.check_send(), Err(crate::NetError::Eacces));
    assert_eq!(security::network::counters(id, security::network::Operation::Send), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Send).is_some());
    assert_eq!(sock.check_send(), Ok(()));
}

#[test]
fn accepted_socket_uses_exact_pending_connection_filter_snapshot() {
    let _guard = vsock::tests::test_domain();
    let owner = owner(0x0a00_0042);
    let port = 61_042;
    let listener_record = vsock::TABLE.add_listener(Some(owner), port)
        .expect("listener registration");
    let listener = VsockSocket::new();
    listener.bpf_filter.attach(crate::bpf_filter::FilterProgram {
        kind: crate::bpf_filter::FilterKind::Ebpf, insns: 7u32.to_ne_bytes().to_vec(),
    }).unwrap();
    *listener.kind.lock() = VsockKind::Listener(listener_record);

    let conn = Arc::new(VsockConn::new(owner, 3, port, 2, 1024, VsockState::Connected));
    conn.bpf_filter.attach(crate::bpf_filter::FilterProgram {
        kind: crate::bpf_filter::FilterKind::Ebpf, insns: 3u32.to_ne_bytes().to_vec(),
    }).unwrap();
    conn.bpf_filter.set_lock(true).unwrap();
    assert!(vsock::TABLE.insert(conn.clone()));
    vsock::TABLE.queue_accept(owner, port, conn.key());

    let child = listener.accept().expect("accepted child");
    assert!(Arc::ptr_eq(&child.bpf_filter, &conn.bpf_filter));
    assert!(child.bpf_filter.is_attached());
    assert!(child.bpf_filter.is_locked());
    assert_eq!(child.bpf_filter.detach(), Err(crate::bpf_filter::FilterChangeError::Locked));
    vsock::TABLE.remove_conn(&conn);
}

#[test]
fn drop_listener_removes_vsock_listener() {
    let _guard = vsock::tests::test_domain();
    let owner = Some(owner(0x0a00_0001));
    let port = 61_001;
    let _ = vsock::TABLE.remove_listener(owner, port);
    let listener = vsock::TABLE.add_listener(owner, port).expect("listener registration");
    let (key, conn) = connection(owner.unwrap().raw(), port);
    vsock::TABLE.queue_accept(owner.unwrap(), port, key);
    assert!(vsock::TABLE.is_listening(owner.unwrap(), port));
    assert!(vsock::TABLE.pop_accept_peek(owner, port));

    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Listener(listener);
    drop(sock);

    assert!(!vsock::TABLE.is_listening(owner.unwrap(), port));
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    assert!(!vsock::TABLE.remove_listener(owner, port));
}

#[test]
fn drop_connected_socket_closes_connection_record() {
    let _guard = vsock::tests::test_domain();
    let (key, conn) = connection(0x0a00_0002, 61_002);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    drop(sock);
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
}

#[test]
fn final_file_release_removes_listener_before_socket_object_drop() {
    let _guard = vsock::tests::test_domain();
    let owner = Some(owner(0x0a00_0003));
    let port = 61_003;
    let _ = vsock::TABLE.remove_listener(owner, port);
    let listener = vsock::TABLE.add_listener(owner, port).expect("listener registration");
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Listener(listener);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(sock.clone())).unwrap();
    let dup = fdt.dup(fd).unwrap();

    fdt.close(fd).unwrap();
    assert!(vsock::TABLE.is_listening(owner.unwrap(), port));
    fdt.close(dup).unwrap();

    assert!(!vsock::TABLE.is_listening(owner.unwrap(), port));
    sock.release_file();
    assert!(!vsock::TABLE.remove_listener(owner, port));
}

#[test]
fn final_file_release_closes_connection_before_socket_object_drop() {
    let _guard = vsock::tests::test_domain();
    let (key, conn) = connection(0x0a00_0004, 61_004);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(sock.clone())).unwrap();
    let dup = fdt.dup(fd).unwrap();
    let child = fdt.fork_clone();

    fdt.close(fd).unwrap();
    fdt.close(dup).unwrap();
    child.close(fd).unwrap();
    assert_eq!(*conn.st.lock(), VsockState::Connected);
    assert!(vsock::TABLE.find(key).is_some());
    child.close(dup).unwrap();

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    sock.release_file();
    assert_eq!(*conn.st.lock(), VsockState::Closed);
}

#[test]
fn failed_fd_install_releases_unpublished_connection() {
    let _guard = vsock::tests::test_domain();
    let (key, conn) = connection(0x0a00_0005, 61_005);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    let fdt = vfs::FdTable::new();

    assert_eq!(fdt.install_limit(file(sock.clone()), vfs::OpenFlags::empty(), 0),
        Err(vfs::VfsError::Emfile));

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    sock.release_file();
}

#[test]
fn active_file_pin_survives_close_and_exact_fd_reuse() {
    let _guard = vsock::tests::test_domain();
    let (old_key, old_conn) = connection(0x0a00_0006, 61_006);
    let old = Arc::new(VsockSocket::new());
    *old.kind.lock() = VsockKind::Conn(old_conn.clone());
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(old)).unwrap();
    let pin = fdt.get(fd).unwrap();

    fdt.close(fd).unwrap();
    let (new_key, new_conn) = connection(0x0a00_0007, 61_007);
    let replacement = Arc::new(VsockSocket::new());
    *replacement.kind.lock() = VsockKind::Conn(new_conn.clone());
    let replacement_file = file(replacement);
    replacement_file.set_flags(vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    let reused = fdt.alloc(replacement_file).unwrap();
    assert_eq!(reused, fd);
    assert!(!pin.flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(fdt.get(reused).unwrap().flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(vsock::TABLE.find(old_key).is_some());

    drop(pin);
    assert_eq!(*old_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(old_key).is_none());
    assert_eq!(*new_conn.st.lock(), VsockState::Connected);
    fdt.close(reused).unwrap();
    assert_eq!(*new_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(new_key).is_none());
}

#[test]
fn accepted_connection_duplicate_and_fork_release_only_after_final_close() {
    let _guard = vsock::tests::test_domain();
    let (key, conn, accepted) = accepted_connection(0x0a00_0008, 61_008);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(accepted)).unwrap();
    let dup = fdt.dup(fd).unwrap();
    let child = fdt.fork_clone();

    fdt.close(fd).unwrap();
    fdt.close(dup).unwrap();
    child.close(fd).unwrap();
    assert_eq!(*conn.st.lock(), VsockState::Connected);
    assert!(vsock::TABLE.find(key).is_some());
    child.close(dup).unwrap();

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    assert!(vsock::driver_uninstall(key.owner));
}

#[test]
fn accepted_connection_active_pin_survives_close_and_exact_fd_reuse() {
    let _guard = vsock::tests::test_domain();
    let (old_key, old_conn, accepted) = accepted_connection(0x0a00_0009, 61_009);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(accepted)).unwrap();
    let pin = fdt.get(fd).unwrap();

    fdt.close(fd).unwrap();
    let (new_key, new_conn) = connection(0x0a00_000a, 61_010);
    let replacement = Arc::new(VsockSocket::new());
    *replacement.kind.lock() = VsockKind::Conn(new_conn.clone());
    let reused = fdt.alloc(file_with_flags(replacement,
        vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK)).unwrap();
    assert_eq!(reused, fd);
    assert!(!pin.flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(fdt.get(reused).unwrap().flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(vsock::TABLE.find(old_key).is_some());

    drop(pin);
    assert_eq!(*old_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(old_key).is_none());
    assert_eq!(*new_conn.st.lock(), VsockState::Connected);
    fdt.close(reused).unwrap();
    assert_eq!(*new_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(new_key).is_none());
    assert!(vsock::driver_uninstall(old_key.owner));
}

#[test]
fn accepted_connection_failed_publication_and_table_drop_release_synchronously() {
    let _guard = vsock::tests::test_domain();
    let (failed_key, failed_conn, failed) = accepted_connection(0x0a00_000b, 61_011);
    let fdt = vfs::FdTable::new();
    assert_eq!(fdt.install_limit(file(failed), vfs::OpenFlags::empty(), 0),
        Err(vfs::VfsError::Emfile));
    assert_eq!(*failed_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(failed_key).is_none());
    assert!(vsock::driver_uninstall(failed_key.owner));

    let (drop_key, drop_conn, installed) = accepted_connection(0x0a00_000c, 61_012);
    let fdt = vfs::FdTable::new();
    fdt.alloc(file(installed)).unwrap();
    drop(fdt);
    assert_eq!(*drop_conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(drop_key).is_none());
    assert!(vsock::driver_uninstall(drop_key.owner));
}

#[test]
fn shutdown_is_net_owned_and_latches_both_directions_without_a_driver() {
    let _guard = vsock::tests::test_domain();
    let (key, conn) = connection(0x0a00_000d, 61_013);
    let sock = VsockSocket::new();
    *sock.kind.lock() = VsockKind::Conn(conn.clone());

    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Ok(()));
    assert!(conn.tx.lock().local_shut);
    assert_eq!(sock.write(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(sock.write_nonblock(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(sock.poll() & vfs::POLL_OUT, 0);

    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Read), Ok(()));
    assert!(sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(sock.read(0, &mut [0u8; 1]), Ok(0));
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_RDHUP | vfs::POLL_HUP),
        vfs::POLL_IN | vfs::POLL_RDHUP | vfs::POLL_HUP);

    sock.release_file();
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
}

#[test]
fn pending_recv_error_overwrites_with_latest_positive_errno() {
    let sock = VsockSocket::new();
    assert_eq!(sock.take_pending_recv_error(), 0);
    assert!(!sock.set_pending_recv_error(0));
    assert!(!sock.set_pending_recv_error(-5));
    assert!(sock.set_pending_recv_error(111));
    assert!(sock.set_pending_recv_error(104));
    assert_eq!(sock.take_pending_recv_error(), 104);
    assert_eq!(sock.take_pending_recv_error(), 0);
}
