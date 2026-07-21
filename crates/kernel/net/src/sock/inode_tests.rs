use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

type Factory = fn() -> Arc<InetSocket>;

fn file(sock: Arc<InetSocket>, flags: vfs::OpenFlags) -> Arc<vfs::File> {
    let inode = make_inet_socket_inode(sock);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
    vfs::File::new(inode, dentry, flags)
}

fn inet() -> Arc<InetSocket> { Arc::new(InetSocket::new_udp()) }

fn unix() -> Arc<InetSocket> { Arc::new(InetSocket::new_unix()) }

fn accepted_inet() -> Arc<InetSocket> {
    let namespace = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_loopback_into(crate::global_stack(), &namespace);
    let stack = crate::global_stack();
    let listener_bind = stack.tcp_reserve_in(namespace.id().as_u64(),
        crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 0, None, false, false, 0, false)
        .expect("reserve TCP listener");
    let listener = stack.tcp_listen_reserved(&listener_bind).expect("publish TCP listener");
    let client_bind = stack.tcp_reserve_in(namespace.id().as_u64(),
        crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), 0, None, false, false, 0, false)
        .expect("reserve TCP client");
    let client = stack.tcp_connect_reserved(&client_bind,
        crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK),
        crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), listener.local.port,
        Arc::new(crate::SocketError::new())).expect("start TCP handshake");
    drain_loopback();
    let child = stack.tcp_accept(&listener).expect("accept passive TCP child");
    let listener_sock = InetSocket::new_tcp_in(namespace);
    let accepted = InetSocket::from_accepted_tcp(&listener_sock, child);
    stack.tcp_unlisten_entry(&listener);
    stack.tcp_release_bind(&listener_bind);
    stack.tcp_disconnect_entry(&client);
    stack.tcp_release_bind(&client_bind);
    accepted
}

fn accepted_unix() -> Arc<InetSocket> {
    static SERIAL: AtomicU32 = AtomicU32::new(1);
    let namespace = crate::net_ns::initial_namespace();
    let addr = crate::UnixAddr::from_abstract_or_test_path(alloc::format!(
        "\0b854-accepted-unix-{}", SERIAL.fetch_add(1, Ordering::Relaxed)));
    let registry = crate::net_ns::unix_registry_for_addr_in(&namespace, &addr);
    let listener = registry.bind_addr(addr.clone()).expect("bind UNIX listener");
    listener.listen(4, crate::sysctl::DEFAULT_SOMAXCONN);
    let client = registry.connect_addr(&addr).expect("queue UNIX client");
    let (pair, pin) = listener.accept().expect("accept queued UNIX child");
    let listener_sock = InetSocket::new_unix_in(namespace);
    let accepted = InetSocket::from_accepted_unix(&listener_sock, pair);
    drop(pin);
    drop(client);
    registry.unbind_addr(&addr);
    accepted
}

#[test]
fn accepted_unix_socket_snapshots_listener_filter_and_lock() {
    let _guard = crate::unix_sock::test_support::guard();
    let listener = InetSocket::new_unix();
    listener.bpf_filter.attach(crate::bpf_filter::FilterProgram {
        kind: crate::bpf_filter::FilterKind::Ebpf, insns: 3u32.to_ne_bytes().to_vec(),
    }).unwrap();
    listener.bpf_filter.set_lock(true).unwrap();
    let child = InetSocket::from_accepted_unix(&listener, crate::UnixPair::new());
    assert!(child.bpf_filter.is_attached());
    assert!(child.bpf_filter.is_locked());
    assert_eq!(child.bpf_filter.detach(), Err(crate::bpf_filter::FilterChangeError::Locked));
}

#[test]
fn unix_socket_creation_owns_and_keeps_its_gc_receive_queue() {
    let _guard = crate::unix_sock::test_support::guard();
    let sock = unix();
    let (pair, end) = match &*sock.kind.lock() {
        SockKind::UnixUnbound(pair, end) => (pair.clone(), *end),
        _ => panic!("AF_UNIX socket must own an unbound Unix endpoint"),
    };
    let socket_file = file(sock.clone(), vfs::OpenFlags::O_RDWR);
    assert!(crate::unix_sock::bind_file(&socket_file, &sock));
    assert!(pair.gc_node(end).is_bound_to(&socket_file));

    *sock.kind.lock() = SockKind::Unix(pair.clone(), end);
    assert!(pair.gc_node(end).is_bound_to(&socket_file));
}

const FACTORIES: [Factory; 4] = [inet, accepted_inet, unix, accepted_unix];

fn assert_open(sock: &InetSocket) { assert!(!sock.released.load(Ordering::Acquire)); }
fn assert_released(sock: &InetSocket) { assert!(sock.released.load(Ordering::Acquire)); }

#[test]
fn socket_inode_is_nonseekable_for_every_inet_factory() {
    let _guard = crate::unix_sock::test_support::guard();
    for factory in FACTORIES {
        let file = file(factory(), vfs::OpenFlags::O_RDWR);
        assert_eq!(file.inode().file_type(), vfs::FileType::Socket);
        assert!(!file.f_mode().contains(vfs::Fmode::LSEEK));
        assert!(!file.f_mode().contains(vfs::Fmode::PREAD));
        assert!(!file.f_mode().contains(vfs::Fmode::PWRITE));
    }
}

#[test]
fn duplicate_and_forked_descriptors_release_only_after_final_close() {
    let _guard = crate::unix_sock::test_support::guard();
    for factory in FACTORIES {
        let sock = factory();
        let parent = vfs::FdTable::new();
        let fd = parent.alloc(file(sock.clone(), vfs::OpenFlags::O_RDWR)).unwrap();
        let dup = parent.dup(fd).unwrap();
        let child = parent.fork_clone();

        parent.close(fd).unwrap();
        parent.close(dup).unwrap();
        assert_open(&sock);
        child.close(fd).unwrap();
        assert_open(&sock);
        child.close(dup).unwrap();
        assert_released(&sock);
    }
}

#[test]
fn active_file_pin_survives_close_and_exact_fd_reuse() {
    let _guard = crate::unix_sock::test_support::guard();
    for factory in FACTORIES {
        let old = factory();
        let fdt = vfs::FdTable::new();
        let fd = fdt.alloc(file(old.clone(), vfs::OpenFlags::O_RDWR)).unwrap();
        let pin = fdt.get(fd).unwrap();

        fdt.close(fd).unwrap();
        let replacement = factory();
        let reused = fdt.alloc(file(replacement.clone(),
            vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK)).unwrap();
        assert_eq!(reused, fd);
        assert!(!pin.flags().contains(vfs::OpenFlags::O_NONBLOCK));
        assert!(fdt.get(reused).unwrap().flags().contains(vfs::OpenFlags::O_NONBLOCK));
        assert_open(&old);

        drop(pin);
        assert_released(&old);
        assert_open(&replacement);
        fdt.close(reused).unwrap();
        assert_released(&replacement);
    }
}

#[test]
fn failed_publication_and_table_drop_release_synchronously() {
    let _guard = crate::unix_sock::test_support::guard();
    for factory in FACTORIES {
        let unpublished = factory();
        let fdt = vfs::FdTable::new();
        assert_eq!(fdt.install_limit(file(unpublished.clone(), vfs::OpenFlags::O_RDWR),
            vfs::OpenFlags::empty(), 0), Err(vfs::VfsError::Emfile));
        assert_released(&unpublished);

        let installed = factory();
        let fdt = vfs::FdTable::new();
        fdt.alloc(file(installed.clone(), vfs::OpenFlags::O_RDWR)).unwrap();
        drop(fdt);
        assert_released(&installed);
    }
}
