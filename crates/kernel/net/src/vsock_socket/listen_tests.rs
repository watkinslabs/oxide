use super::*;

const TEST_TRANSPORT_OWNER: u32 = 0x0D00_0010;
const TEST_GUEST_CID: u64 = 0x5D00_0010;
const TEST_LISTEN_PORT: u32 = 63_100;
const TEST_BACKLOG_LIMIT: usize = 3;
const REQUESTED_BACKLOG: i32 = 7;

fn owner() -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(TEST_TRANSPORT_OWNER).expect("test owner is nonzero")
}

fn tx_ok(_: vsock::VsockOwner, _: &[u8]) -> bool { true }
fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }

fn deny_vsock_listen(context: security::network::Context) -> security::network::Verdict {
    assert_eq!(context.family, crate::socket_args::AF_VSOCK as u16);
    security::network::Verdict::Deny
}

fn deny_vsock_operation(context: security::network::Context) -> security::network::Verdict {
    assert_eq!(context.family, crate::socket_args::AF_VSOCK as u16);
    security::network::Verdict::Deny
}

#[test]
fn listen_uses_retained_namespace_security_and_somaxconn() {
    use core::sync::atomic::Ordering;
    let _domain = vsock::tests::test_domain();
    let transport = owner();
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, TEST_GUEST_CID, tx_ok, rx_noop));

    let namespace = crate::net_ns::test_support::allocate_namespace();
    let namespace_id = crate::net_ns::namespace_id(&namespace);
    assert_eq!(crate::sysctl::set_somaxconn_in(namespace_id, TEST_BACKLOG_LIMIT), Ok(()));
    let socket = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    assert_eq!(socket.bind(crate::socket_args::AF_VSOCK as u16, TEST_LISTEN_PORT,
        TEST_GUEST_CID), Ok(()));

    assert_eq!(security::network::install(namespace_id, security::network::Operation::Listen,
        deny_vsock_listen), None);
    assert_eq!(socket.listen_with_backlog(REQUESTED_BACKLOG), Err(crate::NetError::Eacces));
    assert!(matches!(*socket.kind.lock(), VsockKind::Bound { .. }));
    assert_eq!(security::network::counters(namespace_id, security::network::Operation::Listen),
        Some((0, 1)));
    assert!(security::network::remove(namespace_id, security::network::Operation::Listen).is_some());

    assert_eq!(socket.listen_with_backlog(REQUESTED_BACKLOG), Ok(()));
    let listener = match &*socket.kind.lock() {
        VsockKind::Listener(listener) => listener.clone(),
        _ => panic!("VSOCK listener was not published"),
    };
    assert_eq!(listener.backlog_cap.load(Ordering::Acquire), TEST_BACKLOG_LIMIT);
    socket.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn lifecycle_operations_admit_before_vsock_state_transition() {
    const TEST_BIND_PORT: u32 = 63_101;
    const TEST_PEER_CID: u64 = 2;
    const TEST_PEER_PORT: u32 = 1_024;
    let namespace = crate::net_ns::test_support::allocate_namespace();
    let namespace_id = crate::net_ns::namespace_id(&namespace);

    let bind_socket = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace.clone());
    assert_eq!(security::network::install(namespace_id, security::network::Operation::Bind,
        deny_vsock_operation), None);
    assert_eq!(bind_socket.bind(crate::socket_args::AF_VSOCK as u16, TEST_BIND_PORT,
        vsock::VMADDR_CID_ANY), Err(crate::NetError::Eacces));
    assert!(matches!(*bind_socket.kind.lock(), VsockKind::Init));
    assert!(security::network::remove(namespace_id, security::network::Operation::Bind).is_some());

    let connect_socket = Arc::new(VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM,
        namespace.clone()));
    assert_eq!(security::network::install(namespace_id, security::network::Operation::Connect,
        deny_vsock_operation), None);
    assert_eq!(connect_socket.connect_transport(TEST_PEER_CID, TEST_PEER_PORT, true),
        Err(crate::NetError::Eacces));
    assert!(matches!(*connect_socket.kind.lock(), VsockKind::Init));
    assert!(security::network::remove(namespace_id, security::network::Operation::Connect).is_some());

    let accept_socket = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    assert_eq!(security::network::install(namespace_id, security::network::Operation::Accept,
        deny_vsock_operation), None);
    assert!(matches!(accept_socket.accept(), Err(crate::NetError::Eacces)));
    assert!(security::network::remove(namespace_id, security::network::Operation::Accept).is_some());

    let option_socket = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM,
        crate::net_ns::test_support::allocate_namespace());
    let option_namespace = option_socket.net_ns();
    assert_eq!(security::network::install(option_namespace, security::network::Operation::Option,
        deny_vsock_operation), None);
    assert_eq!(option_socket.check_option(), Err(crate::NetError::Eacces));
    assert!(security::network::remove(option_namespace, security::network::Operation::Option).is_some());
}
