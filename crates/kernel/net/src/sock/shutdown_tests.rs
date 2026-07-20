use super::*;

#[test]
fn unix_listener_shutdown_latches_without_closing_listener() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sock = InetSocket::new_unix_in(owner);
    let listener = crate::UnixListener::new(
        crate::UnixAddr::from_abstract_or_test_path("shutdown-listener".into()));
    let backlog = crate::sysctl::DEFAULT_SOMAXCONN as i32;
    listener.listen(backlog, crate::sysctl::DEFAULT_SOMAXCONN);
    *sock.kind.lock() = SockKind::UnixListener(listener.clone());

    assert_eq!(shutdown(&sock, ShutdownHow::ReadWrite), Ok(()));
    assert!(sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
    assert!(sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
    assert!(listener.is_listening());
}
