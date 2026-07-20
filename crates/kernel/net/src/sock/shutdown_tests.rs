use super::*;

const INVALID_SHUTDOWN_DIRECTION: u32 = u32::MAX;

fn deny_shutdown(_context: security::network::Context) -> security::network::Verdict {
    security::network::Verdict::Deny
}

#[test]
fn shutdown_security_precedes_raw_direction_validation() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = crate::net_ns::namespace_id(&owner);
    let sock = InetSocket::new_udp_in(owner);
    assert_eq!(security::network::install(id, security::network::Operation::Shutdown,
        deny_shutdown), None);
    assert_eq!(shutdown_raw(&sock, INVALID_SHUTDOWN_DIRECTION), Err(NetError::Eacces));
    assert_eq!(security::network::counters(id, security::network::Operation::Shutdown), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Shutdown).is_some());
}
