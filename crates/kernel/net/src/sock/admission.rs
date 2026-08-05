use super::{InetSocket, NetError};

/// Canonical successful admission for one listen transaction.
pub struct ListenAdmission(());

/// Canonical successful admission for one accept transaction.
pub struct AcceptAdmission(());

/// Apply generic listen security before namespace lookup or family dispatch.
/// # C: O(1)
pub fn admit_listen(sock: &InetSocket) -> Result<ListenAdmission, NetError> {
    crate::security_admission::check(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire),
        security::network::Operation::Listen)?;
    Ok(ListenAdmission(()))
}

/// Apply generic accept security before queue inspection or family dispatch.
/// # C: O(1)
pub fn admit_accept(sock: &InetSocket) -> Result<AcceptAdmission, NetError> {
    crate::security_admission::check(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire),
        security::network::Operation::Accept)?;
    Ok(AcceptAdmission(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(context: security::network::Context) -> security::network::Verdict {
        assert_eq!(context.family, crate::sock::AF_INET);
        security::network::Verdict::Deny
    }

    #[test]
    fn listen_and_accept_use_the_socket_namespace_hook_before_dispatch() {
        let owner = crate::net_ns::test_support::allocate_namespace();
        let namespace = owner.id().as_u64();
        let sock = InetSocket::new_tcp_in(owner);
        for operation in [security::network::Operation::Listen, security::network::Operation::Accept] {
            assert!(security::network::install(namespace, operation, deny).is_none());
        }
        assert!(matches!(admit_listen(&sock), Err(NetError::Eacces)));
        assert!(matches!(admit_accept(&sock), Err(NetError::Eacces)));
        assert_eq!(security::network::counters(namespace, security::network::Operation::Listen), Some((0, 1)));
        assert_eq!(security::network::counters(namespace, security::network::Operation::Accept), Some((0, 1)));
        assert!(security::network::remove_namespace(namespace) >= 2);
    }
}
