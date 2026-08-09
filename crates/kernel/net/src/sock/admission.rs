use super::{InetSocket, NetError};

/// Canonical successful admission for one listen transaction.
pub struct ListenAdmission(());

/// Canonical successful admission for one accept transaction.
pub struct AcceptAdmission(());

/// Apply generic listen security before namespace lookup or family dispatch.
/// `backlog` is the caller's requested backlog after `somaxconn` clamping, so
/// an installed hook sees the same value Linux's `security_socket_listen`
/// does. # C: O(1)
pub fn admit_listen(sock: &InetSocket, backlog: u32) -> Result<ListenAdmission, NetError> {
    crate::security_admission::check_listen(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), backlog)?;
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
        assert!(matches!(admit_listen(&sock, 128), Err(NetError::Eacces)));
        assert!(matches!(admit_accept(&sock), Err(NetError::Eacces)));
        assert_eq!(security::network::counters(namespace, security::network::Operation::Listen), Some((0, 1)));
        assert_eq!(security::network::counters(namespace, security::network::Operation::Accept), Some((0, 1)));
        assert!(security::network::remove_namespace(namespace) >= 2);
    }

    /// Pins the `listen(2)` backlog operand reaching the LSM hook, matching
    /// Linux's `security_socket_listen(sock, backlog)`. Before the fix this
    /// closure discarded the caller's backlog (`sock/ops.rs` handed the hook
    /// a `|_|` closure), so a hook could never see or veto on it — this test
    /// fails red against that shape because `SEEN` would observe `None`.
    static SEEN: sync::Spinlock<Option<Option<u32>>, sync::Namespace> = sync::Spinlock::new(None);

    fn record(context: security::network::Context) -> security::network::Verdict {
        *SEEN.lock() = Some(context.backlog);
        security::network::Verdict::Allow
    }

    #[test]
    fn admit_listen_forwards_the_callers_backlog_to_the_security_hook() {
        let owner = crate::net_ns::test_support::allocate_namespace();
        let namespace = owner.id().as_u64();
        let sock = InetSocket::new_tcp_in(owner);
        *SEEN.lock() = None;
        assert!(security::network::install(namespace, security::network::Operation::Listen, record)
            .is_none());
        assert!(admit_listen(&sock, 42).is_ok());
        assert_eq!(*SEEN.lock(), Some(Some(42)),
            "the security hook must receive the caller's listen(2) backlog");
        assert!(security::network::remove_namespace(namespace) >= 1);
    }
}
