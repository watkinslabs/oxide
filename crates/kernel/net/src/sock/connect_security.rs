//! Canonical AF socket connect security admission.

use super::{InetSocket, NetError};

/// Canonical successful admission for one connect transaction.
pub struct ConnectAdmission(());

/// Apply generic connect security before protocol parsing or name lookup. # C: O(1)
pub fn admit_connect(sock: &InetSocket) -> Result<ConnectAdmission, NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0,
        protocol: 0,
        operation: security::network::Operation::Connect,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    Ok(ConnectAdmission(()))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    fn deny(_context: security::network::Context) -> security::network::Verdict {
        security::network::Verdict::Deny
    }

    #[test]
    fn denial_precedes_short_address_and_unix_lookup_errors() {
        let owner = crate::net_ns::test_support::allocate_namespace();
        let namespace = owner.id().as_u64();
        let sock = super::InetSocket::new_udp_in(owner);
        assert!(security::network::install(
            namespace, security::network::Operation::Connect, deny,
        ).is_none());
        let parsed = Cell::new(false);
        let short = super::admit_connect(&sock).and_then(|_| {
            parsed.set(true);
            Err::<(), _>(crate::NetError::Einval)
        });
        assert_eq!(short, Err(crate::NetError::Eacces));
        assert!(!parsed.get());
        let looked_up = Cell::new(false);
        let unix = super::admit_connect(&sock).and_then(|_| {
            looked_up.set(true);
            Err::<(), _>(crate::NetError::Enoent)
        });
        assert_eq!(unix, Err(crate::NetError::Eacces));
        assert!(!looked_up.get());
        assert_eq!(
            security::network::counters(namespace, security::network::Operation::Connect),
            Some((0, 2)),
        );
        assert!(security::network::remove(
            namespace, security::network::Operation::Connect,
        ).is_some());
    }
}
