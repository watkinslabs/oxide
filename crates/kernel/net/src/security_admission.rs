//! Namespace-scoped network security admission shared by every socket family.

/// Evaluate one network operation against the socket's retained namespace. # C: O(1)
pub fn check(namespace: u64, family: u16, operation: security::network::Operation)
    -> Result<(), crate::NetError>
{
    let context = security::network::Context { namespace, family, socket_type: 0, protocol: 0, operation };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use security::network::{self, Operation, Verdict};

    fn deny_family(context: network::Context) -> Verdict {
        assert_eq!(context.family, 10);
        Verdict::Deny
    }

    fn allow(_context: network::Context) -> Verdict { Verdict::Allow }

    #[test]
    fn admission_preserves_namespace_operation_and_family_context() {
        let _ = network::remove_namespace(31);
        let _ = network::remove_namespace(32);
        assert_eq!(network::install(31, Operation::Connect, deny_family), None);
        assert_eq!(network::install(32, Operation::Connect, allow), None);
        assert_eq!(check(31, 10, Operation::Connect), Err(crate::NetError::Eacces));
        assert_eq!(check(32, 10, Operation::Connect), Ok(()));
        assert_eq!(check(31, 2, Operation::Bind), Ok(()));
        assert_eq!(network::counters(31, Operation::Connect), Some((0, 1)));
        assert_eq!(network::counters(32, Operation::Connect), Some((1, 0)));
        assert_eq!(network::remove_namespace(31), 1);
        assert_eq!(network::remove_namespace(32), 1);
    }
}
