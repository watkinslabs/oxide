//! Namespace-scoped network security admission shared by every socket family.

/// Evaluate one network operation against the socket's retained namespace. # C: O(1)
pub fn check(namespace: u64, family: u16, operation: security::network::Operation)
    -> Result<(), crate::NetError>
{
    let context = security::network::Context::op(namespace, family, 0, 0, operation);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

pub fn check_socket(namespace: u64, family: u16, operation: security::network::Operation,
                    target_sid: u32, target_class: &'static str) -> Result<(), crate::NetError> {
    let context = security::network::Context::op(namespace, family, 0, 0, operation);
    if matches!(security::network::evaluate_socket(context, target_sid, target_class),
        security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Evaluate a peer-targeted socket permission such as Unix
/// `unix_stream_socket:connectto` or `socket:sendto`. The target is the
/// retained label of the peer object, not the caller's own socket label.
pub fn check_socket_peer(namespace: u64, family: u16,
                         operation: security::network::Operation,
                         target_sid: u32, target_class: &'static str)
                         -> Result<(), crate::NetError> {
    let context = security::network::Context::op(namespace, family, 0, 0, operation)
        .on_socket(target_sid, target_class);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Evaluate a `listen(2)` decision, carrying the post-clamp backlog so an
/// installed hook can see it — Linux passes `security_socket_listen(sock,
/// backlog)` the same clamped value. # C: O(1)
pub fn check_listen(namespace: u64, family: u16, backlog: u32) -> Result<(), crate::NetError> {
    let context = security::network::Context::listen(namespace, family, 0, 0, backlog);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

pub fn check_socket_listen(namespace: u64, family: u16, backlog: u32, target_sid: u32,
                           target_class: &'static str) -> Result<(), crate::NetError> {
    let context = security::network::Context::listen(namespace, family, 0, 0, backlog);
    if matches!(security::network::evaluate_socket(context, target_sid, target_class),
        security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

pub fn check_netlink(namespace: u64, protocol: u16, message_type: u16,
                     target_sid: u32, target_class: &'static str) -> Result<(), crate::NetError> {
    let context = security::network::Context::netlink_send(
        namespace, protocol as u32, message_type, target_sid, target_class);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

#[allow(unpredictable_function_pointer_comparisons, reason = "the assertion is `the hook I just installed came back`; both sides are the same non-generic fn item in the same codegen unit, so the lint's address-uniqueness caveat cannot apply")]
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
