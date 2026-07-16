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
