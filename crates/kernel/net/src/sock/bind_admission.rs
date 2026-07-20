//! Canonical AF socket bind security admission.

use super::{InetSocket, NetError};

/// Canonical successful admission for one bind transaction.
pub struct BindAdmission(());

/// Apply the Linux bind security hook before protocol or filesystem state changes.
/// # C: O(1)
pub fn admit_bind(sock: &InetSocket) -> Result<BindAdmission, NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Bind,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    Ok(BindAdmission(()))
}
