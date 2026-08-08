//! Canonical AF socket bind security admission.

use super::{InetSocket, NetError};

/// Canonical successful admission for one bind transaction.
pub struct BindAdmission(());

/// Apply the Linux bind security hook before protocol or filesystem state changes.
/// # C: O(1)
pub fn admit_bind(sock: &InetSocket) -> Result<BindAdmission, NetError> {
    let context = security::network::Context::op(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), 0, 0,
        security::network::Operation::Bind);
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    Ok(BindAdmission(()))
}
