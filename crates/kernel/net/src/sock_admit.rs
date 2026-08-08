// The generic socket-address admission every family passes through.
//
// The bind and connect security decisions belong to the generic socket layer,
// above the family dispatch: the hook runs on the socket's namespace and
// family and never on the address, so it is answered before any family looks
// at the caller's `sockaddr`. Placing it inside a family implementation makes
// a malformed address outrank a denial — the caller learns EINVAL where the
// reference says EACCES, and learns it from a code path a policy meant to
// stop before it began.
//
// One token type, produced here and consumed by every family's admitted
// entry point, is what keeps that true: a family operation that requires the
// token cannot be reached without the hook having answered.
//
// Ungated: the decision must run under hosted `cargo test` (`docs/53`).

use crate::NetError;

/// Proof that the generic hook admitted one address-carrying socket
/// operation. Zero-sized; its only value is that it cannot be forged by a
/// family that skipped the hook.
pub struct AddrAdmission(());

impl AddrAdmission {
    /// A token for a test that is exercising a family operation rather than
    /// the admission in front of it. The hook's own coverage is in this
    /// module's tests; production code has no way to reach this. # C: O(1)
    #[cfg(test)]
    pub(crate) fn for_test() -> Self { Self(()) }
}

/// Apply the generic bind security decision. # C: O(1)
pub fn admit_bind_in(namespace: u64, family: u16) -> Result<AddrAdmission, NetError> {
    admit(namespace, family, security::network::Operation::Bind)
}

/// Apply the generic connect security decision. # C: O(1)
pub fn admit_connect_in(namespace: u64, family: u16) -> Result<AddrAdmission, NetError> {
    admit(namespace, family, security::network::Operation::Connect)
}

fn admit(namespace: u64, family: u16, operation: security::network::Operation)
    -> Result<AddrAdmission, NetError>
{
    crate::security_admission::check(namespace, family, operation)?;
    Ok(AddrAdmission(()))
}

#[cfg(test)]
mod tests;
