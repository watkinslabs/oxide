//! The socket-facing bind admission: one namespace and family, handed to the
//! family-agnostic owner in `crate::sock_admit`.

use super::{InetSocket, NetError};

/// Canonical successful admission for one bind transaction. One type across
/// every family, so a family entry point that demands it cannot be reached
/// without the hook having answered.
pub use crate::sock_admit::AddrAdmission as BindAdmission;

/// Apply the Linux bind security hook before protocol or filesystem state
/// changes. # C: O(1)
pub fn admit_bind(sock: &InetSocket) -> Result<BindAdmission, NetError> {
    crate::sock_admit::admit_bind_in(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire))
}
