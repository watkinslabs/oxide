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

/// Apply SELinux's address-object permission after the generic socket check.
/// The port SID comes from the loaded policy's `portcon` table; the target
/// class remains the socket class because Linux checks `name_bind` and
/// `name_connect` in that class.
pub fn admit_port(sock: &crate::sock::InetSocket, protocol: u8, port: u16,
                  operation: security::network::Operation) -> Result<(), NetError> {
    let target_sid = crate::selinux_glue::port_sid(protocol, port);
    let target_class = match &*sock.kind.lock() {
        crate::sock::SockKind::TcpInit | crate::sock::SockKind::TcpListener(_)
        | crate::sock::SockKind::TcpConn(_) => "tcp_socket",
        crate::sock::SockKind::Udp => "udp_socket",
        crate::sock::SockKind::Raw4(_) | crate::sock::SockKind::Raw6(_) => "rawip_socket",
        _ => return Ok(()),
    };
    crate::security_admission::check_socket_peer(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), operation,
        target_sid, target_class)
}

pub fn admit_node(sock: &crate::sock::InetSocket, sid: u32) -> Result<(), NetError> {
    let target_class = match &*sock.kind.lock() {
        crate::sock::SockKind::TcpInit | crate::sock::SockKind::TcpListener(_)
        | crate::sock::SockKind::TcpConn(_) => "tcp_socket",
        crate::sock::SockKind::Udp => "udp_socket",
        crate::sock::SockKind::Raw4(_) | crate::sock::SockKind::Raw6(_) => "rawip_socket",
        _ => return Ok(()),
    };
    crate::security_admission::check_socket_peer(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire),
        security::network::Operation::NodeBind, sid, target_class)
}

fn admit(namespace: u64, family: u16, operation: security::network::Operation)
    -> Result<AddrAdmission, NetError>
{
    crate::security_admission::check(namespace, family, operation)?;
    Ok(AddrAdmission(()))
}

#[cfg(test)]
mod tests;
