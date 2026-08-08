// The one socket-option security decision, for every family and every level.
//
// Reading an option and writing one are separate questions: a module may
// publish state it will not let a caller change, so each direction is its own
// registration, and both carry the level and option number the decision is
// about. A call site that asked "may this task touch options at all?" could
// not express either.

use crate::NetError;

/// Socket identity one option decision is keyed by. The type and protocol come
/// from the socket's own identity owner, so a module sees the same answer the
/// socket reports through `SO_TYPE` / `SO_PROTOCOL`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OptSock {
    pub namespace: u64,
    pub family: u16,
    pub socket_type: u32,
    pub protocol: u32,
}

impl OptSock {
    /// A socket whose type and protocol this boundary has no cheaper source
    /// for than the family itself — every non-inet option target. # C: O(1)
    pub const fn plain(namespace: u64, family: u16) -> Self {
        Self { namespace, family, socket_type: 0, protocol: 0 }
    }
}

/// Describe one internet/unix-family socket to the option hooks. # C: O(1)
pub fn inet(sock: &crate::sock::InetSocket) -> OptSock {
    use crate::sock_opts::identity;
    OptSock {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: identity::socket_type(sock).max(0) as u32,
        protocol: identity::socket_protocol(sock).max(0) as u32,
    }
}

/// Which of the two option decisions a call site is asking for. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Access { Set, Get }

/// One option decision, in whichever direction the caller names. # C: O(1)
pub fn check(sock: OptSock, access: Access, level: i32, optname: i32) -> Result<(), NetError> {
    match access {
        Access::Set => setsockopt(sock, level, optname),
        Access::Get => getsockopt(sock, level, optname),
    }
}

fn verdict(sock: OptSock, operation: security::network::Operation, level: i32, optname: i32)
    -> Result<(), NetError>
{
    let context = security::network::Context::option(sock.namespace, sock.family,
        sock.socket_type, sock.protocol, operation, level, optname);
    match security::network::evaluate(context) {
        security::network::Verdict::Deny => Err(NetError::Eacces),
        security::network::Verdict::Allow => Ok(()),
    }
}

/// Whether this task may write this option on this socket. # C: O(1)
pub fn setsockopt(sock: OptSock, level: i32, optname: i32) -> Result<(), NetError> {
    verdict(sock, security::network::Operation::SetOption, level, optname)
}

/// Whether this task may read this option from this socket. # C: O(1)
pub fn getsockopt(sock: OptSock, level: i32, optname: i32) -> Result<(), NetError> {
    verdict(sock, security::network::Operation::GetOption, level, optname)
}

#[cfg(test)]
#[path = "option/tests.rs"]
mod tests;
