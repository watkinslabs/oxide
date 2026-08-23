// Where the socket send path asks its one security question.
//
// The decision itself belongs to `net::socket_security`; this file is the send
// layer's side of it — turning a retained target into the socket description
// that boundary takes, and holding the single call every send entry point makes.
// Keeping it here rather than inline in `send` means the call site is named,
// countable, and cannot quietly grow a second copy per family.

use crate::{Error, KResult, Message, SendFile, SendKind};
use crate::send::SendContext;

pub(crate) struct SendAdmission {
    pub(crate) udp_autobind: Option<net::landlock_addr::UdpAutobindAdmission>,
}

/// Describe the retained send target to the one message security boundary.
/// # C: O(1)
#[inline(never)]
pub(crate) fn security_sock(target: &SendFile) -> KResult<net::socket_security::MsgSock> {
    Ok(match target.kind() {
        SendKind::File => return Err(Error::Enotsock),
        SendKind::Netlink(socket) => net::socket_security::MsgSock {
            namespace: net::net_ns::namespace_id(&socket.net_ns),
            family: net::socket_args::AF_NETLINK_WIRE,
            proto: ::landlock::netcheck::Proto::Other,
            target_sid: socket.security_sid.load(core::sync::atomic::Ordering::Acquire),
            target_class: socket.security_class(),
        },
        SendKind::Vsock(socket) => net::socket_security::vsock(socket),
        SendKind::Inet(socket) => net::socket_security::inet(socket),
    })
}

/// The one send-side security decision, asked once per message and before any
/// family-specific validation, so a refusal is not preempted by an argument
/// error the sandboxed caller was never allowed to reach.
/// `#[inline(never)]`: this sits at the head of every send, ahead of the
/// family work, so its frame must overlap that work rather than add to it.
/// # C: O(N_layers × N_rules)
#[inline(never)]
pub(crate) fn admit(ctx: &SendContext<'_>, target: &SendFile, message: &Message, flags: u32)
    -> KResult<SendAdmission>
{
    let sock = security_sock(target)?;
    // The one point every send reaches the namespace-keyed policy registry.
    #[cfg(test)]
    crate::test_support::assert_policy_owned(sock.namespace);
    net::socket_security::sendmsg(ctx.sandbox(), sock, message.name.as_deref(), flags as u64)
        .map_err(Error::from)?;
    let udp_autobind = match target.kind() {
        SendKind::Inet(socket) if matches!(*socket.kind.lock(), net::sock::SockKind::Udp) => {
            Some(net::landlock_addr::admit_udp_send_autobind_for(socket, ctx.sandbox())
                .map_err(Error::from)?)
        }
        _ => None,
    };
    Ok(SendAdmission { udp_autobind })
}
