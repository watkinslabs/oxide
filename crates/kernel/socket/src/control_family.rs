// WHICH send-ancillary rule a socket speaks, and the one place that decides it.
//
// Linux has three of them, not one: AF_UNIX and NETLINK run the SCM rule, where
// `SCM_RIGHTS` either carries descriptors or is refused outright; an IP
// transport runs its own level's rule and hands SOL_SOCKET to the generic one;
// and everything else — a stream, AF_PACKET — runs only the generic one. A
// socket that reached the wrong rule got the wrong answer in BOTH directions:
// a UDP sender's `IP_PKTINFO` was silently dropped instead of selecting a
// source, and its `SCM_RIGHTS` was refused with EINVAL where the reference
// steps over it.
//
// AF_VSOCK is the fourth case and has no entry here on purpose: it consults no
// ancillary data at all, so its send never asks this question.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use net::send_control::SendControl;

use crate::address::InetAddress;
use crate::{KResult, SendContext};

/// Whether an IPv6 address is the v4-mapped form that selects the IPv4 send
/// path. # C: O(1)
fn v4_mapped(ip: &net::Ipv6Addr) -> bool {
    ip.0[..10].iter().all(|byte| *byte == 0) && ip.0[10] == 0xff && ip.0[11] == 0xff
}

/// Whether this send leaves through the IPv4 transport.
///
/// An AF_INET socket always does. An AF_INET6 one does exactly when its
/// destination — the supplied name, else the connected peer — is v4-mapped,
/// which is the same condition that hands the message to the IPv4 sender and
/// therefore to the IPv4 ancillary rule and the IPv4 out-of-band answer.
/// # C: O(1)
pub(crate) fn ipv4_send_path(socket: &Arc<net::sock::InetSocket>,
    address: Option<&InetAddress>) -> bool
{
    if socket.family.load(Ordering::Acquire) != net::socket_args::AF_INET6 as u16 { return true; }
    match address {
        Some(InetAddress::V4 { .. }) => true,
        Some(InetAddress::V6 { ip, .. }) => v4_mapped(ip),
        _ => socket.peer6.lock().map(|(ip, _)| v4_mapped(&ip)).unwrap_or(false),
    }
}

/// Admit one send's ancillary stream under the rule this socket's family
/// speaks, and return the transmit overrides it settled. `address` is `None`
/// for a family that has no IP destination, which is AF_PACKET.
/// # C: O(control bytes)
pub(crate) fn admit(ctx: &SendContext<'_>, socket: &Arc<net::sock::InetSocket>,
    control: &[u8], address: Option<&InetAddress>) -> KResult<SendControl>
{
    if control.is_empty() { return Ok(SendControl::default()); }
    let sockcm = crate::sockcm::env_for(ctx, socket);
    let ipv6 = match &*socket.kind.lock() {
        net::sock::SockKind::Raw4(_) => Some(false),
        net::sock::SockKind::Raw6(_) => Some(true),
        net::sock::SockKind::Udp => Some(!ipv4_send_path(socket, address)),
        _ => None,
    };
    let Some(ipv6) = ipv6 else {
        crate::sockcm::admit_socket_level_only(control, &sockcm)?;
        return Ok(SendControl::default());
    };
    let env = crate::control_raw::IpControlEnv {
        ipv6,
        // Only the AF_INET6 socket that fell back to the IPv4 sender carries a
        // v4-mapped `IPV6_PKTINFO` into the IPv4 rule.
        allow_v6_pktinfo: !ipv6
            && socket.family.load(Ordering::Acquire) == net::socket_args::AF_INET6 as u16,
        cap_net_raw: sockcm.net_raw,
        net_ns: socket.net_ns(),
        sockcm,
    };
    crate::control_raw::parse_ip_control(control, &env)
}
