// Linux-ordered admission for every `IPPROTO_IP` `setsockopt` write.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::ipv4_options::Compiled;
use super::state::flag;
use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

/// Argument shape the caller must supply. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgClass {
    /// The byte-or-int import every scalar option at this level shares: four
    /// bytes when the caller supplies them, otherwise one, otherwise zero.
    ByteOrInt,
    /// `IP_OPTIONS` — an opaque header option area.
    Options,
    /// `IP_IPSEC_POLICY` / `IP_XFRM_POLICY` — a transform policy blob whose
    /// capability ladder runs before its shape is ever looked at.
    Policy,
    /// Owned by the multicast, source-filter or raw-socket table.
    Delegated,
}

/// Socket personality this table branches on. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct IpSock {
    pub stream: bool,
    pub dgram: bool,
    pub raw: bool,
    /// `inet_num`: a raw socket's protocol number, a transport socket's bound
    /// local port, zero when unbound.
    pub inet_num: u16,
    /// The socket already sits on the router-alert chain.
    pub on_ra_chain: bool,
    /// `SO_BINDTODEVICE` interface index, zero unset.
    pub bound_if: i32,
}

/// One accepted `IPPROTO_IP` write. # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Flag { bit: u64, on: bool },
    /// `IP_RECVERR`: turning it off also drains the queued errors.
    RecvErr(bool),
    /// `IP_PKTINFO` and `IP_RECVTTL` reach the receive path through the
    /// ancillary-message state the socket already carries.
    PktInfo(bool),
    RecvTtl(bool),
    Ttl(i32),
    Tos(i32),
    MinTtl(i32),
    MtuDiscover(i32),
    UnicastIf(u32),
    LocalPortRange(u32),
    Options(Compiled),
    /// Join or leave the router-alert chain.
    RouterAlert(bool),
    /// Owned by the multicast, source-filter or raw-socket table.
    Delegated,
}

/// Argument shape for one option number. # C: O(1)
pub fn arg_class(optname: u64) -> ArgClass {
    match optname {
        IP_OPTIONS => ArgClass::Options,
        IP_IPSEC_POLICY | IP_XFRM_POLICY => ArgClass::Policy,
        IP_HDRINCL | IP_MULTICAST_IF | IP_MSFILTER | MCAST_MSFILTER
        | IP_ADD_MEMBERSHIP | IP_DROP_MEMBERSHIP | IP_BLOCK_SOURCE | IP_UNBLOCK_SOURCE
        | IP_ADD_SOURCE_MEMBERSHIP | IP_DROP_SOURCE_MEMBERSHIP
        | MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP | MCAST_JOIN_SOURCE_GROUP
        | MCAST_LEAVE_SOURCE_GROUP | MCAST_BLOCK_SOURCE | MCAST_UNBLOCK_SOURCE
        | IP_MULTICAST_TTL | IP_MULTICAST_LOOP => ArgClass::Delegated,
        _ => ArgClass::ByteOrInt,
    }
}

/// `do_ip_setsockopt` admission for one scalar write. The caller has already
/// imported the leading operand per [`arg_class`], so a faulting pointer has
/// been answered before any option number is classified. # C: O(1)
pub fn admit(optname: u64, val: i32, optlen: u32, sock: IpSock, caps: OptCaps)
    -> Result<Action, Errno>
{
    let on = val != 0;
    match optname {
        // The router-alert chain is joined before the socket is even locked,
        // so its own admission precedes every other option's.
        IP_ROUTER_ALERT => {
            if !sock.raw || sock.inet_num == IPPROTO_RAW as u16 { return Err(Errno::Einval); }
            crate::router_alert::admit(on, sock.on_ra_chain)?;
            Ok(Action::RouterAlert(on))
        }

        IP_PKTINFO => Ok(Action::PktInfo(on)),
        IP_RECVTTL => Ok(Action::RecvTtl(on)),
        IP_RECVTOS => Ok(Action::Flag { bit: flag::RECVTOS, on }),
        IP_RECVOPTS => Ok(Action::Flag { bit: flag::RECVOPTS, on }),
        IP_RETOPTS => Ok(Action::Flag { bit: flag::RETOPTS, on }),
        IP_PASSSEC => Ok(Action::Flag { bit: flag::PASSSEC, on }),
        IP_RECVORIGDSTADDR => Ok(Action::Flag { bit: flag::ORIGDSTADDR, on }),
        IP_RECVFRAGSIZE => {
            if !sock.raw && !sock.dgram { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::RECVFRAGSIZE, on })
        }
        IP_RECVERR => Ok(Action::RecvErr(on)),
        IP_RECVERR_RFC4884 => {
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::RECVERR_RFC4884, on })
        }
        IP_FREEBIND => {
            if optlen < 1 { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::FREEBIND, on })
        }
        IP_MULTICAST_ALL => {
            if optlen < 1 { return Err(Errno::Einval); }
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::MC_ALL_OFF, on: !on })
        }
        IP_TRANSPARENT => {
            // The capability ladder runs BEFORE the width screen, so an
            // unprivileged zero-length write is refused for the wrong reason
            // only if it also asked to turn the option on.
            if on && !caps.net_raw_or_admin() { return Err(Errno::Eperm); }
            if optlen < 1 { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::TRANSPARENT, on })
        }
        IP_NODEFRAG => {
            if !sock.raw { return Err(Errno::Enoprotoopt); }
            Ok(Action::Flag { bit: flag::NODEFRAG, on })
        }
        IP_BIND_ADDRESS_NO_PORT =>
            Ok(Action::Flag { bit: flag::BIND_ADDRESS_NO_PORT, on }),
        IP_CHECKSUM => Ok(Action::Flag { bit: flag::CHECKSUM, on }),

        IP_TTL => {
            if optlen < 1 { return Err(Errno::Einval); }
            if val != TTL_ROUTE_DEFAULT && !(1..=TTL_MAX).contains(&val) {
                return Err(Errno::Einval);
            }
            Ok(Action::Ttl(val))
        }
        IP_MINTTL => {
            if optlen < 1 { return Err(Errno::Einval); }
            if !(0..=TTL_MAX).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::MinTtl(val))
        }
        IP_MTU_DISCOVER => {
            if !(IP_PMTUDISC_DONT..=IP_PMTUDISC_OMIT).contains(&val) {
                return Err(Errno::Einval);
            }
            Ok(Action::MtuDiscover(val))
        }
        // Both the precedence and the type-of-service bits are set at once,
        // except on a stream socket, which keeps the congestion-notification
        // pair it negotiated.
        IP_TOS => Ok(Action::Tos(val & 0xff)),
        IP_LOCAL_PORT_RANGE => {
            if optlen != 4 { return Err(Errno::Einval); }
            let (lo, hi) = (val as u16, (val >> 16) as u16);
            if lo != 0 && hi != 0 && lo > hi { return Err(Errno::Einval); }
            Ok(Action::LocalPortRange(val as u32))
        }

        // Read-only, and the multicast/raw families answer through their own
        // owners.
        IP_MTU | IP_PROTOCOL | IP_PKTOPTIONS => Err(Errno::Enoprotoopt),
        _ if arg_class(optname) == ArgClass::Delegated => Ok(Action::Delegated),
        _ => Err(Errno::Enoprotoopt),
    }
}

/// `IP_TOS` on a stream socket: the caller names the differentiated-services
/// field, the transport keeps the congestion-notification bits. # C: O(1)
pub fn tos_value(request: i32, current: i32, stream: bool) -> i32 {
    const ECN_MASK: i32 = 3;
    if !stream { return request & 0xff; }
    (request & 0xff & !ECN_MASK) | (current & ECN_MASK)
}

/// `IP_OPTIONS`: an area wider than an IPv4 header can carry is refused before
/// it is parsed, and a source route needs the raw-network capability. The
/// namespace's own addresses answer the timestamp option's prespecified form.
/// # C: O(optlen)
pub fn admit_options(bytes: &[u8], caps: OptCaps, net_ns: u64) -> Result<Action, Errno> {
    if bytes.len() > MAX_IPOPTLEN { return Err(Errno::Einval); }
    Ok(Action::Options(crate::ipv4_options::build_in(bytes, caps.net_raw, net_ns)?))
}

/// `IP_IPSEC_POLICY` / `IP_XFRM_POLICY`: the capability ladder answers first,
/// then the absence of a transform database. # C: O(1)
pub fn admit_policy(caps: OptCaps) -> Result<Action, Errno> {
    if !caps.net_admin { return Err(Errno::Eperm); }
    Err(Errno::Eopnotsupp)
}

/// `IP_UNICAST_IF` step one: the interface index the caller named, or `None`
/// to clear the binding. The value is a network-order interface index.
/// # C: O(1)
pub fn unicast_if_request(val: i32, optlen: u32) -> Result<Option<u32>, Errno> {
    if optlen != 4 { return Err(Errno::Einval); }
    let ifindex = (val as u32).swap_bytes();
    Ok(if ifindex == 0 { None } else { Some(ifindex) })
}

/// `IP_UNICAST_IF` step two: judge a resolved interface. `master` is the
/// layer-3 master device index, zero when the interface has none; `None` means
/// no such interface exists. # C: O(1)
pub fn unicast_if_admit(ifindex: u32, master: Option<i32>, bound_if: i32)
    -> Result<Action, Errno>
{
    let Some(master) = master else { return Err(Errno::Eaddrnotavail); };
    if bound_if != 0 && master != bound_if { return Err(Errno::Einval); }
    Ok(Action::UnicastIf(ifindex))
}

/// The caller bytes an `IP_OPTIONS` write carries, padded the way the compile
/// pass expects. # C: O(optlen)
pub fn options_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(raw);
    while out.len() & 3 != 0 { out.push(IPOPT_END); }
    out
}
