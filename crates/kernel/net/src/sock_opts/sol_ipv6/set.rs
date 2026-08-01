// Linux-ordered admission for every `IPPROTO_IPV6` `setsockopt` write.

use syscall::errno::Errno;

use super::state::flag;
use super::uapi::*;
use crate::sock_opts::sol_ip::flag as v4flag;
use crate::sock_opts::sol_socket::OptCaps;

/// Argument shape the caller must supply. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArgClass {
    /// The leading `int`: four bytes when the caller supplies them, otherwise
    /// the value is zero — this level never reads a bare byte.
    Int,
    /// A sticky extension header area.
    Header,
    /// `IPV6_PKTINFO` — a sticky source address and interface.
    PktInfo,
    /// `IPV6_NEXTHOP` — a sticky first hop, in socket-address form.
    NextHop,
    /// `IPV6_FLOWLABEL_MGR`.
    FlowLabel,
    /// `IPV6_2292PKTOPTIONS` — an ancillary-message stream.
    PktOptions,
    /// `IPV6_IPSEC_POLICY` / `IPV6_XFRM_POLICY`.
    Policy,
    /// Owned by the multicast, anycast or raw-socket table.
    Delegated,
}

/// Socket personality this table branches on. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Ipv6Sock {
    pub stream: bool,
    pub dgram: bool,
    pub raw: bool,
    /// `sk_protocol`.
    pub protocol: u8,
    /// `inet_num`: the bound local port, zero when unbound.
    pub inet_num: u16,
    pub v6only: bool,
    pub established: bool,
    /// The connected peer is an IPv4-mapped address.
    pub daddr_v4mapped: bool,
    /// A send is already in flight in the IPv6 form.
    pub send_pending: bool,
    pub bound_if: i32,
    pub on_ra_chain: bool,
}

/// One accepted `IPPROTO_IPV6` write. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Flag { bit: u64, on: bool },
    /// A bit this level shares with `IPPROTO_IP`: `IPV6_FREEBIND` and
    /// `IPV6_TRANSPARENT` write the very storage their IPv4 twins do, so the
    /// socket carries exactly one nonlocal-bind permission. `bit` is a
    /// `sol_ip::flag` constant.
    InetFlag { bit: u64, on: bool },
    RecvErr(bool),
    UnicastHops(i32),
    MulticastHops(i32),
    MulticastLoop(bool),
    MulticastIf(u32),
    UnicastIf(u32),
    /// `IPV6_V6ONLY`.
    V6Only(bool),
    MtuDiscover(i32),
    /// `IPV6_MTU` — the fragmentation size the socket names.
    FragSize(i32),
    UseMinMtu(i32),
    MinHopCount(i32),
    Tclass(i32),
    SrcPrefs(i32),
    /// Convert the socket to the IPv4 address family.
    AddrForm,
    /// `IPV6_ROUTER_ALERT`: `selector` is the chain slot to take, `None` to
    /// release one; `on` is what the option bit reads back as.
    RouterAlert { selector: Option<i32>, on: bool },
    /// Owned by the multicast, anycast or raw-socket table.
    Delegated,
}

/// Argument shape for one option number. # C: O(1)
pub fn arg_class(optname: u64) -> ArgClass {
    match optname {
        IPV6_HOPOPTS | IPV6_RTHDRDSTOPTS | IPV6_RTHDR | IPV6_DSTOPTS => ArgClass::Header,
        IPV6_PKTINFO => ArgClass::PktInfo,
        IPV6_NEXTHOP => ArgClass::NextHop,
        IPV6_FLOWLABEL_MGR => ArgClass::FlowLabel,
        IPV6_2292PKTOPTIONS => ArgClass::PktOptions,
        IPV6_IPSEC_POLICY | IPV6_XFRM_POLICY => ArgClass::Policy,
        IPV6_ADD_MEMBERSHIP | IPV6_DROP_MEMBERSHIP | IPV6_JOIN_ANYCAST
        | IPV6_LEAVE_ANYCAST | MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP
        | MCAST_JOIN_SOURCE_GROUP | MCAST_LEAVE_SOURCE_GROUP | MCAST_BLOCK_SOURCE
        | MCAST_UNBLOCK_SOURCE | MCAST_MSFILTER | IPV6_HDRINCL | IPV6_CHECKSUM =>
            ArgClass::Delegated,
        _ => ArgClass::Int,
    }
}

/// `do_ipv6_setsockopt` admission for one scalar write. # C: O(1)
pub fn admit(optname: u64, val: i32, optlen: u32, sock: Ipv6Sock, caps: OptCaps)
    -> Result<Action, Errno>
{
    let on = val != 0;
    let wide = || if optlen < 4 { Err(Errno::Einval) } else { Ok(()) };
    match optname {
        IPV6_UNICAST_HOPS => {
            wide()?;
            if !(HOP_LIMIT_ROUTE..=HOP_LIMIT_MAX).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::UnicastHops(val))
        }
        IPV6_MULTICAST_LOOP => {
            wide()?;
            // The value must be exactly zero or one; anything else is refused
            // rather than reduced to a boolean.
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::MulticastLoop(on))
        }
        IPV6_MULTICAST_HOPS => {
            if sock.stream { return Err(Errno::Enoprotoopt); }
            wide()?;
            if !(HOP_LIMIT_ROUTE..=HOP_LIMIT_MAX).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::MulticastHops(if val == HOP_LIMIT_ROUTE {
                IPV6_DEFAULT_MCASTHOPS
            } else { val }))
        }
        IPV6_MTU => {
            wide()?;
            if val != 0 && val < IPV6_MIN_MTU { return Err(Errno::Einval); }
            Ok(Action::FragSize(val))
        }
        IPV6_MINHOPCOUNT => {
            wide()?;
            if !(0..=HOP_LIMIT_MAX).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::MinHopCount(val))
        }
        IPV6_RECVERR_RFC4884 => {
            wide()?;
            if !(0..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Flag { bit: flag::RECVERR_RFC4884, on })
        }
        IPV6_MULTICAST_ALL => {
            wide()?;
            Ok(Action::Flag { bit: flag::MC_ALL_OFF, on: !on })
        }
        // Neither of these screens the operand width: a zero-length write is
        // the same as writing zero.
        IPV6_AUTOFLOWLABEL => Ok(Action::Flag { bit: flag::AUTOFLOWLABEL, on }),
        IPV6_DONTFRAG => Ok(Action::Flag { bit: flag::DONTFRAG, on }),
        IPV6_RECVFRAGSIZE => Ok(Action::Flag { bit: flag::RECVFRAGSIZE, on }),
        IPV6_RECVERR => { wide()?; Ok(Action::RecvErr(on)) }
        IPV6_ROUTER_ALERT_ISOLATE => {
            wide()?;
            Ok(Action::Flag { bit: flag::RTALERT_ISOLATE, on })
        }
        IPV6_MTU_DISCOVER => {
            wide()?;
            if !(IPV6_PMTUDISC_DONT..=IPV6_PMTUDISC_OMIT).contains(&val) {
                return Err(Errno::Einval);
            }
            Ok(Action::MtuDiscover(val))
        }
        IPV6_FLOWINFO_SEND => { wide()?; Ok(Action::Flag { bit: flag::SNDFLOW, on }) }
        IPV6_ADDR_PREFERENCES => { wide()?; src_prefs(val)?; Ok(Action::SrcPrefs(val)) }
        IPV6_USE_MIN_MTU => {
            wide()?;
            if !(-1..=1).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::UseMinMtu(val))
        }

        IPV6_ADDRFORM => {
            wide()?;
            if val != PF_INET { return Err(Errno::Einval); }
            // A raw socket has no IPv4 personality to convert to, and neither
            // has any protocol outside the two transports.
            if sock.raw { return Err(Errno::Enoprotoopt); }
            match sock.protocol {
                IPPROTO_UDP if sock.send_pending => return Err(Errno::Ebusy),
                IPPROTO_UDP | IPPROTO_TCP => {}
                _ => return Err(Errno::Enoprotoopt),
            }
            if !sock.established { return Err(Errno::Enotconn); }
            if sock.v6only || !sock.daddr_v4mapped { return Err(Errno::Eaddrnotavail); }
            Ok(Action::AddrForm)
        }
        IPV6_V6ONLY => {
            if optlen < 4 || sock.inet_num != 0 { return Err(Errno::Einval); }
            Ok(Action::V6Only(on))
        }

        IPV6_RECVPKTINFO => { wide()?; Ok(Action::Flag { bit: RECVPKTINFO, on }) }
        IPV6_2292PKTINFO => { wide()?; Ok(Action::Flag { bit: flag::RXOINFO, on }) }
        IPV6_RECVHOPLIMIT => { wide()?; Ok(Action::Flag { bit: RECVHOPLIMIT, on }) }
        IPV6_2292HOPLIMIT => { wide()?; Ok(Action::Flag { bit: flag::RXOHLIM, on }) }
        IPV6_RECVRTHDR => { wide()?; Ok(Action::Flag { bit: flag::RXSRCRT, on }) }
        IPV6_2292RTHDR => { wide()?; Ok(Action::Flag { bit: flag::RXOSRCRT, on }) }
        IPV6_RECVHOPOPTS => { wide()?; Ok(Action::Flag { bit: flag::RXHOPOPTS, on }) }
        IPV6_2292HOPOPTS => { wide()?; Ok(Action::Flag { bit: flag::RXOHOPOPTS, on }) }
        IPV6_RECVDSTOPTS => { wide()?; Ok(Action::Flag { bit: flag::RXDSTOPTS, on }) }
        IPV6_2292DSTOPTS => { wide()?; Ok(Action::Flag { bit: flag::RXODSTOPTS, on }) }
        IPV6_RECVTCLASS => { wide()?; Ok(Action::Flag { bit: RECVTCLASS, on }) }
        IPV6_FLOWINFO => { wide()?; Ok(Action::Flag { bit: flag::RXFLOW, on }) }
        IPV6_RECVPATHMTU => { wide()?; Ok(Action::Flag { bit: flag::RXPATHMTU, on }) }
        IPV6_RECVORIGDSTADDR => { wide()?; Ok(Action::Flag { bit: flag::RXORIGDSTADDR, on }) }
        IPV6_TCLASS => {
            wide()?;
            if !(-1..=255).contains(&val) { return Err(Errno::Einval); }
            Ok(Action::Tclass(if val == -1 { 0 } else { val }))
        }
        IPV6_TRANSPARENT => {
            // The capability ladder runs before the width screen.
            if on && !caps.net_raw_or_admin() { return Err(Errno::Eperm); }
            wide()?;
            Ok(Action::InetFlag { bit: v4flag::TRANSPARENT, on })
        }
        IPV6_FREEBIND => { wide()?; Ok(Action::InetFlag { bit: v4flag::FREEBIND, on }) }
        IPV6_ROUTER_ALERT => {
            wide()?;
            // Only a socket opened on the raw protocol itself can receive the
            // packets the chain carries.
            if !sock.raw || sock.protocol != IPPROTO_RAW { return Err(Errno::Enoprotoopt); }
            // The operand is a selector, not a boolean: a zero value takes a
            // chain slot matching alert value zero, and only a negative value
            // releases one. The reported option bit still follows the boolean.
            let selector = crate::router_alert::v6_selector(val);
            crate::router_alert::admit(selector.is_some(), sock.on_ra_chain)?;
            Ok(Action::RouterAlert { selector, on })
        }

        IPV6_PATHMTU | IPV6_HOPLIMIT | IPV6_AUTHHDR => Err(Errno::Enoprotoopt),
        _ if arg_class(optname) == ArgClass::Delegated => Ok(Action::Delegated),
        _ => Err(Errno::Enoprotoopt),
    }
}

/// The receive-personality bits shared with the socket fields that already
/// carry them, so the two never disagree.
pub const RECVPKTINFO: u64 = 1 << 60;
pub const RECVHOPLIMIT: u64 = 1 << 61;
pub const RECVTCLASS: u64 = 1 << 62;

/// `IPV6_TCLASS` on a stream socket: the caller names the traffic class, the
/// transport keeps the congestion-notification bits. # C: O(1)
pub fn tclass_value(request: i32, current: i32, stream: bool) -> i32 {
    const ECN_MASK: i32 = 3;
    if !stream { return request; }
    (request & !ECN_MASK) | (current & ECN_MASK)
}

/// `ip6_sock_set_addr_preferences`: the public/temporary, home/care-of and
/// cryptographic-address groups each admit at most one preference. Returns the
/// bits to set and the mask to keep, so naming one group never disturbs
/// another. Only the temporary, public and care-of bits are retained — the
/// rest are recomputed on every read. # C: O(1)
pub fn src_prefs(val: i32) -> Result<(i32, i32), Errno> {
    let mut pref = 0;
    let mut mask = !IPV6_PREFER_SRC_MASK;
    match val & (IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP
        | IPV6_PREFER_SRC_PUBTMP_DEFAULT)
    {
        v if v == IPV6_PREFER_SRC_PUBLIC => {
            pref |= IPV6_PREFER_SRC_PUBLIC;
            mask &= !(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP);
        }
        v if v == IPV6_PREFER_SRC_TMP => {
            pref |= IPV6_PREFER_SRC_TMP;
            mask &= !(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP);
        }
        v if v == IPV6_PREFER_SRC_PUBTMP_DEFAULT =>
            mask &= !(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_TMP),
        0 => {}
        _ => return Err(Errno::Einval),
    }
    match val & (IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_COA) {
        v if v == IPV6_PREFER_SRC_HOME => mask &= !IPV6_PREFER_SRC_COA,
        v if v == IPV6_PREFER_SRC_COA => pref |= IPV6_PREFER_SRC_COA,
        0 => {}
        _ => return Err(Errno::Einval),
    }
    match val & (IPV6_PREFER_SRC_CGA | IPV6_PREFER_SRC_NONCGA) {
        v if v == IPV6_PREFER_SRC_CGA || v == IPV6_PREFER_SRC_NONCGA || v == 0 => {}
        _ => return Err(Errno::Einval),
    }
    Ok((pref, mask))
}

/// Apply an admitted preference set to the stored one. # C: O(1)
pub fn apply_src_prefs(current: i32, val: i32) -> Result<i32, Errno> {
    let (pref, mask) = src_prefs(val)?;
    Ok((current & mask) | pref)
}

/// `IPV6_MULTICAST_IF` step one. # C: O(1)
pub fn multicast_if_request(val: i32, optlen: u32, sock: Ipv6Sock)
    -> Result<Option<u32>, Errno>
{
    if sock.stream { return Err(Errno::Enoprotoopt); }
    if optlen < 4 { return Err(Errno::Einval); }
    Ok(if val == 0 { None } else { Some(val as u32) })
}

/// `IPV6_MULTICAST_IF` step two: an interface the socket is not bound to is
/// accepted only when it is that binding's layer-3 master. # C: O(1)
pub fn multicast_if_admit(ifindex: u32, master: Option<i32>, bound_if: i32)
    -> Result<Action, Errno>
{
    let Some(master) = master else { return Err(Errno::Enodev); };
    if bound_if != 0 && bound_if != ifindex as i32
        && (master == 0 || master != bound_if)
    {
        return Err(Errno::Einval);
    }
    Ok(Action::MulticastIf(ifindex))
}

/// `IPV6_UNICAST_IF` step one — the value is a network-order index. # C: O(1)
pub fn unicast_if_request(val: i32, optlen: u32) -> Result<Option<u32>, Errno> {
    if optlen != 4 { return Err(Errno::Einval); }
    let ifindex = (val as u32).swap_bytes();
    Ok(if ifindex == 0 { None } else { Some(ifindex) })
}

/// `IPV6_UNICAST_IF` step two: unlike the IPv4 form, ANY existing device
/// binding refuses the write outright. # C: O(1)
pub fn unicast_if_admit(ifindex: u32, exists: bool, bound_if: i32)
    -> Result<Action, Errno>
{
    if !exists { return Err(Errno::Eaddrnotavail); }
    if bound_if != 0 { return Err(Errno::Einval); }
    Ok(Action::UnicastIf(ifindex))
}

/// `IPV6_IPSEC_POLICY` / `IPV6_XFRM_POLICY`. # C: O(1)
pub fn admit_policy(caps: OptCaps) -> Result<Action, Errno> {
    if !caps.net_admin { return Err(Errno::Eperm); }
    Err(Errno::Eopnotsupp)
}

/// `IPV6_PKTINFO`: the sticky source address and interface, refused when the
/// interface contradicts an existing device binding. # C: O(1)
pub fn admit_pktinfo(optlen: u32, ifindex: u32, bound_if: i32)
    -> Result<(), Errno>
{
    if optlen == 0 || (optlen as usize) < IN6_PKTINFO_SIZE { return Err(Errno::Einval); }
    if bound_if != 0 && ifindex != 0 && ifindex as i32 != bound_if {
        return Err(Errno::Einval);
    }
    Ok(())
}
