// Linux value and length table for every `IPPROTO_IPV6` `getsockopt` read.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::set::{Ipv6Sock, RECVHOPLIMIT, RECVPKTINFO, RECVTCLASS};
use super::state::{Sticky, flag};
use crate::sock_opts::sol_ip::flag as v4flag;
use super::uapi::*;

/// The live socket values this level publishes. # C: O(1)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ipv6GetState {
    /// `Ipv6Opts` flag word, plus the three receive bits the socket carries in
    /// its own fields.
    pub flags: u64,
    /// `IPPROTO_IP` flag word — the storage `IPV6_FREEBIND` and
    /// `IPV6_TRANSPARENT` share with their IPv4 twins.
    pub inet_flags: u64,
    pub v6only: bool,
    pub recverr: bool,
    pub mc_loop: bool,
    /// `hop_limit`, negative when the route picks it.
    pub hop_limit: i32,
    pub mcast_hops: i32,
    /// Hop limit of the socket's route, negative when it has none.
    pub route_hoplimit: i32,
    /// Namespace default hop limit.
    pub default_hoplimit: i32,
    pub mcast_oif: u32,
    pub unicast_if: u32,
    pub pmtudisc: i32,
    pub tclass: i32,
    pub min_hopcount: i32,
    pub srcprefs: i32,
    pub frag_size: i32,
    pub use_min_mtu: i32,
    /// Namespace automatic-flow-label policy, published when the socket named
    /// none of its own.
    pub default_autoflowlabel: bool,
    /// Path MTU of the socket's route, zero when it has none.
    pub mtu: u32,
    /// Sticky extension headers, in slot order.
    pub headers: [Option<Vec<u8>>; Sticky::COUNT],
    /// `IPV6_ADDRFORM` reports the family the socket currently carries.
    pub family: i32,
}

/// One published option value. # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// Published as the leading `min(requested, 4)` bytes of an `int`; unlike
    /// the IPv4 level, this one never narrows a small value to a single byte.
    Int(i32),
    /// Published as `min(requested, bytes)`, length first.
    Bytes(Vec<u8>),
    /// `IPV6_PATHMTU`, refused outright when the caller's buffer is too small.
    Exact(Vec<u8>),
    /// Owned by the multicast or flow-label table.
    Delegated,
}

/// `do_ipv6_getsockopt`. # C: O(len)
pub fn read(optname: u64, sock: Ipv6Sock, s: &Ipv6GetState) -> Result<Value, Errno> {
    let bit = |b: u64| Value::Int(i32::from(s.flags & b != 0));
    let inet_bit = |b: u64| Value::Int(i32::from(s.inet_flags & b != 0));
    Ok(match optname {
        IPV6_ADDRFORM => {
            if sock.protocol != IPPROTO_UDP && sock.protocol != IPPROTO_TCP {
                return Err(Errno::Enoprotoopt);
            }
            if !sock.established { return Err(Errno::Enotconn); }
            Value::Int(s.family)
        }
        IPV6_MTU => {
            if s.mtu == 0 { return Err(Errno::Enotconn); }
            Value::Int(s.mtu as i32)
        }
        IPV6_V6ONLY => Value::Int(i32::from(s.v6only)),
        IPV6_RECVPKTINFO => bit(RECVPKTINFO),
        IPV6_2292PKTINFO => bit(flag::RXOINFO),
        IPV6_RECVHOPLIMIT => bit(RECVHOPLIMIT),
        IPV6_2292HOPLIMIT => bit(flag::RXOHLIM),
        IPV6_RECVRTHDR => bit(flag::RXSRCRT),
        IPV6_2292RTHDR => bit(flag::RXOSRCRT),
        IPV6_RECVHOPOPTS => bit(flag::RXHOPOPTS),
        IPV6_2292HOPOPTS => bit(flag::RXOHOPOPTS),
        IPV6_RECVDSTOPTS => bit(flag::RXDSTOPTS),
        IPV6_2292DSTOPTS => bit(flag::RXODSTOPTS),
        IPV6_HOPOPTS | IPV6_RTHDRDSTOPTS | IPV6_RTHDR | IPV6_DSTOPTS => {
            let slot = super::hdr::slot(optname).expect("the four sticky slots");
            Value::Bytes(s.headers[slot as usize].clone().unwrap_or_default())
        }
        IPV6_TCLASS => Value::Int(s.tclass),
        IPV6_RECVTCLASS => bit(RECVTCLASS),
        IPV6_FLOWINFO => bit(flag::RXFLOW),
        IPV6_RECVPATHMTU => bit(flag::RXPATHMTU),
        IPV6_PATHMTU => {
            if s.mtu == 0 { return Err(Errno::Enotconn); }
            Value::Exact(mtuinfo(s.mtu))
        }
        IPV6_TRANSPARENT => inet_bit(v4flag::TRANSPARENT),
        IPV6_FREEBIND => inet_bit(v4flag::FREEBIND),
        IPV6_RECVORIGDSTADDR => bit(flag::RXORIGDSTADDR),
        // An unset hop limit resolves through the route, then the namespace
        // default, exactly as the transmit path does.
        IPV6_UNICAST_HOPS => Value::Int(resolve_hops(s.hop_limit, s)),
        IPV6_MULTICAST_HOPS => Value::Int(resolve_hops(s.mcast_hops, s)),
        IPV6_MULTICAST_LOOP => Value::Int(i32::from(s.mc_loop)),
        IPV6_MULTICAST_IF => Value::Int(s.mcast_oif as i32),
        IPV6_MULTICAST_ALL => Value::Int(i32::from(s.flags & flag::MC_ALL_OFF == 0)),
        IPV6_UNICAST_IF => Value::Int(s.unicast_if.swap_bytes() as i32),
        IPV6_MTU_DISCOVER => Value::Int(s.pmtudisc),
        IPV6_RECVERR => Value::Int(i32::from(s.recverr)),
        IPV6_FLOWINFO_SEND => bit(flag::SNDFLOW),
        IPV6_ADDR_PREFERENCES => Value::Int(published_prefs(s.srcprefs)),
        IPV6_MINHOPCOUNT => Value::Int(s.min_hopcount),
        IPV6_DONTFRAG => bit(flag::DONTFRAG),
        IPV6_USE_MIN_MTU => Value::Int(s.use_min_mtu),
        IPV6_AUTOFLOWLABEL => Value::Int(i32::from(
            if s.flags & flag::AUTOFLOWLABEL_SET != 0 {
                s.flags & flag::AUTOFLOWLABEL != 0
            } else { s.default_autoflowlabel })),
        IPV6_RECVFRAGSIZE => bit(flag::RECVFRAGSIZE),
        IPV6_ROUTER_ALERT => bit(flag::RTALERT),
        IPV6_ROUTER_ALERT_ISOLATE => bit(flag::RTALERT_ISOLATE),
        IPV6_RECVERR_RFC4884 => bit(flag::RECVERR_RFC4884),
        // The stream-socket ancillary snapshot has no datagram form.
        IPV6_2292PKTOPTIONS => {
            if !sock.stream { return Err(Errno::Enoprotoopt); }
            Value::Bytes(Vec::new())
        }
        MCAST_MSFILTER | IPV6_FLOWLABEL_MGR => Value::Delegated,
        _ => return Err(Errno::Enoprotoopt),
    })
}

/// The hop limit a read publishes: the socket's own, else the route's, else
/// the namespace default. # C: O(1)
fn resolve_hops(stored: i32, s: &Ipv6GetState) -> i32 {
    if stored >= 0 { return stored; }
    if s.route_hoplimit >= 0 { return s.route_hoplimit; }
    s.default_hoplimit
}

/// `IPV6_ADDR_PREFERENCES` publishes a complete preference set, filling in the
/// defaults for whichever group the caller never named. # C: O(1)
pub fn published_prefs(stored: i32) -> i32 {
    let mut val = 0;
    if stored & IPV6_PREFER_SRC_TMP != 0 { val |= IPV6_PREFER_SRC_TMP; }
    else if stored & IPV6_PREFER_SRC_PUBLIC != 0 { val |= IPV6_PREFER_SRC_PUBLIC; }
    else { val |= IPV6_PREFER_SRC_PUBTMP_DEFAULT; }
    if stored & IPV6_PREFER_SRC_COA != 0 { val |= IPV6_PREFER_SRC_COA; }
    else { val |= IPV6_PREFER_SRC_HOME; }
    val
}

/// `struct ip6_mtuinfo`: an all-zero IPv6 socket address followed by the MTU.
/// # C: O(1)
pub fn mtuinfo(mtu: u32) -> Vec<u8> {
    let mut out = alloc::vec![0u8; IP6_MTUINFO_SIZE];
    out[IP6_MTUINFO_SIZE - 4..].copy_from_slice(&mtu.to_ne_bytes());
    out
}

/// The `int` copy length this level publishes: never narrowed to a byte, and a
/// negative request is treated as an unbounded one. # C: O(1)
pub fn int_len(requested: i32) -> usize {
    if requested < 0 { return 4; }
    core::cmp::min(requested as usize, 4)
}

/// `IPV6_PATHMTU` and `IPV6_FLOWLABEL_MGR` refuse a buffer that cannot hold
/// the whole structure. # C: O(1)
pub fn exact_len(needed: usize, requested: i32) -> Result<usize, Errno> {
    if requested < 0 || (requested as usize) < needed { return Err(Errno::Einval); }
    Ok(needed)
}
