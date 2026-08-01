// Linux value and length table for every `IPPROTO_IP` `getsockopt` read.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::set::IpSock;
use super::state::flag;
use super::uapi::*;

/// The live socket values this level publishes, lifted out of the socket so
/// the table itself stays hosted-testable. # C: O(optlen)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IpGetState {
    /// `IpOpts` flag word.
    pub flags: u64,
    pub pktinfo: bool,
    pub recvttl: bool,
    pub recverr: bool,
    pub hdrincl: bool,
    pub mc_loop: bool,
    /// `uc_ttl`, negative when the route picks the hop limit.
    pub ttl: i32,
    /// Namespace default hop limit, published when `ttl` is unset.
    pub default_ttl: i32,
    pub min_ttl: i32,
    pub mcast_ttl: i32,
    pub tos: i32,
    pub pmtudisc: i32,
    pub unicast_if: u32,
    pub local_port_range: u32,
    /// The caller's own option area, already returned to its pre-compile
    /// shape.
    pub options: Vec<u8>,
    /// `IP_MULTICAST_IF` publishes the address, never the interface index.
    pub mcast_addr: [u8; 4],
    /// Path MTU of the socket's route, zero when it has none.
    pub mtu: u32,
}

/// One published option value. # C: O(1)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// Published through the byte-or-int shape.
    Int(i32),
    /// Published as `min(requested, bytes)`, length first.
    Bytes(Vec<u8>),
    /// Owned by the multicast or raw-socket table.
    Delegated,
}

/// `do_ip_getsockopt`. # C: O(optlen)
pub fn read(optname: u64, sock: IpSock, s: &IpGetState) -> Result<Value, Errno> {
    let bit = |b: u64| Value::Int(i32::from(s.flags & b != 0));
    Ok(match optname {
        IP_PKTINFO => Value::Int(i32::from(s.pktinfo)),
        IP_RECVTTL => Value::Int(i32::from(s.recvttl)),
        IP_RECVTOS => bit(flag::RECVTOS),
        IP_RECVOPTS => bit(flag::RECVOPTS),
        IP_RETOPTS => bit(flag::RETOPTS),
        IP_PASSSEC => bit(flag::PASSSEC),
        IP_RECVORIGDSTADDR => bit(flag::ORIGDSTADDR),
        IP_CHECKSUM => bit(flag::CHECKSUM),
        IP_RECVFRAGSIZE => bit(flag::RECVFRAGSIZE),
        IP_RECVERR => Value::Int(i32::from(s.recverr)),
        IP_RECVERR_RFC4884 => bit(flag::RECVERR_RFC4884),
        IP_FREEBIND => bit(flag::FREEBIND),
        IP_HDRINCL => Value::Int(i32::from(s.hdrincl)),
        IP_MULTICAST_LOOP => Value::Int(i32::from(s.mc_loop)),
        IP_MULTICAST_ALL => Value::Int(i32::from(s.flags & flag::MC_ALL_OFF == 0)),
        IP_TRANSPARENT => bit(flag::TRANSPARENT),
        IP_NODEFRAG => bit(flag::NODEFRAG),
        IP_BIND_ADDRESS_NO_PORT => bit(flag::BIND_ADDRESS_NO_PORT),
        IP_ROUTER_ALERT => bit(flag::RTALERT),
        IP_TTL => Value::Int(if s.ttl < 0 { s.default_ttl } else { s.ttl }),
        IP_MINTTL => Value::Int(s.min_ttl),
        IP_MULTICAST_TTL => Value::Int(s.mcast_ttl),
        IP_MTU_DISCOVER => Value::Int(s.pmtudisc),
        IP_TOS => Value::Int(s.tos),
        // The area is published without a value at all when the socket carries
        // none, so a caller cannot mistake padding for an empty option list.
        IP_OPTIONS => Value::Bytes(s.options.clone()),
        IP_MTU => {
            if s.mtu == 0 { return Err(Errno::Enotconn); }
            Value::Int(s.mtu as i32)
        }
        // The stream-socket ancillary snapshot has no datagram form.
        IP_PKTOPTIONS => {
            if !sock.stream { return Err(Errno::Enoprotoopt); }
            Value::Bytes(Vec::new())
        }
        IP_UNICAST_IF => Value::Int(s.unicast_if.swap_bytes() as i32),
        // An interface bound by index still reports the ANY address.
        IP_MULTICAST_IF => Value::Bytes(Vec::from(s.mcast_addr)),
        IP_LOCAL_PORT_RANGE => Value::Int(s.local_port_range as i32),
        IP_PROTOCOL => Value::Int(sock.inet_num as i32),
        IP_MSFILTER | MCAST_MSFILTER => Value::Delegated,
        _ => return Err(Errno::Enoprotoopt),
    })
}

/// The copy shape a scalar read publishes: a value in the unsigned-byte window
/// asked for in fewer than four bytes is narrowed to exactly one, everything
/// else is the leading bytes of an `int`. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ScalarOut { Byte(u8), Int(usize) }

/// # C: O(1)
pub fn scalar_out(val: i32, requested: i32) -> ScalarOut {
    if requested > 0 && requested < 4 && (0..=255).contains(&val) {
        return ScalarOut::Byte(val as u8);
    }
    ScalarOut::Int(core::cmp::min(requested.max(0) as usize, 4))
}

/// `IP_OPTIONS` length rule: an empty area publishes a zero length and no
/// value; otherwise the caller's buffer truncates the area. # C: O(1)
pub fn bytes_len(available: usize, requested: i32) -> usize {
    core::cmp::min(requested.max(0) as usize, available)
}
