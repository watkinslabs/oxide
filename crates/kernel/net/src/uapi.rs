/// Socket message flags from Linux UAPI. ABI shims cast only when writing a
/// narrower `msghdr.msg_flags` field.
pub const MSG_PEEK: u64 = 0x02;
pub const MSG_CTRUNC: u64 = 0x08;
pub const MSG_TRUNC: u64 = 0x20;
pub const MSG_DONTWAIT: u64 = 0x40;
pub const MSG_EOR: u64 = 0x80;
pub const MSG_WAITALL: u64 = 0x100;
pub const MSG_OOB: u64 = 0x01;
pub const MSG_DONTROUTE: u64 = 0x04;
pub const MSG_ERRQUEUE: u64 = 0x2000;
pub const MSG_NOSIGNAL: u64 = 0x4000;
pub const MSG_WAITFORONE: u64 = 0x1_0000;
pub const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
pub const MSG_CMSG_COMPAT: u64 = 0x8000_0000;

/// Linux AF_PACKET `sockaddr_ll.sll_pkttype` values visible to userspace.
pub const PACKET_HOST: u8 = 0;
pub const PACKET_BROADCAST: u8 = 1;
pub const PACKET_MULTICAST: u8 = 2;
pub const PACKET_OTHERHOST: u8 = 3;
pub const PACKET_OUTGOING: u8 = 4;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;
pub const PACKET_MR_MULTICAST: u16 = 0;
pub const PACKET_MR_PROMISC: u16 = 1;
pub const PACKET_MR_ALLMULTI: u16 = 2;
pub const PACKET_MR_UNICAST: u16 = 3;

pub const SOL_PACKET: u64 = 263;
pub const PACKET_ADD_MEMBERSHIP: u64 = 1;
pub const PACKET_DROP_MEMBERSHIP: u64 = 2;
pub const PACKET_RECV_OUTPUT: u64 = 3;
pub const PACKET_TX_TIMESTAMP: u64 = 16;
pub const PACKET_IGNORE_OUTGOING: u64 = 23;

/// Linux socket option ABI values used by typed VSOCK option policy.
pub const SOL_SOCKET: u64 = 1;
pub const SO_TYPE: u64 = 3;
pub const SO_ACCEPTCONN: u64 = 30;
pub const SO_PROTOCOL: u64 = 38;
pub const SO_DOMAIN: u64 = 39;

/// Linux IPv4 path-MTU discovery modes (`IP_MTU_DISCOVER`).
pub const IP_PMTUDISC_DONT: i32 = 0;
pub const IP_PMTUDISC_WANT: i32 = 1;
pub const IP_PMTUDISC_DO: i32 = 2;
pub const IP_PMTUDISC_PROBE: i32 = 3;
pub const IP_PMTUDISC_INTERFACE: i32 = 4;
pub const IP_PMTUDISC_OMIT: i32 = 5;

/// True when `mode` is one of Linux's defined `IP_PMTUDISC_*` values. # C: O(1)
pub const fn valid_ip_pmtudisc(mode: i32) -> bool {
    mode >= IP_PMTUDISC_DONT && mode <= IP_PMTUDISC_OMIT
}

/// True when IPv4 input may update learned PMTU for this socket. # C: O(1)
pub const fn ip_pmtudisc_accepts_pmtu(mode: i32) -> bool {
    mode != IP_PMTUDISC_INTERFACE && mode != IP_PMTUDISC_OMIT
}

/// True when IPv4 transmit must ignore learned PMTU and use interface MTU. # C: O(1)
pub const fn ip_pmtudisc_uses_interface(mode: i32) -> bool {
    mode >= IP_PMTUDISC_PROBE
}

/// True when IPv4 transmit may fragment a datagram locally. # C: O(1)
pub const fn ip_pmtudisc_allows_fragmentation(mode: i32) -> bool {
    mode < IP_PMTUDISC_DO || mode == IP_PMTUDISC_OMIT
}

/// Linux IPv6 path-MTU discovery modes (`IPV6_MTU_DISCOVER`).
pub const IPV6_PMTUDISC_DONT: i32 = 0;
pub const IPV6_PMTUDISC_WANT: i32 = 1;
pub const IPV6_PMTUDISC_DO: i32 = 2;
pub const IPV6_PMTUDISC_PROBE: i32 = 3;
pub const IPV6_PMTUDISC_INTERFACE: i32 = 4;
pub const IPV6_PMTUDISC_OMIT: i32 = 5;

/// True when `mode` is one of Linux's defined `IPV6_PMTUDISC_*` values. # C: O(1)
pub const fn valid_ipv6_pmtudisc(mode: i32) -> bool {
    mode >= IPV6_PMTUDISC_DONT && mode <= IPV6_PMTUDISC_OMIT
}

/// True when IPv6 transmit must ignore learned PMTU and use interface MTU. # C: O(1)
pub const fn ipv6_pmtudisc_uses_interface(mode: i32) -> bool {
    mode >= IPV6_PMTUDISC_PROBE
}

/// True when IPv6 transmit may add a local Fragment header. # C: O(1)
pub const fn ipv6_pmtudisc_allows_fragmentation(mode: i32) -> bool {
    mode < IPV6_PMTUDISC_DO || mode == IPV6_PMTUDISC_OMIT
}

/// Linux `shutdown(2)` direction values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ShutdownHow { Read, Write, ReadWrite }

impl TryFrom<u32> for ShutdownHow {
    type Error = ();

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        match raw { 0 => Ok(Self::Read), 1 => Ok(Self::Write), 2 => Ok(Self::ReadWrite), _ => Err(()) }
    }
}

impl ShutdownHow {
    /// Whether this direction closes receive. # C: O(1)
    pub const fn read(self) -> bool { matches!(self, Self::Read | Self::ReadWrite) }
    /// Whether this direction closes send. # C: O(1)
    pub const fn write(self) -> bool { matches!(self, Self::Write | Self::ReadWrite) }
}
