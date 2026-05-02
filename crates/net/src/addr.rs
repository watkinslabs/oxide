// Addressing types per `25` `IpAddr` / `MacAddr` / `NetIfaceId` /
// `IpProto`.

extern crate alloc;

/// 6-byte Ethernet MAC. Stored in network byte order.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO:      MacAddr = MacAddr([0;    6]);

    /// # C: O(1)
    pub const fn is_broadcast(self) -> bool {
        let a = self.0;
        a[0] == 0xff && a[1] == 0xff && a[2] == 0xff
            && a[3] == 0xff && a[4] == 0xff && a[5] == 0xff
    }
    /// IEEE 802 multicast bit (LSB of byte 0).
    /// # C: O(1)
    pub const fn is_multicast(self) -> bool { (self.0[0] & 0x01) != 0 }
    /// IEEE 802 locally-administered bit (bit 1 of byte 0).
    /// # C: O(1)
    pub const fn is_local(self) -> bool { (self.0[0] & 0x02) != 0 }
}

/// IPv4 address — network byte order in `octets()`, host order in `as_u32()`.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv4Addr(u32);

impl Ipv4Addr {
    pub const ANY:       Ipv4Addr = Ipv4Addr(0);
    pub const LOOPBACK:  Ipv4Addr = Ipv4Addr(0x7f00_0001);
    pub const BROADCAST: Ipv4Addr = Ipv4Addr(0xffff_ffff);

    /// # C: O(1)
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32))
    }
    /// # C: O(1)
    pub const fn from_u32(host: u32) -> Self { Self(host) }
    /// # C: O(1)
    pub const fn as_u32(self) -> u32 { self.0 }
    /// Network-byte-order octets.
    /// # C: O(1)
    pub const fn octets(self) -> [u8; 4] {
        [
            (self.0 >> 24) as u8,
            (self.0 >> 16) as u8,
            (self.0 >>  8) as u8,
            (self.0      ) as u8,
        ]
    }

    /// # C: O(1)
    pub const fn is_loopback(self)  -> bool { (self.0 & 0xff00_0000) == 0x7f00_0000 }
    /// # C: O(1)
    pub const fn is_unspecified(self) -> bool { self.0 == 0 }
    /// # C: O(1)
    pub const fn is_broadcast(self) -> bool { self.0 == 0xffff_ffff }
    /// # C: O(1)
    pub const fn is_multicast(self) -> bool { (self.0 >> 28) == 0xe }
    /// 169.254.0.0/16 link-local (RFC 3927).
    /// # C: O(1)
    pub const fn is_link_local(self) -> bool { (self.0 & 0xffff_0000) == 0xa9fe_0000 }
}

/// IPv6 address — 16 bytes in network byte order.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const ANY:      Ipv6Addr = Ipv6Addr([0; 16]);
    pub const LOOPBACK: Ipv6Addr = {
        let mut a = [0u8; 16]; a[15] = 1; Ipv6Addr(a)
    };

    /// # C: O(1)
    pub const fn from_segments(s: [u16; 8]) -> Self {
        let mut o = [0u8; 16];
        let mut i = 0;
        while i < 8 {
            o[2 * i]     = (s[i] >> 8) as u8;
            o[2 * i + 1] = (s[i]     ) as u8;
            i += 1;
        }
        Self(o)
    }

    /// # C: O(1)
    pub const fn segments(self) -> [u16; 8] {
        let o = self.0;
        [
            ((o[ 0] as u16) << 8) | (o[ 1] as u16),
            ((o[ 2] as u16) << 8) | (o[ 3] as u16),
            ((o[ 4] as u16) << 8) | (o[ 5] as u16),
            ((o[ 6] as u16) << 8) | (o[ 7] as u16),
            ((o[ 8] as u16) << 8) | (o[ 9] as u16),
            ((o[10] as u16) << 8) | (o[11] as u16),
            ((o[12] as u16) << 8) | (o[13] as u16),
            ((o[14] as u16) << 8) | (o[15] as u16),
        ]
    }

    /// # C: O(1)
    pub const fn is_unspecified(self) -> bool {
        let s = self.segments();
        s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0
            && s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 0
    }
    /// # C: O(1)
    pub const fn is_loopback(self) -> bool {
        let s = self.segments();
        s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0
            && s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 1
    }
    /// fe80::/10 link-local.
    /// # C: O(1)
    pub const fn is_link_local(self) -> bool {
        (self.0[0] == 0xfe) && ((self.0[1] & 0xc0) == 0x80)
    }
    /// ff00::/8 multicast.
    /// # C: O(1)
    pub const fn is_multicast(self) -> bool { self.0[0] == 0xff }
}

/// Tagged union of v4/v6 addresses for routing & socket APIs.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddr {
    /// # C: O(1)
    pub const fn is_unspecified(self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        }
    }
    /// # C: O(1)
    pub const fn is_loopback(self) -> bool {
        match self {
            IpAddr::V4(a) => a.is_loopback(),
            IpAddr::V6(a) => a.is_loopback(),
        }
    }
}

/// TCP/UDP port number — host order. Wire transmits big-endian; the
/// callers that build packets convert at the boundary.
pub type Port = u16;

/// IP-layer protocol numbers (`IPPROTO_*`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpProto {
    Icmp     = 1,
    Tcp      = 6,
    Udp      = 17,
    Icmpv6   = 58,
    Raw      = 255,
}

/// Opaque interface handle. Real `netdev` registration assigns dense
/// 0..N ids per the order of `register_netdev` calls (`25§3`).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NetIfaceId(pub u32);

/// Common Ethernet / wire type constants per `ETH_P_*`.
pub mod eth_p {
    pub const IPV4: u16 = 0x0800;
    pub const ARP:  u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
    pub const VLAN: u16 = 0x8100;
}
