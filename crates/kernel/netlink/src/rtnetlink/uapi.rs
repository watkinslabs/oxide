/// `RTM_*` message types.
pub const RTM_NEWLINK:  u16 = 16;
pub const RTM_DELLINK:  u16 = 17;
pub const RTM_GETLINK:  u16 = 18;
pub const RTM_SETLINK:  u16 = 19;
pub const RTM_NEWADDR:  u16 = 20;
pub const RTM_DELADDR:  u16 = 21;
pub const RTM_GETADDR:  u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE:  u16 = 32;
pub const RTM_DELRULE:  u16 = 33;
pub const RTM_GETRULE:  u16 = 34;
/// Tunnel notification family retained so `RTM_MAX` matches Linux UAPI even
/// while tunnel operations themselves remain unimplemented in this owner.
pub const RTM_NEWTUNNEL: u16 = 120;
pub const RTM_DELTUNNEL: u16 = RTM_NEWTUNNEL + 1;
pub const RTM_GETTUNNEL: u16 = RTM_NEWTUNNEL + 2;
/// Linux `RTM_MAX`, including ABI-reserved alignment after `__RTM_MAX`.
pub const RTM_MAX:      u16 = RTM_GETTUNNEL + 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ifinfomsg {
    pub ifi_family: u8,
    pub __pad:      u8,
    pub ifi_type:   u16,
    pub ifi_index:  i32,
    pub ifi_flags:  u32,
    pub ifi_change: u32,
}

impl Ifinfomsg {
    pub const SIZE: usize = 16;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.ifi_family;
        buf[1] = self.__pad;
        buf[2..4].copy_from_slice(&self.ifi_type.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.ifi_index.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.ifi_flags.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.ifi_change.to_ne_bytes());
    }
}

pub mod ifla {
    pub const IFLA_UNSPEC:    u16 = 0;
    pub const IFLA_ADDRESS:   u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME:    u16 = 3;
    pub const IFLA_MTU:       u16 = 4;
    pub const IFLA_LINK:      u16 = 5;
    pub const IFLA_QDISC:     u16 = 6;
    pub const IFLA_STATS:     u16 = 7;
    pub const IFLA_TXQLEN:    u16 = 13;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKMODE:  u16 = 17;
    pub const IFLA_STATS64:   u16 = 23;
    pub const IFLA_GROUP:     u16 = 27;
    pub const IFLA_CARRIER:   u16 = 33;
}

/// Linux interface flags are owned by the network device UAPI module.
pub use net::netdev::iff;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ifaddrmsg {
    pub ifa_family:    u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags:     u8,
    pub ifa_scope:     u8,
    pub ifa_index:     u32,
}

impl Ifaddrmsg {
    pub const SIZE: usize = 8;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.ifa_family;
        buf[1] = self.ifa_prefixlen;
        buf[2] = self.ifa_flags;
        buf[3] = self.ifa_scope;
        buf[4..8].copy_from_slice(&self.ifa_index.to_ne_bytes());
    }
}

pub mod ifa {
    pub const IFA_UNSPEC:    u16 = 0;
    pub const IFA_ADDRESS:   u16 = 1;
    pub const IFA_LOCAL:     u16 = 2;
    pub const IFA_LABEL:     u16 = 3;
    pub const IFA_BROADCAST: u16 = 4;
    pub const IFA_ANYCAST:   u16 = 5;
    pub const IFA_CACHEINFO: u16 = 6;
    pub const IFA_FLAGS:     u16 = 8;
}

pub use net::socket_args::{AF_INET6_NETLINK_WIRE as AF_INET6,
    AF_INET_NETLINK_WIRE as AF_INET};

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_SITE: u8 = 200;
pub const RT_SCOPE_LINK: u8 = 253;
pub use net::iface_addr::RT_SCOPE_HOST;
pub const RT_SCOPE_NOWHERE: u8 = 255;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Rtmsg {
    pub rtm_family:    u8,
    pub rtm_dst_len:   u8,
    pub rtm_src_len:   u8,
    pub rtm_tos:       u8,
    pub rtm_table:     u8,
    pub rtm_protocol:  u8,
    pub rtm_scope:     u8,
    pub rtm_type:      u8,
    pub rtm_flags:     u32,
}

impl Rtmsg {
    pub const SIZE: usize = 12;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.rtm_family;
        buf[1] = self.rtm_dst_len;
        buf[2] = self.rtm_src_len;
        buf[3] = self.rtm_tos;
        buf[4] = self.rtm_table;
        buf[5] = self.rtm_protocol;
        buf[6] = self.rtm_scope;
        buf[7] = self.rtm_type;
        buf[8..12].copy_from_slice(&self.rtm_flags.to_ne_bytes());
    }
}

pub mod rta {
    pub const RTA_UNSPEC:    u16 = 0;
    pub const RTA_DST:       u16 = 1;
    pub const RTA_SRC:       u16 = 2;
    pub const RTA_IIF:       u16 = 3;
    pub const RTA_OIF:       u16 = 4;
    pub const RTA_GATEWAY:   u16 = 5;
    pub const RTA_PRIORITY:  u16 = 6;
    pub const RTA_PREFSRC:   u16 = 7;
    pub const RTA_METRICS:   u16 = 8;
    pub const RTA_MULTIPATH: u16 = 9;
    pub const RTA_TABLE:     u16 = 15;
}

/// `struct ndmsg` — Linux `linux/neighbour.h`. Precedes the NDA_* attributes
/// in every RTM_*NEIGH message.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ndmsg {
    pub ndm_family:  u8,
    pub __pad1:      u8,
    pub __pad2:      u16,
    pub ndm_ifindex: i32,
    pub ndm_state:   u16,
    pub ndm_flags:   u8,
    pub ndm_type:    u8,
}

impl Ndmsg {
    pub const SIZE: usize = 12;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.ndm_family;
        buf[1] = self.__pad1;
        buf[2..4].copy_from_slice(&self.__pad2.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.ndm_ifindex.to_ne_bytes());
        buf[8..10].copy_from_slice(&self.ndm_state.to_ne_bytes());
        buf[10] = self.ndm_flags;
        buf[11] = self.ndm_type;
    }

    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        Some(Self {
            ndm_family: buf[0],
            __pad1: buf[1],
            __pad2: u16::from_ne_bytes([buf[2], buf[3]]),
            ndm_ifindex: i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ndm_state: u16::from_ne_bytes([buf[8], buf[9]]),
            ndm_flags: buf[10],
            ndm_type: buf[11],
        })
    }
}

/// NUD_* neighbour reachability bits (`ndm_state`), Linux `linux/neighbour.h`.
pub mod nud {
    pub const NUD_INCOMPLETE: u16 = 0x01;
    pub const NUD_REACHABLE:  u16 = 0x02;
    pub const NUD_STALE:      u16 = 0x04;
    pub const NUD_DELAY:      u16 = 0x08;
    pub const NUD_PROBE:      u16 = 0x10;
    pub const NUD_FAILED:     u16 = 0x20;
    pub const NUD_NOARP:      u16 = 0x40;
    pub const NUD_PERMANENT:  u16 = 0x80;
}

/// NDA_* neighbour attribute ids, Linux `linux/neighbour.h`.
pub mod nda {
    pub const NDA_UNSPEC:    u16 = 0;
    pub const NDA_DST:       u16 = 1;
    pub const NDA_LLADDR:    u16 = 2;
    pub const NDA_CACHEINFO: u16 = 3;
}

pub const RTPROT_UNSPEC: u8 = 0;
pub const RTPROT_REDIRECT: u8 = 1;
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_RA: u8 = 9;

pub const RTN_UNSPEC: u8 = 0;
pub use net::route::{RTN_LOCAL, RTN_UNICAST};
pub const RTN_BROADCAST: u8 = 3;
pub use net::route::{RTN_BLACKHOLE, RTN_PROHIBIT, RTN_THROW, RTN_UNREACHABLE};

pub const RT_TABLE_UNSPEC: u8 = 0;
pub use net::policy_rule::{RT_TABLE_DEFAULT_WIRE as RT_TABLE_DEFAULT,
    RT_TABLE_LOCAL_WIRE as RT_TABLE_LOCAL, RT_TABLE_MAIN_WIRE as RT_TABLE_MAIN};
