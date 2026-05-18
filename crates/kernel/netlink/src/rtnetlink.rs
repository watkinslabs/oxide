// NETLINK_ROUTE per `25§7` + Linux `linux/rtnetlink.h`. F89 implements
// the RTM_GETLINK dump path that `ip link show` issues. Per-iface
// RTM_NEWLINK replies are built from `net::sock::stack().ifaces`;
// the dump terminates with NLMSG_DONE. RTM_NEWADDR/GETADDR and
// RTM_NEWROUTE/GETROUTE land in follow-up F90+/F91 PRs.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use crate::{flags, nlmsg_align, Nlmsghdr};

// ---- Message types -------------------------------------------------------

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

// ---- struct ifinfomsg (16 bytes) -----------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ifinfomsg {
    pub ifi_family: u8,  // AF_UNSPEC for queries; reply echoes AF_UNSPEC
    pub __pad:      u8,  // reserved, zero
    pub ifi_type:   u16, // ARPHRD_* (ETHER = 1, LOOPBACK = 772)
    pub ifi_index:  i32, // ifindex (1-based)
    pub ifi_flags:  u32, // IFF_UP, IFF_RUNNING, IFF_BROADCAST, ...
    pub ifi_change: u32, // 0xFFFFFFFF on set; 0 on query/reply
}

impl Ifinfomsg {
    pub const SIZE: usize = 16;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0]      = self.ifi_family;
        buf[1]      = self.__pad;
        buf[2..4].copy_from_slice(&self.ifi_type.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.ifi_index.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.ifi_flags.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.ifi_change.to_ne_bytes());
    }
}

// ---- IFLA_* attribute types ---------------------------------------------

pub mod ifla {
    pub const IFLA_UNSPEC:    u16 = 0;
    pub const IFLA_ADDRESS:   u16 = 1;  // hardware MAC
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME:    u16 = 3;  // CString
    pub const IFLA_MTU:       u16 = 4;  // u32
    pub const IFLA_LINK:      u16 = 5;
    pub const IFLA_QDISC:     u16 = 6;
    pub const IFLA_STATS:     u16 = 7;
    pub const IFLA_TXQLEN:    u16 = 13;
    pub const IFLA_OPERSTATE: u16 = 16; // u8
    pub const IFLA_LINKMODE:  u16 = 17;
    pub const IFLA_GROUP:     u16 = 27;
}

// ---- IFF_* iface flags ---------------------------------------------------

pub mod iff {
    pub const IFF_UP:          u32 = 0x0001;
    pub const IFF_BROADCAST:   u32 = 0x0002;
    pub const IFF_DEBUG:       u32 = 0x0004;
    pub const IFF_LOOPBACK:    u32 = 0x0008;
    pub const IFF_POINTOPOINT: u32 = 0x0010;
    pub const IFF_NOTRAILERS:  u32 = 0x0020;
    pub const IFF_RUNNING:     u32 = 0x0040;
    pub const IFF_NOARP:       u32 = 0x0080;
    pub const IFF_PROMISC:     u32 = 0x0100;
    pub const IFF_MULTICAST:   u32 = 0x1000;
}

// ---- ARPHRD_* hw types --------------------------------------------------

pub const ARPHRD_ETHER:    u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

// ---- nlattr helpers ------------------------------------------------------

/// `struct nlattr` is 4-byte header { u16 nla_len; u16 nla_type }
/// followed by the payload, rounded up to NLA_ALIGNTO (4).
/// `nla_len` covers the header + payload but NOT the trailing pad.
/// # C: O(N) memcpy
pub fn put_nlattr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = 4 + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nlmsg_align(total) - total;
    for _ in 0..pad { out.push(0); }
}

/// # C: O(1)
pub fn put_nlattr_u32(out: &mut Vec<u8>, ty: u16, v: u32) {
    put_nlattr(out, ty, &v.to_ne_bytes());
}

/// # C: O(1)
pub fn put_nlattr_u8(out: &mut Vec<u8>, ty: u16, v: u8) {
    put_nlattr(out, ty, &[v]);
}

/// `nla_put_string` per Linux — NUL-terminated.
/// # C: O(N)
pub fn put_nlattr_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put_nlattr(out, ty, &payload);
}

// ---- RTM_GETLINK dump ----------------------------------------------------

/// Operational-state codes per Linux IF_OPER_* (`if_link.h`).
const IF_OPER_UP: u8 = 6;

/// Build a single RTM_NEWLINK reply for one iface.
///
/// Layout: nlmsghdr (16) | ifinfomsg (16) | nlattr blocks.
/// Each block is `{ u16 len; u16 type; payload }` padded to 4 B.
/// # C: O(N attrs)
fn build_newlink_reply(
    seq: u32, pid: u32,
    ifindex: i32,
    name: &str,
    mac: [u8; 6],
    mtu: u32,
    is_loopback: bool,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(128);

    // ifinfomsg
    let mut ifi = Ifinfomsg::default();
    ifi.ifi_family = 0; // AF_UNSPEC
    ifi.ifi_type   = if is_loopback { ARPHRD_LOOPBACK } else { ARPHRD_ETHER };
    ifi.ifi_index  = ifindex;
    ifi.ifi_flags  = iff::IFF_UP | iff::IFF_RUNNING
                   | if is_loopback { iff::IFF_LOOPBACK }
                     else { iff::IFF_BROADCAST | iff::IFF_MULTICAST };
    ifi.ifi_change = 0;
    let mut ifi_buf = [0u8; Ifinfomsg::SIZE];
    ifi.write_to(&mut ifi_buf);
    body.extend_from_slice(&ifi_buf);

    // Attributes. Order matches what `ip link show` expects.
    put_nlattr_str(&mut body, ifla::IFLA_IFNAME, name);
    put_nlattr(&mut body, ifla::IFLA_ADDRESS,   &mac);
    put_nlattr(&mut body, ifla::IFLA_BROADCAST, &[0xFFu8; 6]);
    put_nlattr_u32(&mut body, ifla::IFLA_MTU, mtu);
    put_nlattr_u32(&mut body, ifla::IFLA_TXQLEN, 1000);
    put_nlattr_u8(&mut body, ifla::IFLA_OPERSTATE, IF_OPER_UP);
    put_nlattr_u8(&mut body, ifla::IFLA_LINKMODE, 0);

    // Now serialize the leading nlmsghdr with the full length.
    let total = Nlmsghdr::SIZE + body.len();
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  RTM_NEWLINK,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    // The reply itself is nlmsg-aligned; caller may concatenate.
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Handle a single RTM_GETLINK request. Returns the reply byte
/// stream containing one RTM_NEWLINK per registered iface, then a
/// trailing NLMSG_DONE. The caller (NetlinkSocket::write) pushes the
/// reply onto the socket's RX queue verbatim — recv* reads it.
/// # C: O(N_ifaces)
pub fn handle_getlink(req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let entries = ifaces_snapshot();
    for (id, name, mac, mtu, is_lo) in entries.iter() {
        let one = build_newlink_reply(
            req.nlmsg_seq, req.nlmsg_pid,
            *id as i32,
            name,
            *mac,
            *mtu,
            *is_lo,
            /*multi=*/true,
        );
        reply.extend_from_slice(&one);
    }
    // NLMSG_DONE terminator.
    let mut done_buf = [0u8; Nlmsghdr::SIZE];
    let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
    done.nlmsg_flags = flags::NLM_F_MULTI;
    done.write_to(&mut done_buf);
    reply.extend_from_slice(&done_buf);
    reply
}

/// Iface snapshot used by RTM_GETLINK. Kernel build pulls live
/// devices from `net::sock::stack().ifaces`; hosted/test builds
/// return an empty list so the rtnetlink reply path is testable
/// without dragging the runtime socket layer in.
#[cfg(target_os = "oxide-kernel")]
fn ifaces_snapshot() -> Vec<(u32, alloc::string::String, [u8; 6], u32, bool)> {
    let stack = net::sock::stack();
    stack.ifaces.snapshot_devs()
        .into_iter()
        .map(|(id, dev)| {
            let is_lo = dev.name() == "lo";
            (id.0, alloc::string::String::from(dev.name()),
             dev.mac().0, dev.mtu(), is_lo)
        })
        .collect()
}
#[cfg(not(target_os = "oxide-kernel"))]
fn ifaces_snapshot() -> Vec<(u32, alloc::string::String, [u8; 6], u32, bool)> {
    alloc::vec::Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtm_constants_match_linux() {
        assert_eq!(RTM_NEWLINK,  16);
        assert_eq!(RTM_GETLINK,  18);
        assert_eq!(RTM_NEWADDR,  20);
        assert_eq!(RTM_GETADDR,  22);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_GETROUTE, 26);
    }

    #[test]
    fn ifinfomsg_size_matches_linux() {
        assert_eq!(Ifinfomsg::SIZE, 16);
    }

    #[test]
    fn put_nlattr_pads_to_4_bytes() {
        let mut out = Vec::new();
        put_nlattr(&mut out, ifla::IFLA_IFNAME, b"eth0");
        // 4-byte header + 4-byte payload, already aligned, no pad.
        assert_eq!(out.len(), 8);
        // header len field covers header+payload, not pad.
        let nla_len = u16::from_ne_bytes([out[0], out[1]]) as usize;
        assert_eq!(nla_len, 8);

        let mut out2 = Vec::new();
        put_nlattr(&mut out2, ifla::IFLA_IFNAME, b"lo");
        // 4-byte header + 2-byte payload = 6 raw, padded to 8.
        assert_eq!(out2.len(), 8);
        let nla_len2 = u16::from_ne_bytes([out2[0], out2[1]]) as usize;
        assert_eq!(nla_len2, 6);
    }

    #[test]
    fn put_nlattr_str_nul_terminates() {
        let mut out = Vec::new();
        put_nlattr_str(&mut out, ifla::IFLA_IFNAME, "eth0");
        // header(4) + "eth0\0"(5) = 9, padded to 12.
        assert_eq!(out.len(), 12);
        let nla_len = u16::from_ne_bytes([out[0], out[1]]) as usize;
        assert_eq!(nla_len, 9);
        assert_eq!(&out[4..9], b"eth0\0");
    }
}
