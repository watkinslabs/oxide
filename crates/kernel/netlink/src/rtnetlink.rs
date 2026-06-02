// NETLINK_ROUTE per `25§7` + Linux `linux/rtnetlink.h`. F89 implements
// the RTM_GETLINK dump path that `ip link show` issues. Per-iface
// RTM_NEWLINK replies are built from `net::sock::stack().ifaces`;
// the dump terminates with NLMSG_DONE. RTM_NEWADDR/GETADDR and
// RTM_NEWROUTE/GETROUTE land in follow-up F90+/F91 PRs.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use crate::{flags, msg, nlmsg_align, Nlmsghdr};
use sync::{Spinlock, Socket as SockLockClass};

/// One entry in the kernel's iface→address table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IfaceAddr {
    pub ifindex:   u32,
    pub family:    u8,   // AF_INET (v1 IPv6 ride a follow-up)
    pub addr:      [u8; 4],
    pub prefixlen: u8,
    pub scope:     u8,
}

/// Process-global iface address table. F92 replaces the previous
/// hardcoded snapshot in `handle_getaddr` with a real table that
/// userspace can mutate via RTM_NEWADDR / RTM_DELADDR. Boot seeds
/// the qemu user-net default so `ip addr show` still works without
/// a running DHCP client.
static ADDR_TABLE: Spinlock<Vec<IfaceAddr>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Insert (or replace, by ifindex+addr+prefixlen) an address row.
/// Idempotent; same triple twice is one row.
/// # C: O(N) duplicate scan
pub fn addr_insert(row: IfaceAddr) {
    let mut g = ADDR_TABLE.lock();
    let dup = g.iter().position(|r|
        r.ifindex == row.ifindex
        && r.addr == row.addr
        && r.prefixlen == row.prefixlen);
    if let Some(i) = dup { g[i] = row; }
    else { g.push(row); }
}

/// Remove rows matching (ifindex, addr, prefixlen). Returns the
/// number removed. # C: O(N)
pub fn addr_remove(ifindex: u32, addr: [u8; 4], prefixlen: u8) -> usize {
    let mut g = ADDR_TABLE.lock();
    let before = g.len();
    g.retain(|r|
        !(r.ifindex == ifindex
          && r.addr == addr
          && r.prefixlen == prefixlen));
    before - g.len()
}

/// Snapshot of all address rows. # C: O(N)
pub fn addr_snapshot() -> Vec<IfaceAddr> {
    ADDR_TABLE.lock().clone()
}

/// Boot-time seed of the default v1 addresses. Idempotent — re-
/// running with the same rows is a no-op. Called from pci_boot
/// right after the eth0 NetDev registers so `ip addr show` works
/// before any DHCP client runs.
/// # C: O(1) — fixed-size insert sequence
pub fn seed_defaults(eth0_ifindex: Option<u32>, lo_ifindex: Option<u32>) {
    if let Some(idx) = lo_ifindex {
        addr_insert(IfaceAddr {
            ifindex: idx, family: AF_INET,
            addr: [127, 0, 0, 1], prefixlen: 8, scope: RT_SCOPE_HOST,
        });
    }
    if let Some(idx) = eth0_ifindex {
        addr_insert(IfaceAddr {
            ifindex: idx, family: AF_INET,
            addr: [10, 0, 2, 15], prefixlen: 24, scope: RT_SCOPE_UNIVERSE,
        });
    }
}

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

// ---- struct ifaddrmsg (8 bytes) -----------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Ifaddrmsg {
    pub ifa_family:    u8, // AF_INET or AF_INET6
    pub ifa_prefixlen: u8, // /N (e.g. 24)
    pub ifa_flags:     u8, // IFA_F_*
    pub ifa_scope:     u8, // RT_SCOPE_*
    pub ifa_index:     u32, // ifindex
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

// ---- IFA_* attribute types ----------------------------------------------

pub mod ifa {
    pub const IFA_UNSPEC:    u16 = 0;
    pub const IFA_ADDRESS:   u16 = 1;  // peer addr (or local on lo)
    pub const IFA_LOCAL:     u16 = 2;  // local addr
    pub const IFA_LABEL:     u16 = 3;  // ifname
    pub const IFA_BROADCAST: u16 = 4;
    pub const IFA_ANYCAST:   u16 = 5;
    pub const IFA_CACHEINFO: u16 = 6;
    pub const IFA_FLAGS:     u16 = 8;
}

pub const AF_INET:  u8 = 2;
pub const AF_INET6: u8 = 10;

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_SITE:     u8 = 200;
pub const RT_SCOPE_LINK:     u8 = 253;
pub const RT_SCOPE_HOST:     u8 = 254;
pub const RT_SCOPE_NOWHERE:  u8 = 255;

// ---- struct rtmsg (12 bytes) --------------------------------------------

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

// ---- RTA_* attribute types ----------------------------------------------

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
    pub const RTA_TABLE:     u16 = 15;
}

// ---- RTPROT_* / RTN_* / RT_TABLE_* --------------------------------------

pub const RTPROT_UNSPEC:   u8 = 0;
pub const RTPROT_REDIRECT: u8 = 1;
pub const RTPROT_KERNEL:   u8 = 2;
pub const RTPROT_BOOT:     u8 = 3;
pub const RTPROT_STATIC:   u8 = 4;

pub const RTN_UNSPEC:      u8 = 0;
pub const RTN_UNICAST:     u8 = 1;
pub const RTN_LOCAL:       u8 = 2;
pub const RTN_BROADCAST:   u8 = 3;

pub const RT_TABLE_UNSPEC:  u8 = 0;
pub const RT_TABLE_DEFAULT: u8 = 253;
pub const RT_TABLE_MAIN:    u8 = 254;
pub const RT_TABLE_LOCAL:   u8 = 255;

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
const IF_OPER_DOWN: u8 = 2;

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
    flags: u32,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(128);

    // ifinfomsg — ifi_flags is the iface's REAL current flag state
    // (from the registry), not a reply-time fabrication.
    let mut ifi = Ifinfomsg::default();
    ifi.ifi_family = 0; // AF_UNSPEC
    ifi.ifi_type   = if is_loopback { ARPHRD_LOOPBACK } else { ARPHRD_ETHER };
    ifi.ifi_index  = ifindex;
    ifi.ifi_flags  = flags;
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
    let operstate = if flags & iff::IFF_UP != 0 { IF_OPER_UP } else { IF_OPER_DOWN };
    put_nlattr_u8(&mut body, ifla::IFLA_OPERSTATE, operstate);
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
    for (id, name, mac, mtu, is_lo, flags) in entries.iter() {
        let one = build_newlink_reply(
            req.nlmsg_seq, req.nlmsg_pid,
            *id as i32,
            name,
            *mac,
            *mtu,
            *is_lo,
            *flags,
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

/// Build a single RTM_NEWADDR reply for one iface's IPv4 address.
/// `addr` / `prefixlen` are stored as host-order; we serialize the
/// IPv4 as network-order bytes per Linux RTNL convention.
/// # C: O(N attrs)
fn build_newaddr_reply(
    seq: u32, pid: u32,
    ifindex: i32,
    label: &str,
    addr: [u8; 4],
    prefixlen: u8,
    scope: u8,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let ifa = Ifaddrmsg {
        ifa_family:    AF_INET,
        ifa_prefixlen: prefixlen,
        ifa_flags:     0,
        ifa_scope:     scope,
        ifa_index:     ifindex as u32,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);

    put_nlattr(&mut body, ifa::IFA_LOCAL,   &addr);
    put_nlattr(&mut body, ifa::IFA_ADDRESS, &addr);
    if scope != RT_SCOPE_HOST {
        // Broadcast = network|~mask, derived from prefixlen.
        let host_mask = if prefixlen >= 32 { 0u32 }
                        else { (1u32 << (32 - prefixlen)) - 1 };
        let a = u32::from_be_bytes(addr);
        let bcast = ((a & !host_mask) | host_mask).to_be_bytes();
        put_nlattr(&mut body, ifa::IFA_BROADCAST, &bcast);
    }
    put_nlattr_str(&mut body, ifa::IFA_LABEL, label);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  RTM_NEWADDR,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// RTM_GETADDR dump. One RTM_NEWADDR per iface's IPv4 address,
/// terminated by NLMSG_DONE. v1 wires hardcoded addresses:
/// `lo` → 127.0.0.1/8 host-scope; any non-loopback → 10.0.2.15/24
/// universe-scope (qemu user-net default). Real per-iface address
/// table lands when userspace tooling writes them in via
/// RTM_NEWADDR (a follow-up; for now the kernel publishes the
/// defaults so `ip addr show` shows sensible output).
/// # C: O(N_ifaces)
pub fn handle_getaddr(req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    let ifaces = ifaces_snapshot();
    for row in addr_snapshot().iter() {
        // Resolve the iface label by ifindex; missing → "?"
        let name = ifaces.iter()
            .find(|(id, _, _, _, _, _)| *id == row.ifindex)
            .map(|(_, n, _, _, _, _)| n.as_str())
            .unwrap_or("?");
        let one = build_newaddr_reply(
            req.nlmsg_seq, req.nlmsg_pid,
            row.ifindex as i32, name, row.addr, row.prefixlen, row.scope,
            /*multi=*/true,
        );
        reply.extend_from_slice(&one);
    }
    let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
    done.nlmsg_flags = flags::NLM_F_MULTI;
    let mut done_buf = [0u8; Nlmsghdr::SIZE];
    done.write_to(&mut done_buf);
    reply.extend_from_slice(&done_buf);
    reply
}

/// Parse the nlattr stream that follows an ifaddrmsg, looking for
/// the four addresses we care about: IFA_LOCAL, IFA_ADDRESS,
/// IFA_BROADCAST, IFA_LABEL. Returns IFA_LOCAL or IFA_ADDRESS as
/// the canonical addr.
/// # C: O(N attrs)
fn parse_newaddr_attrs(attrs: &[u8]) -> Option<[u8; 4]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        if (nla_type == ifa::IFA_LOCAL || nla_type == ifa::IFA_ADDRESS)
            && payload.len() == 4
        {
            return Some([payload[0], payload[1], payload[2], payload[3]]);
        }
        off += nlmsg_align(nla_len);
    }
    None
}

/// Build a NLMSG_ERROR reply (16 B nlmsghdr + 4 B errno + the
/// echoed request header). errno=0 means "ack" per Linux RTNL
/// convention — userspace tools (`ip`, glibc netlink, libmnl)
/// treat err=0 as success.
/// # C: O(1)
fn nlmsg_ack(req: &Nlmsghdr, err: i32) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + 4 + Nlmsghdr::SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  msg::NLMSG_ERROR,
        nlmsg_flags: 0,
        nlmsg_seq:   req.nlmsg_seq,
        nlmsg_pid:   req.nlmsg_pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&err.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}

/// Handle RTM_NEWADDR. Buffer layout: nlmsghdr(16) | ifaddrmsg(8) |
/// attrs. Inserts the (ifindex, addr, prefixlen) tuple into the
/// process-global address table. Returns an NLMSG_ERROR with
/// err=0 on success.
/// # C: O(N attrs + addr_table size)
pub fn handle_newaddr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ifa_off = Nlmsghdr::SIZE;
    if full_msg.len() < ifa_off + Ifaddrmsg::SIZE {
        return nlmsg_ack(req, -22 /* EINVAL */);
    }
    let family    = full_msg[ifa_off];
    let prefixlen = full_msg[ifa_off + 1];
    let scope     = full_msg[ifa_off + 3];
    let ifindex   = u32::from_ne_bytes([
        full_msg[ifa_off + 4], full_msg[ifa_off + 5],
        full_msg[ifa_off + 6], full_msg[ifa_off + 7],
    ]);
    if family != AF_INET {
        return nlmsg_ack(req, -97 /* EAFNOSUPPORT */);
    }
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let addr = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None    => return nlmsg_ack(req, -22 /* EINVAL */),
    };
    addr_insert(IfaceAddr {
        ifindex, family, addr, prefixlen, scope,
    });
    nlmsg_ack(req, 0)
}

/// Handle RTM_DELADDR. Buffer layout same as RTM_NEWADDR.
/// # C: O(N attrs + addr_table size)
pub fn handle_deladdr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let ifa_off = Nlmsghdr::SIZE;
    if full_msg.len() < ifa_off + Ifaddrmsg::SIZE {
        return nlmsg_ack(req, -22);
    }
    let prefixlen = full_msg[ifa_off + 1];
    let ifindex   = u32::from_ne_bytes([
        full_msg[ifa_off + 4], full_msg[ifa_off + 5],
        full_msg[ifa_off + 6], full_msg[ifa_off + 7],
    ]);
    let attrs = &full_msg[ifa_off + Ifaddrmsg::SIZE..];
    let addr = match parse_newaddr_attrs(attrs) {
        Some(a) => a,
        None    => return nlmsg_ack(req, -22),
    };
    let n = addr_remove(ifindex, addr, prefixlen);
    nlmsg_ack(req, if n > 0 { 0 } else { -2 /* ENOENT */ })
}

/// Build one RTM_NEWROUTE reply.
/// # C: O(N attrs)
#[allow(clippy::too_many_arguments)]
fn build_newroute_reply(
    seq: u32, pid: u32,
    table: u8, protocol: u8, scope: u8, kind: u8,
    dst: Option<([u8; 4], u8)>, // (addr, prefixlen)
    gateway: Option<[u8; 4]>,
    oif_ifindex: u32,
    prefsrc: Option<[u8; 4]>,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let dst_len = dst.map(|(_, n)| n).unwrap_or(0);
    let rtm = Rtmsg {
        rtm_family:   AF_INET,
        rtm_dst_len:  dst_len,
        rtm_src_len:  0,
        rtm_tos:      0,
        rtm_table:    table,
        rtm_protocol: protocol,
        rtm_scope:    scope,
        rtm_type:     kind,
        rtm_flags:    0,
    };
    let mut rtm_buf = [0u8; Rtmsg::SIZE];
    rtm.write_to(&mut rtm_buf);
    body.extend_from_slice(&rtm_buf);

    if let Some((addr, _)) = dst {
        put_nlattr(&mut body, rta::RTA_DST, &addr);
    }
    if let Some(g) = gateway {
        put_nlattr(&mut body, rta::RTA_GATEWAY, &g);
    }
    put_nlattr_u32(&mut body, rta::RTA_OIF, oif_ifindex);
    if let Some(s) = prefsrc {
        put_nlattr(&mut body, rta::RTA_PREFSRC, &s);
    }

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  RTM_NEWROUTE,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// RTM_GETROUTE dump. v1 publishes the hardcoded route table used
/// at boot. Real per-iface route table writes via RTM_NEWROUTE are
/// follow-up (need the route-policy substrate + persistent table).
///
/// Published routes when an eth0-like iface is up:
///   `local 127.0.0.0/8 dev lo proto kernel scope host`
///   `10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15`
///   `default via 10.0.2.2 dev eth0 proto boot`
/// # C: O(N_ifaces)
pub fn handle_getroute(req: &Nlmsghdr) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    for r in route_snapshot().iter() {
        reply.extend_from_slice(&build_newroute_reply(
            req.nlmsg_seq, req.nlmsg_pid,
            r.table, r.protocol, r.scope, r.kind,
            r.dst, r.gateway, r.oif_ifindex, r.prefsrc,
            true,
        ));
    }
    let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
    done.nlmsg_flags = flags::NLM_F_MULTI;
    let mut done_buf = [0u8; Nlmsghdr::SIZE];
    done.write_to(&mut done_buf);
    reply.extend_from_slice(&done_buf);
    reply
}

/// One row in the kernel's route table. v1 IPv4 only; IPv6
/// equivalents (RTA_DST length=16) ride a follow-up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub table:       u8,
    pub protocol:    u8,
    pub scope:       u8,
    pub kind:        u8,
    pub dst:         Option<([u8; 4], u8)>,
    pub gateway:     Option<[u8; 4]>,
    pub oif_ifindex: u32,
    pub prefsrc:     Option<[u8; 4]>,
}

static ROUTE_TABLE: Spinlock<Vec<RouteRow>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Insert (or replace by key=`(table, dst, oif)`).
/// # C: O(N)
pub fn route_insert(row: RouteRow) {
    let mut g = ROUTE_TABLE.lock();
    let dup = g.iter().position(|r|
        r.table == row.table
        && r.dst == row.dst
        && r.oif_ifindex == row.oif_ifindex);
    if let Some(i) = dup { g[i] = row; }
    else { g.push(row); }
}

/// Remove rows matching `(table, dst, oif)`. Returns count removed.
/// # C: O(N)
pub fn route_remove(table: u8, dst: Option<([u8; 4], u8)>, oif: u32) -> usize {
    let mut g = ROUTE_TABLE.lock();
    let before = g.len();
    g.retain(|r| !(r.table == table && r.dst == dst && r.oif_ifindex == oif));
    before - g.len()
}

/// Full snapshot for RTM_GETROUTE.
/// # C: O(N) clone
pub fn route_snapshot() -> Vec<RouteRow> {
    ROUTE_TABLE.lock().clone()
}

/// Seed the boot-time default route for the loopback iface.
/// `local 127.0.0.0/8 dev lo proto kernel scope host`.
/// # C: O(1)
pub fn seed_default_routes_lo(lo_ifindex: u32) {
    route_insert(RouteRow {
        table: RT_TABLE_LOCAL, protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_HOST, kind: RTN_LOCAL,
        dst: Some(([127, 0, 0, 0], 8)),
        gateway: None, oif_ifindex: lo_ifindex,
        prefsrc: Some([127, 0, 0, 1]),
    });
}

/// Seed the boot-time default routes for the eth0 iface. Called
/// from pci_boot alongside addr seed_defaults.
/// # C: O(1)
pub fn seed_default_routes(eth0_ifindex: u32) {
    route_insert(RouteRow {
        table: RT_TABLE_MAIN, protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_LINK, kind: RTN_UNICAST,
        dst: Some(([10, 0, 2, 0], 24)),
        gateway: None, oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]),
    });
    route_insert(RouteRow {
        table: RT_TABLE_MAIN, protocol: RTPROT_BOOT,
        scope: RT_SCOPE_UNIVERSE, kind: RTN_UNICAST,
        dst: None, gateway: Some([10, 0, 2, 2]),
        oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]),
    });
}

/// Parse RTA_* attributes following an rtmsg, returning the
/// destination prefix, gateway, oif_ifindex, and prefsrc as we
/// find them.
/// # C: O(N attrs)
fn parse_route_attrs(attrs: &[u8])
    -> (Option<[u8; 4]>, Option<[u8; 4]>, Option<u32>, Option<[u8; 4]>)
{
    let mut dst: Option<[u8; 4]> = None;
    let mut gw:  Option<[u8; 4]> = None;
    let mut oif: Option<u32>     = None;
    let mut src: Option<[u8; 4]> = None;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        let payload = &attrs[off + 4..off + nla_len];
        match (nla_type, payload.len()) {
            (rta::RTA_DST, 4)     => dst = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_GATEWAY, 4) => gw  = Some([payload[0], payload[1], payload[2], payload[3]]),
            (rta::RTA_OIF, 4)     => oif = Some(u32::from_ne_bytes([
                                       payload[0], payload[1], payload[2], payload[3]])),
            (rta::RTA_PREFSRC, 4) => src = Some([payload[0], payload[1], payload[2], payload[3]]),
            _ => {}
        }
        off += nlmsg_align(nla_len);
    }
    (dst, gw, oif, src)
}

/// Handle RTM_NEWROUTE. Buffer layout: nlmsghdr | rtmsg(12) | attrs.
/// Inserts (table, dst, oif) into the global route table. Returns
/// NLMSG_ERROR with err=0 on success.
/// # C: O(N attrs + route table)
pub fn handle_newroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE {
        return nlmsg_ack(req, -22);
    }
    let family    = full_msg[rtm_off];
    let dst_len   = full_msg[rtm_off + 1];
    let table     = full_msg[rtm_off + 4];
    let protocol  = full_msg[rtm_off + 5];
    let scope     = full_msg[rtm_off + 6];
    let kind      = full_msg[rtm_off + 7];
    if family != AF_INET {
        return nlmsg_ack(req, -97);
    }
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let (dst_addr, gw, oif, src) = parse_route_attrs(attrs);
    let oif = match oif {
        Some(o) => o,
        None    => return nlmsg_ack(req, -22),
    };
    let dst = dst_addr.map(|a| (a, dst_len));
    route_insert(RouteRow {
        table, protocol, scope, kind,
        dst, gateway: gw, oif_ifindex: oif, prefsrc: src,
    });
    nlmsg_ack(req, 0)
}

/// Handle RTM_DELROUTE. Buffer layout same as RTM_NEWROUTE.
/// # C: O(N attrs + route table)
pub fn handle_delroute(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let rtm_off = Nlmsghdr::SIZE;
    if full_msg.len() < rtm_off + Rtmsg::SIZE {
        return nlmsg_ack(req, -22);
    }
    let dst_len = full_msg[rtm_off + 1];
    let table   = full_msg[rtm_off + 4];
    let attrs = &full_msg[rtm_off + Rtmsg::SIZE..];
    let (dst_addr, _gw, oif, _src) = parse_route_attrs(attrs);
    let oif = match oif {
        Some(o) => o,
        None    => return nlmsg_ack(req, -22),
    };
    let dst = dst_addr.map(|a| (a, dst_len));
    let n = route_remove(table, dst, oif);
    nlmsg_ack(req, if n > 0 { 0 } else { -3 /* ESRCH */ })
}

// quiet warnings for the `msg` re-export that's only used by lib.rs
const _: u16 = msg::NLMSG_DONE;

/// Iface snapshot used by RTM_GETLINK. Kernel build pulls live
/// devices from `net::sock::stack().ifaces`; hosted/test builds
/// return an empty list so the rtnetlink reply path is testable
/// without dragging the runtime socket layer in.
#[cfg(target_os = "oxide-kernel")]
fn ifaces_snapshot() -> Vec<(u32, alloc::string::String, [u8; 6], u32, bool, u32)> {
    let stack = net::sock::stack();
    stack.ifaces.snapshot_devs()
        .into_iter()
        .map(|(id, dev)| {
            let is_lo = dev.name() == "lo";
            let flags = stack.ifaces.iface_flags(id).unwrap_or(0);
            (id.0, alloc::string::String::from(dev.name()),
             dev.mac().0, dev.mtu(), is_lo, flags)
        })
        .collect()
}
#[cfg(not(target_os = "oxide-kernel"))]
fn ifaces_snapshot() -> Vec<(u32, alloc::string::String, [u8; 6], u32, bool, u32)> {
    alloc::vec::Vec::new()
}

/// Handle RTM_NEWLINK / RTM_SETLINK. Parses the ifinfomsg and applies the
/// flag change to the iface's REAL flags (registry), so `ip link set X
/// up/down` and systemd's loopback bring-up actually mutate kernel state
/// (RTM_GETLINK then reports it). Buffer: nlmsghdr(16) | ifinfomsg(16) |
/// attrs. Returns an NLMSG_ERROR ack (err=0 success / -ENODEV). # C: O(N)
pub fn handle_setlink(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifinfomsg::SIZE { return nlmsg_ack(req, -22 /* EINVAL */); }
    let ifindex = i32::from_ne_bytes([
        full_msg[off + 4], full_msg[off + 5], full_msg[off + 6], full_msg[off + 7],
    ]);
    let ifi_flags = u32::from_ne_bytes([
        full_msg[off + 8], full_msg[off + 9], full_msg[off + 10], full_msg[off + 11],
    ]);
    let ifi_change = u32::from_ne_bytes([
        full_msg[off + 12], full_msg[off + 13], full_msg[off + 14], full_msg[off + 15],
    ]);
    #[cfg(target_os = "oxide-kernel")]
    {
        if ifindex <= 0 { return nlmsg_ack(req, -19 /* ENODEV */); }
        let id = net::addr::NetIfaceId::from_raw(ifindex as u32);
        match net::sock::stack().ifaces.set_iface_flags(id, ifi_flags, ifi_change) {
            Some(_) => nlmsg_ack(req, 0),
            None    => nlmsg_ack(req, -19 /* ENODEV */),
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = (ifindex, ifi_flags, ifi_change); nlmsg_ack(req, 0) }
}

/// Public NLMSG_ERROR ack (err=0) for the dispatcher's default arm.
/// # C: O(1)
pub fn nlmsg_ack_pub(req: &Nlmsghdr, err: i32) -> Vec<u8> { nlmsg_ack(req, err) }

#[cfg(test)]
#[path = "rtnetlink_tests.rs"]
mod tests;
