// B48: SIOC* network-interface ioctls. dhcpcd's bring-up flow
// drives this surface to probe + configure eth0 before sending
// the DHCPDISCOVER. Linux SIOC* numbers per linux/sockios.h.
//
// ifreq layout (linux/if.h):
//   char ifr_name[16];
//   union {
//       struct sockaddr  ifr_addr;     // sa_family + 14 bytes
//       short            ifr_flags;
//       int              ifr_ifindex;
//       int              ifr_mtu;
//       char             ifr_hwaddr[6 in sa_data];
//   };

#![cfg(target_os = "oxide-kernel")]

use hal::USER_VA_END;
use syscall::errno::Errno;

const SIOCGIFNAME:     u64 = 0x8910;
const SIOCGIFCONF:     u64 = 0x8912;
const SIOCGIFFLAGS:    u64 = 0x8913;
const SIOCSIFFLAGS:    u64 = 0x8914;
const SIOCGIFADDR:     u64 = 0x8915;
const SIOCSIFADDR:     u64 = 0x8916;
const SIOCGIFBRDADDR:  u64 = 0x8919;
const SIOCSIFBRDADDR:  u64 = 0x891a;
const SIOCGIFNETMASK:  u64 = 0x891b;
const SIOCSIFNETMASK:  u64 = 0x891c;
const SIOCGIFMTU:      u64 = 0x8921;
const SIOCSIFMTU:      u64 = 0x8922;
const SIOCGIFHWADDR:   u64 = 0x8927;
const SIOCSIFHWADDR:   u64 = 0x8924;
const SIOCGIFINDEX:    u64 = 0x8933;
const SIOCGIFTXQLEN:   u64 = 0x8942;
const SIOCSIFTXQLEN:   u64 = 0x8943;
const SIOCADDRT:       u64 = 0x890B;
const SIOCDELRT:       u64 = 0x890C;

const IFNAMSIZ: usize = 16;

/// Per-iface IPv4 addr + netmask, indexed by NetIfaceId.raw().
/// 32 slots covers any plausible v1 build. Each slot is two atomic
/// u32s (addr + mask) so we don't need a separate spinlock for the
/// dhcpcd post-fork read/write race.
use core::sync::atomic::{AtomicU32, Ordering};
struct IfAddr { addr: AtomicU32, mask: AtomicU32 }
impl IfAddr {
    const fn new() -> Self { Self { addr: AtomicU32::new(0), mask: AtomicU32::new(0) } }
}
const IFADDR_SLOTS: usize = 32;
#[allow(clippy::declare_interior_mutable_const)]
const IFADDR_INIT: IfAddr = IfAddr::new();
static IFADDR: [IfAddr; IFADDR_SLOTS] = [IFADDR_INIT; IFADDR_SLOTS];

fn get_ifaddr(id: net::NetIfaceId) -> (u32, u32) {
    let idx = id.raw() as usize;
    if idx >= IFADDR_SLOTS { return (0, 0); }
    (IFADDR[idx].addr.load(Ordering::Acquire), IFADDR[idx].mask.load(Ordering::Acquire))
}

/// F150: hook installed into the net crate so socket_sendto can
/// resolve outbound src IPs without owning the ifaddr table.
/// # C: O(1)
pub fn iface_primary_ip_hook(id: net::NetIfaceId) -> Option<net::Ipv4Addr> {
    let (ip, _mask) = get_ifaddr(id);
    if ip == 0 { None } else { Some(net::Ipv4Addr::from_u32(ip)) }
}

fn set_ifaddr(id: net::NetIfaceId, ip: u32, mask: u32, set_ip: bool, set_mask: bool) {
    let idx = id.raw() as usize;
    if idx >= IFADDR_SLOTS { return; }
    if set_ip   { IFADDR[idx].addr.store(ip, Ordering::Release); }
    if set_mask { IFADDR[idx].mask.store(mask, Ordering::Release); }
}

/// Dispatch a SIOC* ioctl. Returns Some(rv) when recognised;
/// None to let the caller fall through. `arg` is a user pointer
/// to a `struct ifreq` (or `struct ifconf` for SIOCGIFCONF).
/// # SAFETY: `arg` validated against USER_VA_END for every read/write.
/// # C: O(N_ifaces) name lookup
pub fn handle_sioc(req: u64, arg: u64) -> Option<i64> {
    if arg == 0 || arg >= USER_VA_END { return Some(-(Errno::Efault.as_i32() as i64)); }
    match req {
        SIOCGIFCONF => Some(siocgifconf(arg)),
        SIOCGIFNAME => Some(siocgifname(arg)),
        SIOCGIFFLAGS => Some(siocgifflags(arg)),
        SIOCSIFFLAGS => Some(0), // accept-and-ignore (we keep ifaces "up")
        SIOCGIFADDR => Some(siocgifaddr(arg)),
        SIOCSIFADDR => Some(siocsifaddr(arg)),
        SIOCGIFBRDADDR => Some(siocgifbrdaddr(arg)),
        SIOCSIFBRDADDR => Some(0),
        SIOCGIFNETMASK => Some(siocgifnetmask(arg)),
        SIOCSIFNETMASK => Some(siocsifnetmask(arg)),
        SIOCGIFMTU => Some(siocgifmtu(arg)),
        SIOCSIFMTU => Some(0),
        SIOCGIFHWADDR => Some(siocgifhwaddr(arg)),
        SIOCSIFHWADDR => Some(0),
        SIOCGIFINDEX => Some(siocgifindex(arg)),
        SIOCGIFTXQLEN | SIOCSIFTXQLEN => Some(0),
        SIOCADDRT => Some(siocaddrt(arg)),
        SIOCDELRT => Some(siocdelrt(arg)),
        _ => None,
    }
}

fn read_ifname(arg: u64) -> Option<alloc::string::String> {
    let mut buf = [0u8; IFNAMSIZ];
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; 16-byte bounded read.
    unsafe {
        for i in 0..IFNAMSIZ {
            buf[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
        }
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    core::str::from_utf8(&buf[..end]).ok().map(|s| s.into())
}

/// Write a sockaddr_in (16 bytes) at offset 16 of the ifreq.
/// `ip` is host-byte-order; we write big-endian per the wire ABI.
/// # SAFETY: caller asserts arg+32 ≤ USER_VA_END.
unsafe fn write_sockaddr_in(arg: u64, ip: u32) {
    // SAFETY: caller asserted arg+32 ≤ USER_VA_END; the ifr_addr union at offset 16 covers a sockaddr_in (16 bytes); CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile((arg + 16) as *mut u16, 2);  // AF_INET
        core::ptr::write_volatile((arg + 18) as *mut u16, 0);  // sin_port
        core::ptr::write_volatile((arg + 20) as *mut u32, ip.to_be());
        for i in 0..8 {
            core::ptr::write_volatile((arg + 24 + i) as *mut u8, 0);
        }
    }
}

fn siocgifflags(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let exists = net::sock::stack().ifaces.lookup_name(&name).is_some();
    if !exists { return -(Errno::Enoent.as_i32() as i64); }
    let mut flags: u16 = 1 /* UP */ | 2 /* BROADCAST */ | 64 /* RUNNING */ | 0x1000 /* MULTICAST */;
    if name == "lo" { flags = (flags & !2) | 8 /* LOOPBACK */; }
    // SAFETY: arg + 16 within user range; ifr_flags at +16.
    unsafe { core::ptr::write_volatile((arg + 16) as *mut u16, flags); }
    0
}

fn siocgifindex(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name(&name) {
        Some((id, _)) => {
            // SAFETY: arg + 16 within user range; ifr_ifindex at +16.
            unsafe { core::ptr::write_volatile((arg + 16) as *mut i32, id.raw() as i32); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocgifmtu(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name(&name) {
        Some((_, dev)) => {
            // SAFETY: arg + 16 within user range; ifr_mtu at +16.
            unsafe { core::ptr::write_volatile((arg + 16) as *mut i32, dev.mtu() as i32); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocgifhwaddr(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name(&name) {
        Some((_, dev)) => {
            let mac = dev.mac();
            // SAFETY: arg validated < USER_VA_END at handle_sioc entry; the 32-byte ifreq's ifr_hwaddr/sa_data slot covers +16..+24.
            unsafe {
                core::ptr::write_volatile((arg + 16) as *mut u16, 1);  // ARPHRD_ETHER
                for i in 0..6 {
                    core::ptr::write_volatile((arg + 18 + i) as *mut u8, mac.0[i as usize]);
                }
            }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocgifaddr(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name(&name) {
        Some((id, _)) => {
            let (ip, _mask) = get_ifaddr(id);
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            unsafe { write_sockaddr_in(arg, ip); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocsifaddr(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name(&name) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // SAFETY: arg + 24 within user range; sa_family at +16, addr at +20.
    let ip_be = unsafe { core::ptr::read_volatile((arg + 20) as *const u32) };
    let ip_host = u32::from_be(ip_be);
    set_ifaddr(id, ip_host, 0, true, false);
    // F138: if this iface is the one the virtio-net rx softirq is
    // bound to, update its stashed IP so the ARP responder starts
    // answering "who-has <new-ip>" with our MAC.
    if drv_virtio_net::modern::softirq_iface_id() == id.raw() {
        drv_virtio_net::modern::set_softirq_ip(ip_host.to_be_bytes());
    }
    0
}

fn siocgifnetmask(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name(&name) {
        Some((id, _)) => {
            let (_ip, mask) = get_ifaddr(id);
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            unsafe { write_sockaddr_in(arg, mask); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocsifnetmask(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name(&name) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifr_addr's sin_addr at +20 within the 32-byte ifreq.
    let mask_be = unsafe { core::ptr::read_volatile((arg + 20) as *const u32) };
    set_ifaddr(id, 0, u32::from_be(mask_be), false, true);
    0
}

fn siocgifbrdaddr(arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name(&name) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let (ip, mask) = get_ifaddr(id);
    let brd = ip | !mask;
    // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
    unsafe { write_sockaddr_in(arg, brd); }
    0
}

fn siocgifname(arg: u64) -> i64 {
    // SAFETY: arg + 20 within user range; ifr_ifindex at +16.
    let idx = unsafe { core::ptr::read_volatile((arg + 16) as *const i32) };
    if idx <= 0 { return -(Errno::Enoent.as_i32() as i64); }
    let id = net::NetIfaceId::from_raw(idx as u32);
    let dev = match net::sock::stack().ifaces.lookup(id) {
        Some(d) => d, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let bytes = dev.name().as_bytes();
    // SAFETY: arg validated; 16-byte ifr_name at the base.
    unsafe {
        for i in 0..IFNAMSIZ {
            let b = if i < bytes.len() { bytes[i] } else { 0 };
            core::ptr::write_volatile((arg + i as u64) as *mut u8, b);
        }
    }
    0
}

/// SIOCGIFCONF — return the list of interfaces. ifconf layout:
///   int     ifc_len     // bytes capacity in, bytes filled out
///   char*   ifc_buf     // pointer to ifreq[]
/// We fill ifc_req[] with one struct ifreq per iface and update
/// ifc_len.
fn siocgifconf(arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifc_len at +0 and ifc_buf at +8 of the 16-byte ifconf header.
    let (ifc_len, ifc_buf) = unsafe {
        let l = core::ptr::read_volatile(arg as *const i32);
        let b = core::ptr::read_volatile((arg + 8) as *const u64);
        (l, b)
    };
    if ifc_buf == 0 || ifc_buf >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let stride: usize = 16 /* name */ + 16 /* sockaddr */;
    let cap = (ifc_len as usize) / stride;
    let mut written = 0usize;
    // Snapshot known interface names. Probe ids 1..=8 — covers
    // every iface our v1 ever registers (lo + virtio-net eth0 +
    // a couple of spares).
    let mut entries: alloc::vec::Vec<(net::NetIfaceId, alloc::string::String)> = alloc::vec::Vec::new();
    for raw in 1u32..=8 {
        let id = net::NetIfaceId::from_raw(raw);
        if let Some(dev) = net::sock::stack().ifaces.lookup(id) {
            entries.push((id, dev.name().into()));
        }
    }
    for (id, name) in entries {
        if written >= cap { break; }
        let slot = ifc_buf + (written * stride) as u64;
        if slot + stride as u64 >= USER_VA_END { break; }
        let name_bytes = name.as_bytes();
        // SAFETY: slot range validated < USER_VA_END.
        unsafe {
            for i in 0..IFNAMSIZ {
                let b = if i < name_bytes.len() { name_bytes[i] } else { 0 };
                core::ptr::write_volatile((slot + i as u64) as *mut u8, b);
            }
            let (ip, _mask) = get_ifaddr(id);
            write_sockaddr_in(slot, ip);
        }
        written += 1;
    }
    let bytes_written = (written * stride) as i32;
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifc_len at +0 of the 16-byte ifconf header.
    unsafe { core::ptr::write_volatile(arg as *mut i32, bytes_written); }
    0
}

/// F148: SIOCADDRT — install a route into the kernel net stack's
/// route table. `struct rtentry` layout per linux/route.h:
///   u64 rt_pad1; struct sockaddr rt_dst (16); struct sockaddr
///   rt_gateway (16); struct sockaddr rt_genmask (16); u16 rt_flags;
///   u16 rt_pad2; u64 rt_pad3, rt_pad4; u16 rt_metric; ...
/// sockaddr_in layout: u16 family + u16 port + u32 addr (big-endian)
/// + 8 bytes zero pad. addr lives at +4 of each sockaddr_in.
/// The iface is picked by gateway-on-subnet match across the
/// per-iface address/netmask table populated by SIOCSIFADDR.
fn siocaddrt(arg: u64) -> i64 {
    if arg + 56 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: arg + 56 bounds-checked above; rtentry's three sockaddrs
    // start at offsets 8, 24, 40; each sockaddr_in's sin_addr is +4.
    let (dst_be, gw_be, mask_be) = unsafe {
        (
            core::ptr::read_volatile((arg + 8  + 4) as *const u32),
            core::ptr::read_volatile((arg + 24 + 4) as *const u32),
            core::ptr::read_volatile((arg + 40 + 4) as *const u32),
        )
    };
    let dst  = net::Ipv4Addr::from_u32(u32::from_be(dst_be));
    let gw   = net::Ipv4Addr::from_u32(u32::from_be(gw_be));
    let mask = u32::from_be(mask_be);
    let prefix_len = if mask == 0 { 0 } else { 32 - mask.trailing_zeros() as u8 };
    // Pick the iface whose connected subnet contains the gateway.
    let mut iface_id: Option<net::NetIfaceId> = None;
    for raw in 0..32u32 {
        let id = net::NetIfaceId::from_raw(raw);
        if net::sock::stack().ifaces.lookup(id).is_none() { continue; }
        let (ip_host, m_host) = get_ifaddr(id);
        if m_host == 0 { continue; }
        let m_be = m_host.to_be();
        if (gw_be & m_be) == (ip_host.to_be() & m_be) {
            iface_id = Some(id);
            break;
        }
    }
    let iface_id = match iface_id { Some(i) => i, None => return -(Errno::Enetunreach.as_i32() as i64) };
    net::sock::stack().routes.add(net::route::RouteEntry {
        dst, prefix_len,
        iface: iface_id,
        gateway: if gw.as_u32() == 0 { None } else { Some(gw) },
        src_hint: None,
    });
    0
}

/// F148: SIOCDELRT — drop matching routes from the kernel table.
fn siocdelrt(arg: u64) -> i64 {
    if arg + 56 > USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: arg + 56 bounds-checked above; sockaddr_in offsets per linux/route.h rtentry layout.
    let (dst_be, gw_be) = unsafe {
        (
            core::ptr::read_volatile((arg + 8  + 4) as *const u32),
            core::ptr::read_volatile((arg + 24 + 4) as *const u32),
        )
    };
    let dst = net::Ipv4Addr::from_u32(u32::from_be(dst_be));
    let gw  = net::Ipv4Addr::from_u32(u32::from_be(gw_be));
    net::sock::stack().routes.retain(|e| {
        let gw_match = match (e.gateway, gw.as_u32()) {
            (Some(g), x) if x != 0 => g.as_u32() != x,
            _ => true,
        };
        e.dst.as_u32() != dst.as_u32() || gw_match
    });
    0
}
