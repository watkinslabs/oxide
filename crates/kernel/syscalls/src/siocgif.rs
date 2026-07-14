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

// Module manifest: route_ioctl owns rtentry ABI parsing and canonical FIB mutation.
mod route_ioctl;

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SiocAccess { Get, Mutate }

/// Classify supported network ioctls for socket-fd authorization. # C: O(1)
pub(crate) fn sioc_access(req: u64) -> Option<SiocAccess> {
    match req {
        SIOCGIFNAME | SIOCGIFCONF | SIOCGIFFLAGS | SIOCGIFADDR
        | SIOCGIFBRDADDR | SIOCGIFNETMASK | SIOCGIFMTU | SIOCGIFHWADDR
        | SIOCGIFINDEX | SIOCGIFTXQLEN => Some(SiocAccess::Get),
        SIOCSIFFLAGS | SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFNETMASK
        | SIOCSIFMTU | SIOCSIFHWADDR | SIOCSIFTXQLEN | SIOCADDRT
        | SIOCDELRT => Some(SiocAccess::Mutate),
        _ => None,
    }
}

fn get_ifaddr(id: net::NetIfaceId) -> (u32, u32) {
    get_ifaddr_in(net::netdev::current_net_ns(), id)
}

fn get_ifaddr_in(net_ns: u64, id: net::NetIfaceId) -> (u32, u32) {
    net::iface_addr::primary(net_ns, id)
        .map(|(ip, mask)| (ip.as_u32(), mask))
        .unwrap_or((0, 0))
}

/// F150: hook installed into the net crate so socket_sendto can
/// resolve outbound src IPs without owning the ifaddr table.
/// # C: O(1)
pub fn iface_primary_ip_hook(id: net::NetIfaceId) -> Option<net::Ipv4Addr> {
    let (ip, _mask) = get_ifaddr(id);
    if ip == 0 { None } else { Some(net::Ipv4Addr::from_u32(ip)) }
}

/// Keep virtio-net's ARP responder in sync with whichever control plane
/// changes the primary IPv4 address. # C: O(1)
pub fn ipv4_addr_change_hook(id: net::NetIfaceId, ip: net::Ipv4Addr) {
    let _ = drv_virtio_net::modern::set_softirq_ip_for_iface(id, ip.octets());
}

fn set_ifaddr_in(ns: u64, id: net::NetIfaceId, ip: u32, mask: u32, set_ip: bool, set_mask: bool) {
    if set_ip {
        net::iface_addr::set_primary_addr(ns, id, net::Ipv4Addr::from_u32(ip), 0);
    }
    if set_mask {
        net::iface_addr::set_primary_mask(ns, id, mask);
    }
}

/// Dispatch a SIOC* ioctl. Returns Some(rv) when recognised;
/// None to let the caller fall through. `arg` is a user pointer
/// to a `struct ifreq` (or `struct ifconf` for SIOCGIFCONF).
/// # SAFETY: `arg` validated against USER_VA_END for every read/write.
/// # C: O(N_ifaces) name lookup
pub fn handle_sioc(req: u64, arg: u64) -> Option<i64> {
    handle_sioc_in(net::netdev::current_net_ns(), req, arg)
}

/// Dispatch an interface ioctl against the socket-captured network namespace. # C: O(N_ifaces)
pub fn handle_sioc_in(net_ns: u64, req: u64, arg: u64) -> Option<i64> {
    if arg == 0 || arg >= USER_VA_END { return Some(-(Errno::Efault.as_i32() as i64)); }
    match req {
        SIOCGIFCONF => Some(siocgifconf(net_ns, arg)),
        SIOCGIFNAME => Some(siocgifname(net_ns, arg)),
        SIOCGIFFLAGS => Some(siocgifflags(net_ns, arg)),
        SIOCSIFFLAGS => Some(siocsifflags(net_ns, arg)),
        SIOCGIFADDR => Some(siocgifaddr(net_ns, arg)),
        SIOCSIFADDR => Some(siocsifaddr(net_ns, arg)),
        SIOCGIFBRDADDR => Some(siocgifbrdaddr(net_ns, arg)),
        SIOCSIFBRDADDR => Some(-(Errno::Eopnotsupp.as_i32() as i64)),
        SIOCGIFNETMASK => Some(siocgifnetmask(net_ns, arg)),
        SIOCSIFNETMASK => Some(siocsifnetmask(net_ns, arg)),
        SIOCGIFMTU => Some(siocgifmtu(net_ns, arg)),
        SIOCSIFMTU => Some(-(Errno::Eopnotsupp.as_i32() as i64)),
        SIOCGIFHWADDR => Some(siocgifhwaddr(net_ns, arg)),
        SIOCSIFHWADDR => Some(-(Errno::Eopnotsupp.as_i32() as i64)),
        SIOCGIFINDEX => Some(siocgifindex(net_ns, arg)),
        SIOCGIFTXQLEN | SIOCSIFTXQLEN => Some(-(Errno::Eopnotsupp.as_i32() as i64)),
        SIOCADDRT => Some(route_ioctl::add(net_ns, arg)),
        SIOCDELRT => Some(route_ioctl::delete(net_ns, arg)),
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

fn siocgifflags(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let id = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => id,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let flags = net::sock::stack().ifaces.iface_flags(id).unwrap_or(0) as u16;
    // SAFETY: arg + 16 within user range; ifr_flags at +16.
    unsafe { core::ptr::write_volatile((arg + 16) as *mut u16, flags); }
    0
}

fn siocsifflags(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let id = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => id,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    // SAFETY: handle_sioc_in validated the ifreq base; ifr_flags occupies bytes 16..18.
    let requested = unsafe { core::ptr::read_volatile((arg + 16) as *const u16) } as u32;
    let current = net::sock::stack().ifaces.iface_flags(id).unwrap_or(0);
    if (current ^ requested) & !net::netdev::iff::IFF_UP != 0 {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    match net::sock::stack().ifaces.set_iface_flags(id, requested, net::netdev::iff::IFF_UP) {
        Some(_) => 0,
        None => -(Errno::Enodev.as_i32() as i64),
    }
}

fn siocgifindex(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => {
            // SAFETY: arg + 16 within user range; ifr_ifindex at +16.
            unsafe { core::ptr::write_volatile((arg + 16) as *mut i32, id.raw() as i32); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocgifmtu(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((_, dev)) => {
            // SAFETY: arg + 16 within user range; ifr_mtu at +16.
            unsafe { core::ptr::write_volatile((arg + 16) as *mut i32, dev.mtu() as i32); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocgifhwaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
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

fn siocgifaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => {
            let (ip, _mask) = get_ifaddr_in(net_ns, id);
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            unsafe { write_sockaddr_in(arg, ip); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocsifaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // SAFETY: arg + 24 within user range; sa_family at +16, addr at +20.
    let ip_be = unsafe { core::ptr::read_volatile((arg + 20) as *const u32) };
    let ip_host = u32::from_be(ip_be);
    set_ifaddr_in(net_ns, id, ip_host, 0, true, false);
    0
}

fn siocgifnetmask(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => {
            let (_ip, mask) = get_ifaddr_in(net_ns, id);
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            unsafe { write_sockaddr_in(arg, mask); }
            0
        }
        None => -(Errno::Enoent.as_i32() as i64),
    }
}

fn siocsifnetmask(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifr_addr's sin_addr at +20 within the 32-byte ifreq.
    let mask_be = unsafe { core::ptr::read_volatile((arg + 20) as *const u32) };
    set_ifaddr_in(net_ns, id, 0, u32::from_be(mask_be), false, true);
    0
}

fn siocgifbrdaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(t) => t, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let (ip, mask) = get_ifaddr_in(net_ns, id);
    let brd = ip | !mask;
    // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
    unsafe { write_sockaddr_in(arg, brd); }
    0
}

fn siocgifname(net_ns: u64, arg: u64) -> i64 {
    // SAFETY: arg + 20 within user range; ifr_ifindex at +16.
    let idx = unsafe { core::ptr::read_volatile((arg + 16) as *const i32) };
    if idx <= 0 { return -(Errno::Enoent.as_i32() as i64); }
    let id = net::NetIfaceId::from_raw(idx as u32);
    let dev = match net::sock::stack().ifaces.lookup_in_ns(id, net_ns) {
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
fn siocgifconf(net_ns: u64, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifc_len at +0 and ifc_buf at +8 of the 16-byte ifconf header.
    let (ifc_len, ifc_buf) = unsafe {
        let l = core::ptr::read_volatile(arg as *const i32);
        let b = core::ptr::read_volatile((arg + 8) as *const u64);
        (l, b)
    };
    let devices = net::sock::stack().ifaces.snapshot_devs_in_ns(net_ns);
    let mut addresses = net::iface_addr::snapshot_ns(net_ns);
    addresses.retain(|row| !row.addr.is_unspecified()
        && devices.iter().any(|(id, _)| *id == row.iface));
    let stride: usize = 16 /* name */ + 16 /* sockaddr */;
    if ifc_buf == 0 {
        let required = addresses.len().saturating_mul(stride).min(i32::MAX as usize) as i32;
        // SAFETY: handle_sioc_in validated the ifconf header base; ifc_len is its first word.
        unsafe { core::ptr::write_volatile(arg as *mut i32, required); }
        return 0;
    }
    if ifc_buf >= USER_VA_END || ifc_len < 0 {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = (ifc_len as usize) / stride;
    let mut written = 0usize;
    for row in addresses {
        if written >= cap { break; }
        let Some((_, dev)) = devices.iter().find(|(id, _)| *id == row.iface) else { continue; };
        let slot = ifc_buf + (written * stride) as u64;
        if slot + stride as u64 > USER_VA_END { break; }
        let name_bytes = dev.name().as_bytes();
        // SAFETY: slot range validated < USER_VA_END.
        unsafe {
            for i in 0..IFNAMSIZ {
                let b = if i < name_bytes.len() { name_bytes[i] } else { 0 };
                core::ptr::write_volatile((slot + i as u64) as *mut u8, b);
            }
            write_sockaddr_in(slot, row.addr.as_u32());
        }
        written += 1;
    }
    let bytes_written = (written * stride) as i32;
    // SAFETY: arg validated < USER_VA_END at handle_sioc entry; ifc_len at +0 of the 16-byte ifconf header.
    unsafe { core::ptr::write_volatile(arg as *mut i32, bytes_written); }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_sioc_getters_and_mutators() {
        const UNKNOWN_SIOC: u64 = 0x89ff;
        for req in [
            SIOCGIFNAME, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR,
            SIOCGIFBRDADDR, SIOCGIFNETMASK, SIOCGIFMTU, SIOCGIFHWADDR,
            SIOCGIFINDEX, SIOCGIFTXQLEN,
        ] {
            assert_eq!(sioc_access(req), Some(SiocAccess::Get));
        }
        for req in [
            SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFNETMASK,
            SIOCSIFMTU, SIOCSIFHWADDR, SIOCSIFTXQLEN, SIOCADDRT, SIOCDELRT,
        ] {
            assert_eq!(sioc_access(req), Some(SiocAccess::Mutate));
        }
        assert_eq!(sioc_access(UNKNOWN_SIOC), None);
    }
}
