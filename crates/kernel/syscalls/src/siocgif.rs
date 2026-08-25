// B48: SIOC* network-interface ioctls. dhcpcd's bring-up flow
// drives this surface to probe + configure eth0 before sending
// the DHCPDISCOVER. Linux SIOC* interface ioctl numbering.
//
// ifreq layout:
//   char ifr_name[16];
//   union {
//       struct sockaddr  ifr_addr;     // sa_family + 14 bytes
//       short            ifr_flags;
//       int              ifr_ifindex;
//       int              ifr_mtu;
//       char             ifr_hwaddr[6 in sa_data];
//   };

// Module manifest: route_ioctl owns rtentry ABI parsing; arp_ioctl owns arpreq
// ABI decoding and canonical neighbour mutation; ipv4_addr_ioctl owns legacy
// IPv4 destination/delete ABI parsing; legacy_device_ioctl owns terminal
// legacy device ABI results; WAN owns `ndo_siocwandev`; multicast and bridge
// (BRCTL/SIOCDEVPRIVATE) own their own ABI shims.
#[cfg(any(not(test), target_os = "oxide-kernel"))]
#[path = "siocgif/route_ioctl.rs"] mod route_ioctl;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod route_ioctl {
    pub(super) fn add(_net_ns: u64, _arg: u64) -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
    pub(super) fn delete(_net_ns: u64, _arg: u64) -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
}
#[path = "siocgif/arp_ioctl.rs"] mod arp_ioctl;
#[path = "siocgif/bridge.rs"] mod bridge;
#[path = "siocgif/device_map_ioctl.rs"] mod device_map_ioctl;
#[path = "siocgif/ethtool.rs"] mod ethtool;
#[path = "siocgif/hardware_broadcast_ioctl.rs"] mod hardware_broadcast_ioctl;
#[path = "siocgif/ipv4_addr_ioctl.rs"] mod ipv4_addr_ioctl;
#[path = "siocgif/legacy_device_ioctl.rs"] mod legacy_device_ioctl;
#[path = "siocgif/multicast_ioctl.rs"] mod multicast_ioctl;
#[path = "siocgif/wan_ioctl.rs"] mod wan_ioctl;

use crate::siocgif_decide as decide;
pub(crate) use decide::SiocAccess;
use decide::{user_range, IFCONF_SIZE, IFNAMSIZ, IFREQ_SIZE,
    SIOCADDRT, SIOCDELRT, SIOCDIFADDR, SIOCDRARP, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF,
    SIOCGIFCOUNT, SIOCGIFDSTADDR, SIOCGIFENCAP, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX,
    SIOCGIFMAP, SIOCGIFMEM, SIOCGIFMETRIC, SIOCGIFMTU, SIOCGIFNAME, SIOCGIFNETMASK,
    SIOCGIFPFLAGS, SIOCGIFSLAVE, SIOCGIFTXQLEN, SIOCGRARP, SIOCSIFADDR, SIOCSIFBRDADDR,
    SIOCSIFDSTADDR, SIOCSIFENCAP, SIOCSIFFLAGS, SIOCSIFHWADDR, SIOCSIFHWBROADCAST, SIOCSIFLINK,
    SIOCSIFMAP, SIOCSIFMEM, SIOCSIFMETRIC, SIOCSIFMTU, SIOCSIFNAME, SIOCSIFNETMASK,
    SIOCSIFPFLAGS, SIOCSIFSLAVE, SIOCSIFTXQLEN, SIOCSRARP, SIOCWANDEV};
use syscall::errno::Errno;

#[path = "siocgif/basic.rs"]
mod basic;
#[path = "siocgif/address.rs"]
mod address;
pub(crate) use basic::*;
pub(crate) use address::*;


// Linux x86_64/aarch64 `struct ifreq`: 16-byte name plus a 24-byte union.
// The union is 24 bytes because `ifr_data` is a native pointer; fixed-field
// members still begin at offset 16.
const AF_INET: u16 = 2;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;


/// Classify supported network ioctls for socket-fd authorization.
///
/// The bridge shim first: its commands are told apart by the vector the caller
/// passed in user memory, which no ungated table can read. Everything else is
/// decided by the command number alone, in `decide::classify`.
/// # C: O(1)
pub(crate) fn sioc_access(req: u64, arg: u64) -> Result<Option<SiocAccess>, i64> {
    if let Some(access) = bridge::access(req, arg)? { return Ok(Some(access)); }
    Ok(decide::classify(req))
}

fn get_ifaddr(id: net::NetIfaceId) -> (u32, u32) {
    get_ifaddr_in(net::netdev::current_net_ns(), id)
}

fn find_ifaddr_in(net_ns: u64, id: net::NetIfaceId) -> Option<(u32, u32)> {
    net::iface_addr::primary(net_ns, id)
        .map(|(ip, mask)| (ip.as_u32(), mask))
}

fn get_ifaddr_in(net_ns: u64, id: net::NetIfaceId) -> (u32, u32) {
    find_ifaddr_in(net_ns, id).unwrap_or((0, 0))
}

fn lookup_ipv4_getter(net_ns: u64, name: &str)
    -> Result<(net::NetIfaceId, u32, u32), Errno>
{
    let (id, _) = net::sock::stack().ifaces.lookup_name_in_ns(name, net_ns)
        .ok_or(Errno::Enodev)?;
    let (ip, mask) = find_ifaddr_in(net_ns, id).ok_or(Errno::Eaddrnotavail)?;
    Ok((id, ip, mask))
}

/// F150: hook installed into the net crate so socket_sendto can
/// resolve outbound src IPs without owning the ifaddr table.
/// # C: O(1)
pub fn iface_primary_ip_hook(id: net::NetIfaceId) -> Option<net::Ipv4Addr> {
    let (ip, _mask) = get_ifaddr(id);
    if ip == 0 { None } else { Some(net::Ipv4Addr::from_u32(ip)) }
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
    if let Some(size) = bridge::arg_size(req) {
        if !user_range(arg, size) { return Some(-(Errno::Efault.as_i32() as i64)); }
        return bridge::handle(net_ns, req, arg);
    }
    let size = if req == SIOCGIFCONF { IFCONF_SIZE } else if matches!(req,
        net::arp::uapi::SIOCGARP | net::arp::uapi::SIOCSARP | net::arp::uapi::SIOCDARP)
    { net::arp::uapi::ARPREQ_SIZE } else { IFREQ_SIZE };
    if !user_range(arg, size) { return Some(-(Errno::Efault.as_i32() as i64)); }
    match req {
        SIOCGIFCONF => Some(siocgifconf(net_ns, arg)),
        SIOCGIFNAME => Some(siocgifname(net_ns, arg)),
        SIOCSIFLINK | SIOCGIFMEM | SIOCSIFMEM | SIOCGIFENCAP | SIOCSIFENCAP
        | SIOCDRARP | SIOCGRARP | SIOCSRARP
        | net::uapi::SIOCRTMSG
        | SIOCGIFSLAVE | SIOCSIFSLAVE => Some(legacy_device_ioctl::handle(net_ns, req, arg)),
        SIOCSIFNAME => Some(siocsifname(net_ns, arg)),
        SIOCGIFFLAGS => Some(siocgifflags(net_ns, arg)),
        ethtool::SIOCETHTOOL => Some(ethtool::handle(net_ns, arg)),
        SIOCSIFFLAGS => Some(siocsifflags(net_ns, arg)),
        SIOCGIFADDR => Some(siocgifaddr(net_ns, arg)),
        SIOCSIFADDR => Some(siocsifaddr(net_ns, arg)),
        SIOCGIFDSTADDR => Some(ipv4_addr_ioctl::get_destination(net_ns, arg)),
        SIOCSIFDSTADDR => Some(ipv4_addr_ioctl::set_destination(net_ns, arg)),
        SIOCGIFBRDADDR => Some(siocgifbrdaddr(net_ns, arg)),
        SIOCSIFBRDADDR => Some(siocsifbrdaddr(net_ns, arg)),
        SIOCGIFNETMASK => Some(siocgifnetmask(net_ns, arg)),
        SIOCGIFMETRIC => Some(siocgifmetric(net_ns, arg)),
        SIOCSIFMETRIC => Some(siocsifmetric(net_ns, arg)),
        SIOCSIFNETMASK => Some(siocsifnetmask(net_ns, arg)),
        SIOCGIFMTU => Some(siocgifmtu(net_ns, arg)),
        SIOCSIFMTU => Some(siocsifmtu(net_ns, arg)),
        SIOCGIFHWADDR => Some(siocgifhwaddr(net_ns, arg)),
        SIOCGIFMAP => Some(siocgifmap(net_ns, arg)),
        SIOCSIFMAP => Some(device_map_ioctl::set(net_ns, arg)),
        SIOCSIFHWBROADCAST => Some(hardware_broadcast_ioctl::set(net_ns, arg)),
        SIOCWANDEV => Some(wan_ioctl::handle(net_ns, arg)),
        SIOCSIFHWADDR => Some(siocsifhwaddr(net_ns, arg)),
        SIOCGIFINDEX => Some(siocgifindex(net_ns, arg)),
        SIOCGIFTXQLEN => Some(siocgiftxqlen(net_ns, arg)),
        SIOCSIFTXQLEN => Some(siocsiftxqlen(net_ns, arg)),
        SIOCGIFPFLAGS => Some(siocgifpflags(net_ns, arg)),
        SIOCGIFCOUNT => Some(siocgifcount(net_ns, arg)),
        SIOCSIFPFLAGS => Some(siocsifpflags(net_ns, arg)),
        SIOCADDRT => Some(route_ioctl::add(net_ns, arg)),
        SIOCDELRT => Some(route_ioctl::delete(net_ns, arg)),
        SIOCDIFADDR => Some(ipv4_addr_ioctl::delete(net_ns, arg)),
        net::arp::uapi::SIOCGARP | net::arp::uapi::SIOCSARP | net::arp::uapi::SIOCDARP => {
            Some(arp_ioctl::handle(net_ns, req, arg))
        }
        net::uapi::SIOCADDMULTI | net::uapi::SIOCDELMULTI => {
            Some(multicast_ioctl::handle(net_ns, req, arg))
        }
        _ => None,
    }
}


fn read_ifname(arg: u64) -> Option<alloc::string::String> {
    let req = read_ifreq(arg)?;
    copied_ifname(&req).map(alloc::string::ToString::to_string)
}

fn read_ifreq(arg: u64) -> Option<[u8; IFREQ_SIZE]> {
    if !user_range(arg, IFREQ_SIZE) { return None; }
    let mut req = [0u8; IFREQ_SIZE];
    uaccess::copy_from_user(&mut req, arg).ok().map(|()| req)
}

fn copied_ifname(req: &[u8; IFREQ_SIZE]) -> Option<&str> {
    let end = req[..IFNAMSIZ].iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    core::str::from_utf8(&req[..end]).ok()
}

fn copied_sockaddr_family(req: &[u8; IFREQ_SIZE]) -> u16 {
    u16::from_ne_bytes([req[16], req[17]])
}

fn lease_matches_rtnl(stack: &net::NetStack, rtnl: &net::RtnlGuard<'_>, net_ns: u64,
                      name: &str, lease: &net::netdev::IngressLease) -> bool {
    matches!(stack.ifaces.control_ready_name_generation_in_ns(rtnl, name, net_ns),
        Some((id, _, generation)) if id == lease.iface() && generation == lease.generation()
            && lease.net_ns() == net_ns)
}

fn live_iface_flags(id: net::NetIfaceId) -> Result<u16, Errno> {
    net::sock::stack().ifaces.iface_flags(id).map(|flags| flags as u16).ok_or(Errno::Enodev)
}

/// Write a sockaddr_in (16 bytes) at offset 16 of the ifreq.
/// `ip` is host-byte-order; we write big-endian per the wire ABI.
/// # SAFETY: caller asserts arg+IFREQ_SIZE ≤ USER_VA_END.
fn write_sockaddr_in(arg: u64, ip: u32) -> bool {
    let bytes = sockaddr_in_bytes(ip);
    write_ifreq_bytes(arg, 16, &bytes)
}

fn write_ifreq_bytes(arg: u64, offset: usize, bytes: &[u8]) -> bool {
    let Some(dst) = arg.checked_add(offset as u64) else { return false; };
    uaccess::copy_to_user(dst, bytes).is_ok()
}

fn sockaddr_in_bytes(ip: u32) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..2].copy_from_slice(&AF_INET.to_ne_bytes());
    bytes[4..8].copy_from_slice(&ip.to_be_bytes());
    bytes
}

#[cfg(test)]
#[path = "siocgif/tests.rs"]
mod tests;
