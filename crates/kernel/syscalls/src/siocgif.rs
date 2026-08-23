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

use alloc::vec::Vec;
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

fn siocgifflags(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let id = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => id,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let flags = match live_iface_flags(id) {
        Ok(flags) => flags,
        Err(errno) => return -(errno.as_i32() as i64),
    };
    if write_ifreq_bytes(arg, 16, &flags.to_ne_bytes()[..2]) { 0 }
    else { -(Errno::Efault.as_i32() as i64) }
}

fn siocsifflags(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let requested = u16::from_ne_bytes([req[16], req[17]]) as u32;
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease,
        None => return siocsifflags_enodev(b"acquire"),
    };
    let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
        return siocsifflags_enodev(b"lookup");
    };
    let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return siocsifflags_enodev(b"generation");
        }
        let id = lease.iface();
        // Compare ADMINISTRATIVE bits only. `iface_flags` reports what the
        // device presents — carrier included, as `dev_get_flags` does — and a
        // caller's `ifr_flags` never carries the volatile bits (it cannot: the
        // field is 16 bits and `IFF_LOWER_UP` does not fit). Comparing the
        // reported word against a request therefore always differs in bits the
        // caller could not have set, and the reference does not compare them
        // either: `dev_change_flags` ignores the volatile set entirely.
        let current = stack.ifaces.iface_flags(id).unwrap_or(0);
        if !net::netdev::iff::siocsifflags_supported(current, requested) {
            return -(Errno::Eopnotsupp.as_i32() as i64);
        }
        let Some(after) = stack.ifaces.set_iface_flags_in_ns(
            &rtnl, id, net_ns, requested, net::netdev::iff::IFF_UP) else {
            return siocsifflags_enodev(b"mutate");
        };
        if current & net::netdev::iff::IFF_UP != 0
            && after & net::netdev::iff::IFF_UP == 0 {
            stack.flowtable_device_down_in(net_ns, id);
        }
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()), id,
            properties, net::control_event::EventKind::New) else {
            return siocsifflags_enodev(b"event");
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}

fn siocsifflags_enodev(stage: &'static [u8]) -> i64 {
    klog::write_raw(b"[SIOCSIFFLAGS ENODEV] stage=");
    klog::write_raw(stage);
    klog::write_raw(b"\n");
    -(Errno::Enodev.as_i32() as i64)
}

fn siocgifindex(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((id, _)) => {
            let Some(ifindex) = net::sock::stack().ifaces.ifindex_in_ns(id, net_ns) else {
                return -(Errno::Enodev.as_i32() as i64);
            };
            if write_ifreq_bytes(arg, 16, &(ifindex as i32).to_ne_bytes()) { 0 }
            else { -(Errno::Efault.as_i32() as i64) }
        }
        None => -(Errno::Enodev.as_i32() as i64),
    }
}

/// Run a fixed-size `ifreq` operation after the exception-table copy-in.  The
/// decision and device lookup live in the slice form below so hosted tests can
/// exercise the exact production owner without inventing a user address.
fn with_ifreq<F>(net_ns: u64, arg: u64, f: F) -> i64
where F: FnOnce(u64, &mut [u8; IFREQ_SIZE]) -> i64 {
    let Some(mut req) = read_ifreq(arg) else { return -(Errno::Efault.as_i32() as i64); };
    let rv = f(net_ns, &mut req);
    if rv == 0 && uaccess::copy_to_user(arg, &req).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    rv
}

fn siocgifmtu(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((_, dev)) => {
            if write_ifreq_bytes(arg, 16, &(dev.mtu() as i32).to_ne_bytes()) { 0 }
            else { -(Errno::Efault.as_i32() as i64) }
        }
        None => -(Errno::Enodev.as_i32() as i64),
    }
}

fn siocgifmetric(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifmetric_inner)
}

fn siocgifmetric_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    if net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    req[16..20].copy_from_slice(&0i32.to_ne_bytes());
    0
}

fn siocsifmetric(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocsifmetric_inner)
}

fn siocsifmetric_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    if net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    -(Errno::Eopnotsupp.as_i32() as i64)
}

fn siocgifcount(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifcount_inner)
}

fn siocgifcount_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let count = net::sock::stack().ifaces.snapshot_devs_in_ns(net_ns).len() as i32;
    req[16..20].copy_from_slice(&count.to_ne_bytes());
    0
}

fn siocsifmtu(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let mtu = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
    if !(68..=65_535).contains(&mtu) { return -(Errno::Einval.as_i32() as i64); }
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        match dev.set_mtu(mtu as u32) {
            Ok(()) => {}
            Err(net::NetError::Einval) => return -(Errno::Einval.as_i32() as i64),
            Err(net::NetError::Enodev) => return -(Errno::Enodev.as_i32() as i64),
            Err(net::NetError::Eopnotsupp) => return -(Errno::Eopnotsupp.as_i32() as i64),
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()),
            lease.iface(), properties, net::control_event::EventKind::New) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}

fn siocgifhwaddr(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifhwaddr_inner)
}

fn siocgifhwaddr_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((_, dev)) => {
            let mac = dev.mac();
            let hardware_type = if dev.hardware_type() == ARPHRD_LOOPBACK { ARPHRD_LOOPBACK } else { ARPHRD_ETHER };
            let mut data = [0u8; 8];
            data[..2].copy_from_slice(&hardware_type.to_ne_bytes());
            data[2..].copy_from_slice(&mac.0);
            req[16..24].copy_from_slice(&data);
            0
        }
        None => -(Errno::Enodev.as_i32() as i64),
    }
}

fn siocgifmap(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifmap_inner)
}

fn siocgifmap_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let Some((_, dev)) = net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    let map = dev.ifmap();
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&map.mem_start.to_ne_bytes());
    bytes[8..16].copy_from_slice(&map.mem_end.to_ne_bytes());
    bytes[16..18].copy_from_slice(&map.base_addr.to_ne_bytes());
    bytes[18] = map.irq;
    bytes[19] = map.dma;
    bytes[20] = map.port;
    req[16..40].copy_from_slice(&bytes);
    0
}

fn siocsifhwaddr(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let hardware_type = u16::from_ne_bytes([req[16], req[17]]);
    if hardware_type != ARPHRD_ETHER { return -(Errno::Eopnotsupp.as_i32() as i64); }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&req[18..24]);
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        match dev.set_mac(net::MacAddr(mac)) {
            Ok(()) => {}
            Err(net::NetError::Einval) => return -(Errno::Einval.as_i32() as i64),
            Err(net::NetError::Enodev) => return -(Errno::Enodev.as_i32() as i64),
            Err(net::NetError::Eopnotsupp) => return -(Errno::Eopnotsupp.as_i32() as i64),
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()),
            lease.iface(), properties, net::control_event::EventKind::New) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}

fn siocgiftxqlen(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let (_, dev) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(row) => row, None => return -(Errno::Enodev.as_i32() as i64),
    };
    if write_ifreq_bytes(arg, 16, &(dev.tx_queue_len() as i32).to_ne_bytes()) { 0 }
    else { -(Errno::Efault.as_i32() as i64) }
}

fn siocgifpflags(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifpflags_inner)
}

fn siocgifpflags_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let (_, dev) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(row) => row, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let Some(flags) = dev.private_flags() else {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    };
    req[16..20].copy_from_slice(&flags.to_ne_bytes());
    0
}

fn siocsifpflags(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let flags = u16::from_ne_bytes([req[16], req[17]]);
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        match dev.set_private_flags(flags) {
            Ok(()) => {}
            Err(net::NetError::Einval) => return -(Errno::Einval.as_i32() as i64),
            Err(net::NetError::Enodev) => return -(Errno::Enodev.as_i32() as i64),
            Err(net::NetError::Eopnotsupp) => return -(Errno::Eopnotsupp.as_i32() as i64),
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()),
            lease.iface(), properties, net::control_event::EventKind::New) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}

fn siocsiftxqlen(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let len = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
    if len < 0 { return -(Errno::Einval.as_i32() as i64); }
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        match dev.set_tx_queue_len(len as u32) {
            Ok(()) => {}
            Err(net::NetError::Enodev) => return -(Errno::Enodev.as_i32() as i64),
            Err(net::NetError::Eopnotsupp) => return -(Errno::Eopnotsupp.as_i32() as i64),
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()),
            lease.iface(), properties, net::control_event::EventKind::New) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}

fn siocgifaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match lookup_ipv4_getter(net_ns, &name) {
        Ok((_id, ip, _mask)) => {
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            if write_sockaddr_in(arg, ip) { 0 } else { -(Errno::Efault.as_i32() as i64) }
        }
        Err(errno) => -(errno.as_i32() as i64),
    }
}

fn siocsifaddr(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    if copied_sockaddr_family(&req) != AF_INET { return -(Errno::Einval.as_i32() as i64); }
    let ip = net::Ipv4Addr::from_u32(u32::from_be_bytes([req[20], req[21], req[22], req[23]]));
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let id = lease.iface();
        let Some(effect) = stack.set_primary_ipv4_generation_rtnl(
            &rtnl, net_ns, id, lease.generation(), ip, 0)
        else { return -(Errno::Enodev.as_i32() as i64) };
        let Some(row) = net::iface_addr::snapshot_ns(net_ns).into_iter()
            .find(|row| row.iface == id && row.addr == ip) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage_addr(&rtnl, net::control_event::AddrEvent {
            kind: net::control_event::EventKind::New,
            namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
            owner: net::control_event::IfaceOwner { iface: id, generation: lease.generation() },
            label: alloc::string::String::from(name), row,
        }, effect)
    };
    net::control_event::publish(ticket);
    0
}

fn siocgifnetmask(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match lookup_ipv4_getter(net_ns, &name) {
        Ok((_id, _ip, mask)) => {
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            if write_sockaddr_in(arg, mask) { 0 } else { -(Errno::Efault.as_i32() as i64) }
        }
        Err(errno) => -(errno.as_i32() as i64),
    }
}

fn siocsifnetmask(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    if copied_sockaddr_family(&req) != AF_INET { return -(Errno::Einval.as_i32() as i64); }
    let mask = u32::from_be_bytes([req[20], req[21], req[22], req[23]]);
    let ones = mask.leading_ones();
    let canonical = if ones == 0 { 0 } else { u32::MAX << (32 - ones) };
    if mask != canonical { return -(Errno::Einval.as_i32() as i64); }
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let id = lease.iface();
        if net::iface_addr::primary(net_ns, id).is_none() {
            return -(Errno::Eaddrnotavail.as_i32() as i64);
        }
        if !stack.set_primary_ipv4_mask_generation_rtnl(
            &rtnl, net_ns, id, lease.generation(), mask) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(row) = net::iface_addr::snapshot_ns(net_ns).into_iter()
            .find(|row| row.iface == id && row.mask == mask) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl,
            net::control_event::ControlEvent::Addr(net::control_event::AddrEvent {
                kind: net::control_event::EventKind::New,
                namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
                owner: net::control_event::IfaceOwner {
                    iface: id, generation: lease.generation(),
                },
                label: alloc::string::String::from(name), row,
            }))
    };
    net::control_event::publish(ticket);
    0
}

fn siocgifbrdaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    let (id, _, _) = match lookup_ipv4_getter(net_ns, &name) {
        Ok(found) => found,
        Err(errno) => return -(errno.as_i32() as i64),
    };
    let Some(brd) = net::iface_addr::broadcast(net_ns, id) else {
        return -(Errno::Eaddrnotavail.as_i32() as i64);
    };
    // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
    if write_sockaddr_in(arg, brd.as_u32()) { 0 } else { -(Errno::Efault.as_i32() as i64) }
}

fn siocsifbrdaddr(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let name = match copied_ifname(&req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    if copied_sockaddr_family(&req) != AF_INET { return -(Errno::Einval.as_i32() as i64); }
    let broadcast = net::Ipv4Addr::from_u32(u32::from_be_bytes([req[20], req[21], req[22], req[23]]));
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease,
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let rtnl = stack.rtnl_lock();
    if !lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
        return -(Errno::Enodev.as_i32() as i64);
    }
    if stack.set_ipv4_broadcast_generation_rtnl(&rtnl, net_ns, lease.iface(),
        lease.generation(), broadcast) { 0 }
    else { -(Errno::Enodev.as_i32() as i64) }
}

fn siocgifname(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifname_inner)
}

fn siocgifname_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let idx = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
    if idx <= 0 { return -(Errno::Enodev.as_i32() as i64); }
    let bytes = match net::sock::stack().ifaces.lookup_ifindex_in_ns(idx as u32, net_ns) {
        Some((id, _)) => match net::sock::stack().ifaces.name_in_ns(id, net_ns) {
            Some(name) => name, None => return -(Errno::Enodev.as_i32() as i64),
        },
        None => return -(Errno::Enodev.as_i32() as i64),
    };
    let bytes = bytes.as_bytes();
    let mut name = [0u8; IFNAMSIZ];
    name[..bytes.len().min(IFNAMSIZ)].copy_from_slice(&bytes[..bytes.len().min(IFNAMSIZ)]);
    req[..IFNAMSIZ].copy_from_slice(&name);
    0
}

fn siocsifname(net_ns: u64, arg: u64) -> i64 {
    let req = match read_ifreq(arg) { Some(req) => req, None => return -(Errno::Efault.as_i32() as i64) };
    let Some(end) = req[..IFNAMSIZ].iter().position(|&b| b == 0) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if end == 0 { return -(Errno::Einval.as_i32() as i64); }
    let Ok(name) = core::str::from_utf8(&req[..end]) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if name == "." || name == ".." || name.bytes().any(|b| b == b'/' || b.is_ascii_whitespace()) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let idx = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
    if idx <= 0 { return -(Errno::Enodev.as_i32() as i64); }
    let stack = net::sock::stack();
    let Some((id, _)) = stack.ifaces.lookup_ifindex_in_ns(idx as u32, net_ns) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    let lease = match stack.ifaces.acquire_ingress(id) {
        Some(lease) if lease.net_ns() == net_ns => lease,
        _ => return -(Errno::Enodev.as_i32() as i64),
    };
    let rtnl = stack.rtnl_lock();
    if stack.ifaces.control_generation_in_ns(&rtnl, id, net_ns) != Some(lease.generation()) {
        return -(Errno::Enodev.as_i32() as i64);
    }
    match stack.ifaces.rename_in_ns(&rtnl, id, net_ns, name) {
        Ok(_) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// SIOCGIFCONF — return the list of interfaces. ifconf layout:
///   int     ifc_len     // bytes capacity in, bytes filled out
///   char*   ifc_buf     // pointer to ifreq[]
/// We fill ifc_req[] with one struct ifreq per iface and update
/// ifc_len.
fn siocgifconf(net_ns: u64, arg: u64) -> i64 {
    if !user_range(arg, IFCONF_SIZE) { return -(Errno::Efault.as_i32() as i64); }
    let mut header = [0u8; IFCONF_SIZE];
    if uaccess::copy_from_user(&mut header, arg).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let ifc_len = i32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
    let ifc_buf = u64::from_ne_bytes(header[8..16].try_into().unwrap());
    let devices = net::sock::stack().ifaces.snapshot_devs_in_ns(net_ns);
    let mut addresses = net::iface_addr::snapshot_ns(net_ns);
    addresses.retain(|row| !row.addr.is_unspecified()
        && devices.iter().any(|(id, _)| *id == row.iface));
    let stride = IFREQ_SIZE;
    if ifc_buf == 0 {
        let required = addresses.len().saturating_mul(stride).min(i32::MAX as usize) as i32;
        return if uaccess::copy_to_user(arg, &required.to_ne_bytes()).is_ok() { 0 }
            else { -(Errno::Efault.as_i32() as i64) };
    }
    if ifc_len < 0 || !user_range(ifc_buf, ifc_len as usize) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cap = (ifc_len as usize) / stride;
    let mut output = Vec::with_capacity(cap.saturating_mul(stride));
    for row in addresses {
        if output.len() / stride >= cap { break; }
        let Some((id, _)) = devices.iter().find(|(id, _)| *id == row.iface) else { continue; };
        let Some(name) = net::sock::stack().ifaces.name_in_ns(*id, net_ns) else { continue; };
        let name_bytes = name.as_bytes();
        for i in 0..IFNAMSIZ { output.push(if i < name_bytes.len() { name_bytes[i] } else { 0 }); }
        output.extend_from_slice(&sockaddr_in_bytes(row.addr.as_u32()));
        output.resize(output.len() + (IFREQ_SIZE - IFNAMSIZ - 16), 0);
    }
    if !output.is_empty() && uaccess::copy_to_user(ifc_buf, &output).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let bytes_written = output.len().min(i32::MAX as usize) as i32;
    if uaccess::copy_to_user(arg, &bytes_written.to_ne_bytes()).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

#[cfg(test)]
#[path = "siocgif/tests.rs"]
mod tests;
