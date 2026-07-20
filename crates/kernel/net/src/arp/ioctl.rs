// ARP ioctl owner — `arpreq` decoding, neighbour-table mutation, and reply encoding.

use alloc::string::String;

use syscall::errno::Errno;

use super::{ArpCache, NudState};
use super::uapi::*;
use crate::{Ipv4Addr, MacAddr, NetError, NetStack};

enum ArpIoctl { Get, Set, Delete }

struct ArpReq {
    ip: Ipv4Addr,
    mac: MacAddr,
    flags: u32,
    hardware_type: u16,
    device: Option<String>,
    device_valid: bool,
    netmask: Ipv4Addr,
}

/// Execute one Linux SIOC*ARP command against canonical interface-generation state. # C: O(N routes + log N neighbours)
pub fn ioctl(stack: &NetStack, net_ns: u64, command: u64, bytes: &mut [u8; ARPREQ_SIZE])
    -> Result<(), Errno>
{
    let operation = match command {
        SIOCGARP => ArpIoctl::Get,
        SIOCSARP => ArpIoctl::Set,
        SIOCDARP => ArpIoctl::Delete,
        _ => return Err(Errno::Einval),
    };
    let request = decode(bytes)?;
    validate(&request)?;
    match operation {
        ArpIoctl::Get => get(stack, net_ns, &request, bytes),
        ArpIoctl::Set => set(stack, net_ns, request),
        ArpIoctl::Delete => delete(stack, net_ns, request),
    }
}

fn decode(bytes: &[u8; ARPREQ_SIZE]) -> Result<ArpReq, Errno> {
    let protocol_family = family(bytes, ARPREQ_PA_OFFSET);
    if protocol_family != AF_INET { return Err(Errno::Epfnsupport); }
    let ip = Ipv4Addr::from_u32(u32::from_be_bytes(bytes[
        ARPREQ_PA_OFFSET + SOCKADDR_IN_ADDR_OFFSET..ARPREQ_PA_OFFSET + SOCKADDR_IN_ADDR_OFFSET + core::mem::size_of::<u32>()
    ].try_into().map_err(|_| Errno::Einval)?));
    let mut hardware = [0u8; ETHERNET_ADDRESS_BYTES];
    hardware.copy_from_slice(&bytes[ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET..
        ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET + ETHERNET_ADDRESS_BYTES]);
    let flags = u32::from_ne_bytes(bytes[ARPREQ_FLAGS_OFFSET..
        ARPREQ_FLAGS_OFFSET + core::mem::size_of::<u32>()].try_into().map_err(|_| Errno::Einval)?);
    let dev_bytes = &bytes[ARPREQ_DEV_OFFSET..];
    let end = dev_bytes.iter().position(|byte| *byte == 0).unwrap_or(IFNAMSIZ);
    let (device, device_valid) = if end == 0 { (None, true) } else {
        match core::str::from_utf8(&dev_bytes[..end]) {
            Ok(name) => (Some(String::from(name)), true),
            Err(_) => (None, false),
        }
    };
    let netmask = Ipv4Addr::from_u32(u32::from_be_bytes(bytes[
        ARPREQ_NETMASK_OFFSET + SOCKADDR_IN_ADDR_OFFSET..ARPREQ_NETMASK_OFFSET + SOCKADDR_IN_ADDR_OFFSET + core::mem::size_of::<u32>()
    ].try_into().map_err(|_| Errno::Einval)?));
    Ok(ArpReq { ip, mac: MacAddr(hardware), flags, hardware_type: family(bytes, ARPREQ_HA_OFFSET),
        device, device_valid, netmask })
}

fn validate(request: &ArpReq) -> Result<(), Errno> {
    if request.flags & ATF_PUBL == 0 && request.flags & (ATF_NETMASK | ATF_DONTPUB) != 0 {
        return Err(Errno::Einval);
    }
    if request.flags & ATF_PUBL != 0 && request.flags & ATF_NETMASK != 0
        && request.netmask.as_u32() != 0 && request.netmask.as_u32() != u32::MAX
    { return Err(Errno::Einval); }
    Ok(())
}

fn cache_for(stack: &NetStack, net_ns: u64, request: &ArpReq, get: bool)
    -> Result<(ArcCache, u16), Errno>
{
    if !request.device_valid { return Err(Errno::Enodev); }
    let (iface, device) = match &request.device {
        Some(name) => stack.ifaces.lookup_name_in_ns(name, net_ns).ok_or(Errno::Enodev)?,
        None if get => return Err(Errno::Enodev),
        None => stack.routes.lookup_result_in(net_ns, request.ip).map_err(route_errno)
            .and_then(|route| stack.ifaces.lookup_in_ns(route.iface, net_ns)
                .map(|dev| (route.iface, dev)).ok_or(Errno::Enodev))?,
    };
    let hardware_type = device.hardware_type();
    if request.hardware_type != 0 && request.flags & ATF_COM != 0
        && request.hardware_type != hardware_type
    { return Err(Errno::Einval); }
    let cache = stack.ifaces.arp_cache_in_ns(iface, net_ns).ok_or(Errno::Enodev)?;
    Ok((ArcCache(cache), hardware_type))
}

struct ArcCache(alloc::sync::Arc<ArpCache>);

impl core::ops::Deref for ArcCache {
    type Target = ArpCache;
    fn deref(&self) -> &Self::Target { self.0.as_ref() }
}

fn get(stack: &NetStack, net_ns: u64, request: &ArpReq, bytes: &mut [u8; ARPREQ_SIZE])
    -> Result<(), Errno>
{
    let (cache, hardware_type) = cache_for(stack, net_ns, request, true)?;
    let (mac, state) = cache.neighbour_state(request.ip).ok_or(Errno::Enxio)?;
    if !state.usable() { return Err(Errno::Enxio); }
    bytes[ARPREQ_HA_OFFSET..ARPREQ_HA_OFFSET + core::mem::size_of::<u16>()]
        .copy_from_slice(&hardware_type.to_ne_bytes());
    bytes[ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET..
        ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET + ETHERNET_ADDRESS_BYTES]
        .copy_from_slice(&mac.unwrap_or(MacAddr::ZERO).0);
    let flags = if state == NudState::Permanent { ATF_PERM | ATF_COM } else { ATF_COM };
    bytes[ARPREQ_FLAGS_OFFSET..ARPREQ_FLAGS_OFFSET + core::mem::size_of::<u32>()]
        .copy_from_slice(&flags.to_ne_bytes());
    Ok(())
}

fn set(stack: &NetStack, net_ns: u64, request: ArpReq) -> Result<(), Errno> {
    let _rtnl = stack.rtnl_lock();
    if request.flags & ATF_PUBL != 0 {
        let iface = proxy_iface(stack, net_ns, &request)?;
        if request.flags & ATF_NETMASK != 0 && request.netmask.as_u32() == 0 {
            return Err(Errno::Eopnotsupp);
        }
        stack.arp_proxy.insert(net_ns, iface, request.ip);
        return Ok(());
    }
    let (cache, _) = cache_for(stack, net_ns, &request, false)?;
    let completed = cache.admin_set(request.ip,
        (request.flags & (ATF_COM | ATF_PERM) != 0).then_some(request.mac),
        request.flags & ATF_PERM != 0, crate::stack::net_now_ns());
    for job in completed { job.resume(); }
    Ok(())
}

fn delete(stack: &NetStack, net_ns: u64, request: ArpReq) -> Result<(), Errno> {
    let _rtnl = stack.rtnl_lock();
    if request.flags & ATF_PUBL != 0 {
        let iface = proxy_iface(stack, net_ns, &request)?;
        if request.flags & ATF_NETMASK != 0 && request.netmask.as_u32() == 0 {
            return Err(Errno::Eopnotsupp);
        }
        return if stack.arp_proxy.remove(net_ns, iface, request.ip) { Ok(()) }
        else { Err(Errno::Enxio) };
    }
    let (cache, _) = cache_for(stack, net_ns, &request, false)?;
    let entry = cache.remove(request.ip).ok_or(Errno::Enxio)?;
    for job in entry.pending { job.complete(Err(NetError::Ehostunreach)); }
    Ok(())
}

fn proxy_iface(stack: &NetStack, net_ns: u64, request: &ArpReq) -> Result<Option<crate::NetIfaceId>, Errno> {
    if !request.device_valid { return Err(Errno::Enodev); }
    request.device.as_ref().map(|name| stack.ifaces.lookup_name_in_ns(name, net_ns)
        .map(|(iface, _)| iface).ok_or(Errno::Enodev)).transpose()
}

fn family(bytes: &[u8; ARPREQ_SIZE], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn route_errno(error: NetError) -> Errno {
    match error {
        NetError::Enetunreach => Errno::Enetunreach,
        NetError::Ehostunreach => Errno::Ehostunreach,
        NetError::Eacces => Errno::Eacces,
        _ => Errno::Einval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    const TEST_NAMESPACE: u64 = 0x4152_5001;
    const TEST_IP_OCTETS: [u8; 4] = [198, 18, 0, 1];
    const TEST_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const UNSUPPORTED_PROTOCOL_FAMILY: u16 = AF_INET + 1;

    fn request(device: &[u8], ip: Ipv4Addr, hardware_type: u16, flags: u32) -> [u8; ARPREQ_SIZE] {
        let mut bytes = [0u8; ARPREQ_SIZE];
        bytes[ARPREQ_PA_OFFSET..ARPREQ_PA_OFFSET + core::mem::size_of::<u16>()]
            .copy_from_slice(&AF_INET.to_ne_bytes());
        bytes[ARPREQ_PA_OFFSET + SOCKADDR_IN_ADDR_OFFSET..
            ARPREQ_PA_OFFSET + SOCKADDR_IN_ADDR_OFFSET + core::mem::size_of::<u32>()]
            .copy_from_slice(&ip.as_u32().to_be_bytes());
        bytes[ARPREQ_HA_OFFSET..ARPREQ_HA_OFFSET + core::mem::size_of::<u16>()]
            .copy_from_slice(&hardware_type.to_ne_bytes());
        bytes[ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET..
            ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET + ETHERNET_ADDRESS_BYTES].copy_from_slice(&TEST_MAC.0);
        bytes[ARPREQ_FLAGS_OFFSET..ARPREQ_FLAGS_OFFSET + core::mem::size_of::<u32>()]
            .copy_from_slice(&flags.to_ne_bytes());
        bytes[ARPREQ_DEV_OFFSET..ARPREQ_DEV_OFFSET + device.len()].copy_from_slice(device);
        bytes
    }

    #[test]
    fn set_get_delete_uses_the_interface_generation_neighbour_cache() {
        let stack = crate::sock::stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(crate::LoopbackDev::new()), TEST_NAMESPACE);
        let ip = Ipv4Addr::new(TEST_IP_OCTETS[0], TEST_IP_OCTETS[1], TEST_IP_OCTETS[2], TEST_IP_OCTETS[3]);
        let device = b"lo";
        let hardware_type = crate::uapi::ARPHRD_LOOPBACK;
        let mut set = request(device, ip, hardware_type, ATF_COM | ATF_PERM);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCSARP, &mut set), Ok(()));
        let mut get = request(device, ip, 0, 0);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCGARP, &mut get), Ok(()));
        assert_eq!(&get[ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET..
            ARPREQ_HA_OFFSET + SOCKADDR_DATA_OFFSET + ETHERNET_ADDRESS_BYTES], &TEST_MAC.0);
        let flags = u32::from_ne_bytes(get[ARPREQ_FLAGS_OFFSET..
            ARPREQ_FLAGS_OFFSET + core::mem::size_of::<u32>()].try_into().unwrap());
        assert_eq!(flags, ATF_COM | ATF_PERM);
        let mut delete = request(device, ip, hardware_type, 0);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCDARP, &mut delete), Ok(()));
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCGARP, &mut get), Err(Errno::Enxio));
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn rejects_non_ipv4_and_proxy_flag_forms_before_neighbour_lookup() {
        let stack = crate::sock::stack();
        let ip = Ipv4Addr::new(TEST_IP_OCTETS[0], TEST_IP_OCTETS[1], TEST_IP_OCTETS[2], TEST_IP_OCTETS[3]);
        let mut family = request(b"missing", ip, 0, 0);
        family[ARPREQ_PA_OFFSET..ARPREQ_PA_OFFSET + core::mem::size_of::<u16>()]
            .copy_from_slice(&UNSUPPORTED_PROTOCOL_FAMILY.to_ne_bytes());
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCGARP, &mut family), Err(Errno::Epfnsupport));
        let mut flags = request(b"missing", ip, 0, ATF_DONTPUB);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCGARP, &mut flags), Err(Errno::Einval));
    }

    #[test]
    fn published_entry_is_a_canonical_proxy_neighbour_not_a_driver_cache() {
        let stack = crate::sock::stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(crate::LoopbackDev::new()), TEST_NAMESPACE);
        let ip = Ipv4Addr::new(TEST_IP_OCTETS[0], TEST_IP_OCTETS[1], TEST_IP_OCTETS[2], TEST_IP_OCTETS[3]);
        let mut set = request(b"lo", ip, crate::uapi::ARPHRD_LOOPBACK, ATF_PUBL);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCSARP, &mut set), Ok(()));
        assert!(stack.arp_proxy.contains(TEST_NAMESPACE, iface, ip));
        let mut delete = request(b"lo", ip, crate::uapi::ARPHRD_LOOPBACK, ATF_PUBL);
        assert_eq!(ioctl(stack, TEST_NAMESPACE, SIOCDARP, &mut delete), Ok(()));
        assert!(!stack.arp_proxy.contains(TEST_NAMESPACE, iface, ip));
        let _ = stack.ifaces.unregister(iface);
    }
}
