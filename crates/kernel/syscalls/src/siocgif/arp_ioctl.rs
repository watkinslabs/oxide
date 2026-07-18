//! Linux `struct arpreq` legacy ioctl ABI over the canonical neighbour owner.

use super::SiocAccess;
use hal::USER_VA_END;
use syscall::errno::Errno;

pub(super) const SIOCDARP: u64 = 0x8953;
pub(super) const SIOCGARP: u64 = 0x8954;
pub(super) const SIOCSARP: u64 = 0x8955;

const ARPREQ_SIZE: usize = 68;
const SOCKADDR_SIZE: usize = 16;
const ARPREQ_PA: usize = 0;
const ARPREQ_HA: usize = ARPREQ_PA + SOCKADDR_SIZE;
const ARPREQ_FLAGS: usize = ARPREQ_HA + SOCKADDR_SIZE;
const ARPREQ_DEV: usize = ARPREQ_FLAGS + 4 + SOCKADDR_SIZE;
const AF_INET: u16 = 2;
const ARPHRD_ETHER: u16 = 1;
const ATF_COM: u32 = 0x02;
const ATF_PERM: u32 = 0x04;
const ATF_PUBL: u32 = 0x08;
const ATF_NETMASK: u32 = 0x20;
const ATF_DONTPUB: u32 = 0x40;

pub(super) fn arg_size(req: u64) -> Option<usize> {
    matches!(req, SIOCDARP | SIOCGARP | SIOCSARP).then_some(ARPREQ_SIZE)
}

pub(super) fn access(req: u64) -> Option<SiocAccess> {
    match req {
        SIOCGARP => Some(SiocAccess::Get),
        SIOCDARP | SIOCSARP => Some(SiocAccess::Mutate),
        _ => None,
    }
}

pub(super) fn handle(net_ns: u64, req: u64, arg: u64) -> i64 {
    let mut bytes = [0u8; ARPREQ_SIZE];
    if uaccess::copy_from_user(&mut bytes, arg).is_err() { return errno(Errno::Efault); }
    match req {
        SIOCGARP => get(net_ns, arg, &mut bytes),
        SIOCSARP => set(net_ns, &bytes),
        SIOCDARP => delete(net_ns, &bytes),
        _ => errno(Errno::Enotty),
    }
}

fn get(net_ns: u64, arg: u64, bytes: &mut [u8; ARPREQ_SIZE]) -> i64 {
    let ip = match protocol_address(bytes) { Ok(ip) => ip, Err(error) => return errno(error) };
    let iface = match iface_for(net_ns, bytes, ip, true) { Ok(iface) => iface, Err(error) => return errno(error) };
    let Some((mac, permanent)) = net::sock::stack().arp_entry(iface, ip) else { return errno(Errno::Enxio); };
    bytes[ARPREQ_HA..ARPREQ_HA + 2].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
    bytes[ARPREQ_HA + 2..ARPREQ_HA + 8].copy_from_slice(&mac.0);
    let flags = ATF_COM | if permanent { ATF_PERM } else { 0 };
    bytes[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].copy_from_slice(&(flags as i32).to_ne_bytes());
    if uaccess::copy_to_user(arg, bytes).is_ok() { 0 } else { errno(Errno::Efault) }
}

fn set(net_ns: u64, bytes: &[u8; ARPREQ_SIZE]) -> i64 {
    let ip = match protocol_address(bytes) { Ok(ip) => ip, Err(error) => return errno(error) };
    let flags = u32::from_ne_bytes(bytes[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].try_into().unwrap());
    if let Err(error) = supported_flags(flags) { return errno(error); }
    if flags & (ATF_COM | ATF_PERM) == 0 { return errno(Errno::Eopnotsupp); }
    let iface = match iface_for(net_ns, bytes, ip, false) { Ok(iface) => iface, Err(error) => return errno(error) };
    let family = u16::from_ne_bytes(bytes[ARPREQ_HA..ARPREQ_HA + 2].try_into().unwrap());
    if family != 0 && family != ARPHRD_ETHER { return errno(Errno::Einval); }
    let mut raw = [0; 6]; raw.copy_from_slice(&bytes[ARPREQ_HA + 2..ARPREQ_HA + 8]);
    let stack = net::sock::stack();
    if flags & ATF_PERM != 0 { stack.arp_set_permanent(iface, ip, net::MacAddr(raw)); }
    else { stack.arp_learn(iface, ip, net::MacAddr(raw)); }
    0
}

fn delete(net_ns: u64, bytes: &[u8; ARPREQ_SIZE]) -> i64 {
    let ip = match protocol_address(bytes) { Ok(ip) => ip, Err(error) => return errno(error) };
    let flags = u32::from_ne_bytes(bytes[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].try_into().unwrap());
    if let Err(error) = supported_flags(flags) { return errno(error); }
    let iface = match iface_for(net_ns, bytes, ip, false) { Ok(iface) => iface, Err(error) => return errno(error) };
    net::sock::stack().arp_remove(iface, ip).map_or_else(|| errno(Errno::Enxio), |_| 0)
}

/// Reject ARP forms that either Linux rejects or need the absent forwarding owner. # C: O(1)
fn supported_flags(flags: u32) -> Result<(), Errno> {
    if flags & ATF_PUBL == 0 && flags & (ATF_NETMASK | ATF_DONTPUB) != 0 {
        return Err(Errno::Einval);
    }
    if flags & ATF_PUBL != 0 { return Err(Errno::Eopnotsupp); }
    Ok(())
}

fn protocol_address(bytes: &[u8; ARPREQ_SIZE]) -> Result<net::Ipv4Addr, Errno> {
    if u16::from_ne_bytes(bytes[ARPREQ_PA..ARPREQ_PA + 2].try_into().unwrap()) != AF_INET {
        return Err(Errno::Eafnosupport);
    }
    Ok(net::Ipv4Addr::from_u32(u32::from_be_bytes(bytes[ARPREQ_PA + 4..ARPREQ_PA + 8].try_into().unwrap())))
}

fn iface_for(net_ns: u64, bytes: &[u8; ARPREQ_SIZE], ip: net::Ipv4Addr,
             get: bool) -> Result<net::NetIfaceId, Errno>
{
    let end = bytes[ARPREQ_DEV..].iter().position(|byte| *byte == 0).unwrap_or(16);
    if end != 0 {
        let name = core::str::from_utf8(&bytes[ARPREQ_DEV..ARPREQ_DEV + end]).map_err(|_| Errno::Enodev)?;
        let (iface, dev) = net::sock::stack().ifaces.lookup_name_in_ns(name, net_ns)
            .ok_or(Errno::Enodev)?;
        return (dev.hardware_type() == ARPHRD_ETHER).then_some(iface).ok_or(Errno::Eopnotsupp);
    }
    if get { return Err(Errno::Enodev); }
    let iface = net::sock::stack().routes.lookup_in(net_ns, ip)
        .map(|route| route.iface).ok_or(Errno::Enetunreach)?;
    let dev = net::sock::stack().ifaces.lookup_in_ns(iface, net_ns).ok_or(Errno::Enodev)?;
    (dev.hardware_type() == ARPHRD_ETHER).then_some(iface).ok_or(Errno::Eopnotsupp)
}

fn errno(error: Errno) -> i64 { -(error.as_i32() as i64) }

const _: () = assert!(ARPREQ_DEV + 16 == ARPREQ_SIZE);
const _: () = assert!(ARPREQ_SIZE as u64 <= USER_VA_END);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_native_arpreq_ipv4_address() {
        let mut request = [0u8; ARPREQ_SIZE];
        request[ARPREQ_PA..ARPREQ_PA + 2].copy_from_slice(&AF_INET.to_ne_bytes());
        request[ARPREQ_PA + 4..ARPREQ_PA + 8].copy_from_slice(&[192, 0, 2, 9]);
        assert_eq!(protocol_address(&request), Ok(net::Ipv4Addr::new(192, 0, 2, 9)));
        request[ARPREQ_PA..ARPREQ_PA + 2].copy_from_slice(&10u16.to_ne_bytes());
        assert_eq!(protocol_address(&request), Err(Errno::Eafnosupport));
    }

    #[test]
    fn advertises_native_arpreq_layout_and_access() {
        assert_eq!(arg_size(SIOCGARP), Some(68));
        assert_eq!(arg_size(SIOCSARP), Some(68));
        assert_eq!(arg_size(SIOCDARP), Some(68));
        assert_eq!(access(SIOCGARP), Some(SiocAccess::Get));
        assert_eq!(access(SIOCSARP), Some(SiocAccess::Mutate));
        assert_eq!(access(SIOCDARP), Some(SiocAccess::Mutate));
    }

    #[test]
    fn rejects_proxy_and_invalid_masked_arpreq_without_mutating_neighbours() {
        let mut request = [0u8; ARPREQ_SIZE];
        request[ARPREQ_PA..ARPREQ_PA + 2].copy_from_slice(&AF_INET.to_ne_bytes());
        request[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].copy_from_slice(&(ATF_COM | ATF_PUBL).to_ne_bytes());
        assert_eq!(set(0, &request), errno(Errno::Eopnotsupp));
        request[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].copy_from_slice(&(ATF_COM | ATF_NETMASK).to_ne_bytes());
        assert_eq!(set(0, &request), errno(Errno::Einval));
        request[ARPREQ_FLAGS..ARPREQ_FLAGS + 4].copy_from_slice(&ATF_PUBL.to_ne_bytes());
        assert_eq!(delete(0, &request), errno(Errno::Eopnotsupp));
    }
}
