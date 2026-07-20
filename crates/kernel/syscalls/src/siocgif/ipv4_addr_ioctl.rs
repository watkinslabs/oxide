// Legacy IPv4 address ioctl ABI shim — canonical iface_addr mutations under RTNL.

use syscall::errno::Errno;

const SOCKADDR_IN_ADDR_OFFSET: usize = super::IFNAMSIZ + core::mem::size_of::<u16>()
    + core::mem::size_of::<[u8; 2]>();
const IPV4_FIRST_OCTET_SHIFT: u32 = 24;
const IPV4_MULTICAST_FIRST_OCTET: u8 = 224;
const IPV4_CLASS_E_FIRST_OCTET: u8 = 240;

fn request(arg: u64) -> Result<[u8; super::IFREQ_SIZE], i64> {
    super::read_ifreq(arg).ok_or(-(Errno::Efault.as_i32() as i64))
}

fn name(ifreq: &[u8; super::IFREQ_SIZE]) -> Result<&str, i64> {
    super::copied_ifname(ifreq).ok_or(-(Errno::Efault.as_i32() as i64))
}

fn ipv4(ifreq: &[u8; super::IFREQ_SIZE]) -> net::Ipv4Addr {
    let start = SOCKADDR_IN_ADDR_OFFSET;
    let end = start + core::mem::size_of::<u32>();
    net::Ipv4Addr::from_u32(u32::from_be_bytes(ifreq[start..end].try_into().unwrap()))
}

fn accepted_legacy_peer(address: net::Ipv4Addr) -> bool {
    let first = (address.as_u32() >> IPV4_FIRST_OCTET_SHIFT) as u8;
    first < IPV4_MULTICAST_FIRST_OCTET || first >= IPV4_CLASS_E_FIRST_OCTET
}

/// Read the destination/peer address from the canonical IPv4 address record. # C: O(N addresses)
pub(super) fn get_destination(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match request(arg) { Ok(request) => request, Err(error) => return error };
    let name = match name(&ifreq) { Ok(name) => name, Err(error) => return error };
    let (iface, _) = match net::sock::stack().ifaces.lookup_name_in_ns(name, net_ns) {
        Some(found) => found, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let requested = (super::copied_sockaddr_family(&ifreq) == super::AF_INET).then(|| ipv4(&ifreq));
    let rows = net::iface_addr::snapshot_ns(net_ns);
    let row = requested.and_then(|address| rows.iter().find(|row| {
        row.iface == iface && row.addr == address
    })).or_else(|| rows.iter().find(|row| row.iface == iface && !row.addr.is_unspecified()));
    let Some(row) = row else { return -(Errno::Eaddrnotavail.as_i32() as i64) };
    if super::write_sockaddr_in(arg, row.address().as_u32()) { 0 }
    else { -(Errno::Efault.as_i32() as i64) }
}

/// Set the destination/peer address through the canonical IPv4 address owner. # C: O(N addresses)
pub(super) fn set_destination(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match request(arg) { Ok(request) => request, Err(error) => return error };
    let name = match name(&ifreq) { Ok(name) => name, Err(error) => return error };
    if super::copied_sockaddr_family(&ifreq) != super::AF_INET { return -(Errno::Einval.as_i32() as i64); }
    let peer = ipv4(&ifreq);
    if !accepted_legacy_peer(peer) { return -(Errno::Einval.as_i32() as i64); }
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !super::lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let id = lease.iface();
        let Some(row) = net::iface_addr::snapshot_ns(net_ns).into_iter()
            .find(|row| row.iface == id && !row.addr.is_unspecified())
        else { return -(Errno::Eaddrnotavail.as_i32() as i64) };
        let Some(effect) = stack.set_ipv4_prefix_meta_generation_rtnl(&rtnl, net_ns, id,
            lease.generation(), row.addr, Some(peer), row.prefixlen, row.scope, row.flags,
            row.cacheinfo) else { return -(Errno::Enodev.as_i32() as i64) };
        let Some(updated) = net::iface_addr::snapshot_ns(net_ns).into_iter()
            .find(|candidate| candidate.iface == id && candidate.addr == row.addr
                && candidate.prefixlen == row.prefixlen)
        else { return -(Errno::Enodev.as_i32() as i64) };
        net::control_event::stage_addr(&rtnl, net::control_event::AddrEvent {
            kind: net::control_event::EventKind::New,
            namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
            owner: net::control_event::IfaceOwner { iface: id, generation: lease.generation() },
            label: alloc::string::String::from(name), row: updated,
        }, effect)
    };
    net::control_event::publish(ticket);
    0
}

/// Delete the exact local or peer IPv4 address through its canonical owner. # C: O(N addresses)
pub(super) fn delete(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match request(arg) { Ok(request) => request, Err(error) => return error };
    let name = match name(&ifreq) { Ok(name) => name, Err(error) => return error };
    if super::copied_sockaddr_family(&ifreq) != super::AF_INET { return -(Errno::Einval.as_i32() as i64); }
    let address = ipv4(&ifreq);
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !super::lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let id = lease.iface();
        let Some(row) = net::iface_addr::snapshot_ns(net_ns).into_iter().find(|row| {
            row.iface == id && row.address() == address
        }) else { return -(Errno::Eaddrnotavail.as_i32() as i64) };
        let Some((removed, effect)) = stack.remove_ipv4_prefix_generation_rtnl(
            &rtnl, net_ns, id, lease.generation(), row.addr, Some(address), row.prefixlen)
        else { return -(Errno::Eaddrnotavail.as_i32() as i64) };
        net::control_event::stage_addr(&rtnl, net::control_event::AddrEvent {
            kind: net::control_event::EventKind::Delete,
            namespace: net::control_event::NamespaceOwner::Live(lease.namespace()),
            owner: net::control_event::IfaceOwner { iface: id, generation: lease.generation() },
            label: alloc::string::String::from(name), row: removed,
        }, effect)
    };
    net::control_event::publish(ticket);
    0
}
