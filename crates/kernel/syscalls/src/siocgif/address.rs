use alloc::vec::Vec;

use super::*;

pub(crate) fn siocgifaddr(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match lookup_ipv4_getter(net_ns, &name) {
        Ok((_id, ip, _mask)) => {
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            if write_sockaddr_in(arg, ip) { 0 } else { -(Errno::Efault.as_i32() as i64) }
        }
        Err(errno) => -(errno.as_i32() as i64),
    }
}

pub(crate) fn siocsifaddr(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocgifnetmask(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match lookup_ipv4_getter(net_ns, &name) {
        Ok((_id, _ip, mask)) => {
            // SAFETY: arg validated; 16-byte sockaddr_in write at +16.
            if write_sockaddr_in(arg, mask) { 0 } else { -(Errno::Efault.as_i32() as i64) }
        }
        Err(errno) => -(errno.as_i32() as i64),
    }
}

pub(crate) fn siocsifnetmask(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocgifbrdaddr(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocsifbrdaddr(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocgifname(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifname_inner)
}

pub(crate) fn siocgifname_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
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

pub(crate) fn siocsifname(net_ns: u64, arg: u64) -> i64 {
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
        Ok(_) => { stack.flowtable_device_event_in(net_ns, id, true); 0 },
        Err(e) => -(e.as_i32() as i64),
    }
}

/// SIOCGIFCONF — return the list of interfaces. ifconf layout:
///   int     ifc_len     // bytes capacity in, bytes filled out
///   char*   ifc_buf     // pointer to ifreq[]
/// We fill ifc_req[] with one struct ifreq per iface and update
/// ifc_len.
pub(crate) fn siocgifconf(net_ns: u64, arg: u64) -> i64 {
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
