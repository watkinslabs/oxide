use super::*;

pub(crate) fn siocgifflags(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocsifflags(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocsifflags_enodev(stage: &'static [u8]) -> i64 {
    klog::write_raw(b"[SIOCSIFFLAGS ENODEV] stage=");
    klog::write_raw(stage);
    klog::write_raw(b"\n");
    -(Errno::Enodev.as_i32() as i64)
}

pub(crate) fn siocgifindex(net_ns: u64, arg: u64) -> i64 {
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
pub(crate) fn with_ifreq<F>(net_ns: u64, arg: u64, f: F) -> i64
where F: FnOnce(u64, &mut [u8; IFREQ_SIZE]) -> i64 {
    let Some(mut req) = read_ifreq(arg) else { return -(Errno::Efault.as_i32() as i64); };
    let rv = f(net_ns, &mut req);
    if rv == 0 && uaccess::copy_to_user(arg, &req).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    rv
}

pub(crate) fn siocgifmtu(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some((_, dev)) => {
            if write_ifreq_bytes(arg, 16, &(dev.mtu() as i32).to_ne_bytes()) { 0 }
            else { -(Errno::Efault.as_i32() as i64) }
        }
        None => -(Errno::Enodev.as_i32() as i64),
    }
}

pub(crate) fn siocgifmetric(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifmetric_inner)
}

pub(crate) fn siocgifmetric_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(n) => n, None => return -(Errno::Efault.as_i32() as i64) };
    if net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    req[16..20].copy_from_slice(&0i32.to_ne_bytes());
    0
}

pub(crate) fn siocsifmetric(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocsifmetric_inner)
}

pub(crate) fn siocsifmetric_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let name = match copied_ifname(req) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    if net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns).is_none() {
        return -(Errno::Enodev.as_i32() as i64);
    }
    -(Errno::Eopnotsupp.as_i32() as i64)
}

pub(crate) fn siocgifcount(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifcount_inner)
}

pub(crate) fn siocgifcount_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
    let count = net::sock::stack().ifaces.snapshot_devs_in_ns(net_ns).len() as i32;
    req[16..20].copy_from_slice(&count.to_ne_bytes());
    0
}

pub(crate) fn siocsifmtu(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocgifhwaddr(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifhwaddr_inner)
}

pub(crate) fn siocgifhwaddr_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
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

pub(crate) fn siocgifmap(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifmap_inner)
}

pub(crate) fn siocgifmap_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
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

pub(crate) fn siocsifhwaddr(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocgiftxqlen(net_ns: u64, arg: u64) -> i64 {
    let name = match read_ifname(arg) { Some(name) => name, None => return -(Errno::Efault.as_i32() as i64) };
    let (_, dev) = match net::sock::stack().ifaces.lookup_name_in_ns(&name, net_ns) {
        Some(row) => row, None => return -(Errno::Enodev.as_i32() as i64),
    };
    if write_ifreq_bytes(arg, 16, &(dev.tx_queue_len() as i32).to_ne_bytes()) { 0 }
    else { -(Errno::Efault.as_i32() as i64) }
}

pub(crate) fn siocgifpflags(net_ns: u64, arg: u64) -> i64 {
    with_ifreq(net_ns, arg, siocgifpflags_inner)
}

pub(crate) fn siocgifpflags_inner(net_ns: u64, req: &mut [u8; IFREQ_SIZE]) -> i64 {
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

pub(crate) fn siocsifpflags(net_ns: u64, arg: u64) -> i64 {
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

pub(crate) fn siocsiftxqlen(net_ns: u64, arg: u64) -> i64 {
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
