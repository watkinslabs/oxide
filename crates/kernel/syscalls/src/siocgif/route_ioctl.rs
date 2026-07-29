use alloc::string::String;
use hal::USER_VA_END;
use syscall::errno::Errno;

const AF_INET: u16 = 2;
const RTENTRY_LEN: u64 = 120;
const OFF_DST: u64 = 8;
const OFF_GATEWAY: u64 = 24;
const OFF_GENMASK: u64 = 40;
const OFF_FLAGS: u64 = 56;
const OFF_METRIC: u64 = 80;
const OFF_DEV: u64 = 88;
const OFF_MTU: u64 = 96;
const OFF_WINDOW: u64 = 104;
const OFF_IRTT: u64 = 112;
const RTF_GATEWAY: u16 = 0x0002;
const RTF_HOST: u16 = 0x0004;
const RTF_MTU: u16 = 0x0040;
const RTF_WINDOW: u16 = 0x0080;
const RTF_IRTT: u16 = 0x0100;
const RTF_REJECT: u16 = 0x0200;

#[derive(Copy, Clone)]
struct Request {
    dst: net::Ipv4Addr,
    gateway: Option<net::Ipv4Addr>,
    prefix_len: u8,
    flags: u16,
    metric: Option<u32>,
    dev_ptr: u64,
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn sockaddr(arg: u64, off: u64) -> (u16, u32) {
    // SAFETY: parse bounds-checks the complete rtentry before fixed-offset reads.
    unsafe {
        (core::ptr::read_volatile((arg + off) as *const u16),
         u32::from_be(core::ptr::read_volatile((arg + off + 4) as *const u32)))
    }
}

fn prefix(mask: u32) -> Option<u8> {
    let len = mask.leading_ones() as u8;
    let expected = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (mask == expected).then_some(len)
}

fn parse(arg: u64) -> Result<Request, i64> {
    if arg == 0 || arg.checked_add(RTENTRY_LEN).is_none_or(|end| end > USER_VA_END) {
        return Err(errno(Errno::Efault));
    }
    let (dst_family, dst_raw) = sockaddr(arg, OFF_DST);
    let (gateway_family, gateway_raw) = sockaddr(arg, OFF_GATEWAY);
    let (mask_family, mask) = sockaddr(arg, OFF_GENMASK);
    if dst_family != AF_INET { return Err(errno(Errno::Eafnosupport)); }
    if gateway_family != 0 && gateway_family != AF_INET {
        return Err(errno(Errno::Eafnosupport));
    }
    if mask_family != AF_INET && !(mask_family == 0 && mask == 0) {
        return Err(errno(Errno::Eafnosupport));
    }
    // SAFETY: complete rtentry range was checked above and offsets match Linux x86_64/aarch64 ABI.
    let (flags, metric, dev_ptr, mtu, window, irtt) = unsafe {
        (core::ptr::read_volatile((arg + OFF_FLAGS) as *const u16),
         core::ptr::read_volatile((arg + OFF_METRIC) as *const i16),
         core::ptr::read_volatile((arg + OFF_DEV) as *const u64),
         core::ptr::read_volatile((arg + OFF_MTU) as *const u64),
         core::ptr::read_volatile((arg + OFF_WINDOW) as *const u64),
         core::ptr::read_volatile((arg + OFF_IRTT) as *const u16))
    };
    if metric < 0 { return Err(errno(Errno::Einval)); }
    if mtu != 0 || window != 0 || irtt != 0
        || flags & (RTF_MTU | RTF_WINDOW | RTF_IRTT) != 0 {
        return Err(errno(Errno::Eopnotsupp));
    }
    let prefix_len = if flags & RTF_HOST != 0 { 32 }
        else { prefix(mask).ok_or_else(|| errno(Errno::Einval))? };
    if prefix_len < 32 && dst_raw & (u32::MAX >> prefix_len) != 0 {
        return Err(errno(Errno::Einval));
    }
    let gateway = (flags & RTF_GATEWAY != 0 && gateway_family == AF_INET && gateway_raw != 0)
        .then_some(net::Ipv4Addr::from_u32(gateway_raw));
    if flags & RTF_GATEWAY != 0 && gateway.is_none() {
        return Err(errno(Errno::Einval));
    }
    Ok(Request {
        dst: net::Ipv4Addr::from_u32(dst_raw), gateway, prefix_len, flags,
        metric: (metric != 0).then_some(metric as u32 - 1), dev_ptr,
    })
}

fn explicit_iface_name(dev_ptr: u64) -> Result<Option<String>, i64> {
    if dev_ptr == 0 { return Ok(None); }
    let name = crate::mount_common::read_user_cstr_owned(dev_ptr, super::IFNAMSIZ)?;
    let base = name.split(':').next().unwrap_or("");
    if base.is_empty() { return Err(errno(Errno::Enodev)); }
    Ok(Some(String::from(base)))
}

fn subnet_iface(net_ns: u64, addr: net::Ipv4Addr) -> Option<net::NetIfaceId> {
    for (id, _) in net::sock::stack().ifaces.snapshot_devs_in_ns(net_ns) {
        let (ip, mask) = super::get_ifaddr_in(net_ns, id);
        if mask != 0 && (addr.as_u32() & mask) == (ip & mask) { return Some(id); }
    }
    None
}

fn resolve_iface(net_ns: u64, req: Request, explicit: Option<net::NetIfaceId>)
    -> Result<net::NetIfaceId, i64> {
    if let Some(id) = explicit { return Ok(id); }
    if req.flags & RTF_REJECT != 0 { return Ok(net::NetIfaceId::from_raw(0)); }
    let next_hop = req.gateway.unwrap_or(req.dst);
    if let Some(record) = net::sock::stack().routes.lookup_record_in(net_ns, next_hop) {
        if matches!(record.kind, net::route::RTN_UNICAST | net::route::RTN_LOCAL)
            && record.route.gateway.is_none() {
            return Ok(record.route.iface);
        }
    }
    subnet_iface(net_ns, next_hop).ok_or_else(|| errno(Errno::Enetunreach))
}

fn record(req: Request, iface: net::NetIfaceId) -> net::RouteRecord {
    let reject = req.flags & RTF_REJECT != 0;
    net::RouteRecord {
        route: net::RouteEntry {
            table: net::policy_rule::RT_TABLE_MAIN, dst: req.dst, prefix_len: req.prefix_len,
            iface, gateway: req.gateway, src_hint: None,
        },
        protocol: netlink::rtnetlink::RTPROT_BOOT,
        scope: if reject { netlink::rtnetlink::RT_SCOPE_HOST }
            else if req.gateway.is_some() { netlink::rtnetlink::RT_SCOPE_UNIVERSE }
            else { netlink::rtnetlink::RT_SCOPE_LINK },
        kind: if reject { net::route::RTN_UNREACHABLE } else { net::route::RTN_UNICAST },
        metric: req.metric.unwrap_or(0), metrics: net::RouteMetrics::NONE,
        flags: 0, weight: 1, nh_flags: 0,
    }
}

fn route_leases(stack: &net::NetStack, net_ns: u64, records: &[net::RouteRecord])
    -> Option<alloc::vec::Vec<net::netdev::IngressLease>> {
    let mut leases = alloc::vec::Vec::new();
    for iface in records.iter().map(|record| record.route.iface) {
        if iface.raw() == 0 || leases.iter().any(|lease: &net::netdev::IngressLease| {
            lease.iface() == iface
        }) { continue; }
        let lease = stack.ifaces.acquire_ingress(iface)?;
        if lease.net_ns() != net_ns { return None; }
        leases.push(lease);
    }
    Some(leases)
}

fn leases_match(stack: &net::NetStack, rtnl: &net::RtnlGuard<'_>, net_ns: u64,
                records: &[net::RouteRecord], leases: &[net::netdev::IngressLease]) -> bool {
    records.iter().all(|record| record.route.iface.raw() == 0 || leases.iter().any(|lease| {
        lease.iface() == record.route.iface && lease.net_ns() == net_ns
            && stack.ifaces.control_generation_in_ns(rtnl, lease.iface(), net_ns)
                == Some(lease.generation())
    }))
}

fn iface_owners(leases: &[net::netdev::IngressLease])
    -> alloc::vec::Vec<net::control_event::IfaceOwner> {
    leases.iter().map(|lease| net::control_event::IfaceOwner {
        iface: lease.iface(), generation: lease.generation(),
    }).collect()
}

/// Add an IPv4 route from Linux `struct rtentry`. # C: O(N_routes + N_ifaces)
pub(super) fn add(net_ns: u64, arg: u64) -> i64 {
    let namespace = if net_ns == 0 { network_namespace::initial() } else {
        match network_namespace::lookup_u64(net_ns) {
            Some(namespace) => namespace, None => return errno(Errno::Enodev),
        }
    };
    let req = match parse(arg) { Ok(req) => req, Err(rv) => return rv };
    let name = match explicit_iface_name(req.dev_ptr) { Ok(name) => name, Err(rv) => return rv };
    let stack = net::sock::stack();
    let explicit_lease = match name.as_deref() {
        Some(name) => match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
            Some(lease) => Some(lease), None => return errno(Errno::Enodev),
        },
        None => None,
    };
    let explicit = explicit_lease.as_ref().map(net::netdev::IngressLease::iface);
    let iface = match resolve_iface(net_ns, req, explicit) { Ok(id) => id, Err(rv) => return rv };
    let leases = if let Some(lease) = explicit_lease { alloc::vec![lease] }
        else if iface.raw() == 0 { alloc::vec::Vec::new() }
        else { match stack.ifaces.acquire_ingress(iface) {
            Some(lease) if lease.net_ns() == net_ns => alloc::vec![lease],
            _ => return errno(Errno::Enodev),
        }
    };
    let added = record(req, iface);
    let rtnl = stack.rtnl_lock();
    if !leases_match(stack, &rtnl, net_ns, core::slice::from_ref(&added), &leases) {
        return errno(Errno::Enodev);
    }
    if let Err(err) = stack.routes.replace_group_rtnl(
        &rtnl, net_ns, &[added], true, true, false, false) {
        return match err {
            net::route::RouteChangeError::Exists => errno(Errno::Eexist),
            net::route::RouteChangeError::NotFound => errno(Errno::Esrch),
            net::route::RouteChangeError::Invalid => errno(Errno::Einval),
        };
    }
    let owners = iface_owners(&leases);
    let ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: net::control_event::EventKind::New,
            namespace: net::control_event::NamespaceOwner::Live(namespace), owners, leases,
            records: alloc::vec![added],
        }));
    drop(rtnl);
    net::control_event::publish(ticket);
    0
}

/// Delete the lowest-priority matching IPv4 route alias group. # C: O(N_routes + N_ifaces)
pub(super) fn delete(net_ns: u64, arg: u64) -> i64 {
    let namespace = if net_ns == 0 { network_namespace::initial() } else {
        match network_namespace::lookup_u64(net_ns) {
            Some(namespace) => namespace, None => return errno(Errno::Enodev),
        }
    };
    let req = match parse(arg) { Ok(req) => req, Err(rv) => return rv };
    let name = match explicit_iface_name(req.dev_ptr) { Ok(name) => name, Err(rv) => return rv };
    let stack = net::sock::stack();
    let explicit_lease = match name.as_deref() {
        Some(name) => match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
            Some(lease) => Some(lease), None => return errno(Errno::Enodev),
        },
        None => None,
    };
    let explicit = explicit_lease.as_ref().map(net::netdev::IngressLease::iface);
    let matches = |old: &net::RouteRecord| {
        old.route.table == net::policy_rule::RT_TABLE_MAIN && old.route.dst == req.dst
            && old.route.prefix_len == req.prefix_len
            && req.gateway.is_none_or(|gateway| old.route.gateway == Some(gateway))
            && explicit.is_none_or(|iface| old.route.iface == iface)
            && req.metric.is_none_or(|metric| old.metric == metric)
            && (req.flags & RTF_REJECT == 0 || old.kind == net::route::RTN_UNREACHABLE)
    };
    let selected = net::RouteTable::lowest_metric_group(
        &stack.routes.snapshot_records_in(net_ns), |record| matches(record));
    if selected.is_empty() { return errno(Errno::Esrch); }
    let leases = match explicit_lease {
        Some(lease) if selected.iter().all(|record| record.route.iface == lease.iface()) => {
            alloc::vec![lease]
        }
        Some(_) => return errno(Errno::Enodev),
        None => match route_leases(stack, net_ns, &selected) {
            Some(leases) => leases, None => return errno(Errno::Enodev),
        },
    };
    let rtnl = stack.rtnl_lock();
    let current = net::RouteTable::lowest_metric_group(
        &stack.routes.snapshot_records_in(net_ns), |record| matches(record));
    if current != selected || !leases_match(stack, &rtnl, net_ns, &current, &leases) {
        return errno(Errno::Enodev);
    }
    let removed = stack.routes.take_lowest_metric_group_rtnl(
        &rtnl, net_ns, |record| matches(record));
    if removed.is_empty() { return errno(Errno::Esrch); }
    let owners = iface_owners(&leases);
    let ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: net::control_event::EventKind::Delete,
            namespace: net::control_event::NamespaceOwner::Live(namespace),
            owners, leases, records: removed,
        }));
    drop(rtnl);
    net::control_event::publish(ticket);
    0
}
