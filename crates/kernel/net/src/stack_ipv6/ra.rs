use crate::addr::Ipv6Addr;
// Only the `#[cfg(test)]` RA entry points below take an iface id.
#[cfg(test)]
use crate::addr::NetIfaceId;
use crate::route6::{Route6Entry, Route6Origin};
use crate::stack::NetStack;

const NS_PER_SEC: u64 = 1_000_000_000;
const NS_PER_MILLISEC: u64 = 1_000_000;
const INFINITE_DEADLINE: u64 = u64::MAX;
const MAX_FINITE_DEADLINE: u64 = u64::MAX - 1;
pub(super) const TWO_HOURS_SECS: u32 = 2 * 60 * 60;
pub(crate) const DAD_DELAY_NS: u64 = NS_PER_SEC;

impl NetStack {
    /// Test-only RA entry: the live path resolves the ingress lease first and
    /// calls `apply_router_advertisement_lease` (see `stack_ipv6/control.rs`).
    #[cfg(test)]
    pub(crate) fn apply_router_advertisement(&self, net_ns: u64, iface: NetIfaceId,
        router: Ipv6Addr, ra: &crate::ndp::RouterAdvertisement)
    {
        self.apply_router_advertisement_ordered(net_ns, iface, router, ra, || {});
    }

    #[cfg(test)]
    pub(super) fn apply_router_advertisement_ordered<F: FnOnce()>(&self, net_ns: u64,
        iface: NetIfaceId, router: Ipv6Addr, ra: &crate::ndp::RouterAdvertisement,
        routes_published: F)
    {
        let Some(lease) = self.ifaces.acquire_ingress(iface) else { return };
        if lease.net_ns() != net_ns { return; }
        self.apply_router_advertisement_lease(&lease, router, ra, routes_published);
    }

    pub(super) fn apply_router_advertisement_lease<F: FnOnce()>(
        &self, lease: &crate::IngressLease, router: Ipv6Addr,
        ra: &crate::ndp::RouterAdvertisement, routes_published: F)
    {
        let net_ns = lease.net_ns();
        let iface = lease.iface();
        let Some(label) = self.ifaces.lookup_in_ns(iface, net_ns)
            .map(|dev| alloc::string::String::from(dev.name())) else { return };
        let rtnl = self.rtnl_lock();
        if self.multicast_generation_in(&rtnl, net_ns, iface).ok() != Some(lease.generation()) {
            return;
        }
        let now_ns = self.ra_now_ns();
        if let Some(mac) = ra.source_lladdr { self.ndp_insert(iface, router, mac); }
        let our_mac = match self.ifaces.lookup_in_ns(iface, net_ns) {
            Some(dev) => dev.mac(),
            None => return,
        };
        let mut replacements = alloc::vec::Vec::new();
        let mut slaac_hints = alloc::vec::Vec::new();
        let mut addr_events = alloc::vec::Vec::new();
        let mut dad_targets = alloc::vec::Vec::new();
        let retrans_timer_ns = (ra.retrans_timer != 0).then(||
            (ra.retrans_timer as u64).saturating_mul(NS_PER_MILLISEC));
        for p in &ra.prefixes {
            if p.prefix_len > 128 || p.preferred_lifetime > p.valid_lifetime { continue; }
            let prefix = canonical_prefix(p.prefix, p.prefix_len);
            if prefix.is_link_local() { continue; }
            let autoconf = p.prefix_len == 64
                && (p.flags & crate::ndp::NDP_PIO_FLAG_AUTO) != 0;
            let onlink = (p.flags & crate::ndp::NDP_PIO_FLAG_ONLINK) != 0;
            let addr = slaac_eui64_addr(prefix, our_mac);
            slaac_hints.retain(|(candidate, _)| *candidate != prefix);
            if autoconf {
                if let Some(start_dad) = self.upsert_slaac_addr(iface, addr, p.prefix_len,
                    p.valid_lifetime, p.preferred_lifetime, prefix, now_ns, retrans_timer_ns) {
                    slaac_hints.push((prefix, addr));
                    if start_dad { dad_targets.push(addr); }
                    if let Some(row) = self.v6_addrs.lock().get(&iface)
                        .and_then(|rows| rows.iter().find(|row| row.addr == addr)).cloned()
                    {
                        addr_events.push(row);
                    }
                }
            }
            replacements.retain(|route: &Route6Entry| !(route.origin.is_ra_prefix()
                && route.iface == iface && route.prefix_len == p.prefix_len && route.dst == prefix));
            if onlink && p.valid_lifetime != 0 {
                let src_hint = self.v6_select_source_current(iface, prefix,
                    autoconf.then_some(addr));
                replacements.push(Route6Entry { table: crate::policy_rule::RT_TABLE_MAIN,
                    dst: prefix, prefix_len: p.prefix_len,
                    iface, gateway: None, src_hint,
                    origin: Route6Origin::RouterAdvertisementPrefix {
                        valid_until_ns: lifetime_deadline(now_ns, p.valid_lifetime) } });
            }
        }
        if ra.router_lifetime != 0 {
            replacements.push(Route6Entry { table: crate::policy_rule::RT_TABLE_MAIN,
                dst: Ipv6Addr::ANY, prefix_len: 0, iface,
                gateway: Some(router), src_hint: self.v6_select_source_current(iface, router,
                    slaac_hints.last().map(|(_, addr)| *addr)),
                origin: Route6Origin::RouterAdvertisementDefault { router,
                    valid_until_ns: lifetime_deadline(now_ns, ra.router_lifetime as u32) } });
        }
        let added_routes = replacements.clone();
        let removed_routes = self.routes6.replace_in_changes(net_ns, |route| route.iface == iface
            && (route.origin.ra_router() == Some(router) || route.origin.is_ra_prefix()
                && ra.prefixes.iter().any(|p| p.prefix_len <= 128
                    && p.preferred_lifetime <= p.valid_lifetime
                    && (p.flags & crate::ndp::NDP_PIO_FLAG_ONLINK) != 0
                    && !canonical_prefix(p.prefix, p.prefix_len).is_link_local()
                    && route.prefix_len == p.prefix_len
                    && route.dst == canonical_prefix(p.prefix, p.prefix_len))), replacements);
        let deleted_routes = removed_routes.into_iter().filter(|old| !added_routes.iter()
            .any(|new| new.dst == old.dst && new.prefix_len == old.prefix_len
                && new.iface == old.iface && new.gateway == old.gateway)).collect();
        let mut ticket = None;
        for row in addr_events {
            ticket = self.stage_addr6(&rtnl, &lease, label.clone(),
                crate::control_event::EventKind::New, row);
        }
        if let Some(next) = self.stage_route6(&rtnl, &lease,
            crate::control_event::EventKind::Delete, deleted_routes) { ticket = Some(next); }
        if let Some(next) = self.stage_route6(&rtnl, &lease,
            crate::control_event::EventKind::New, added_routes) { ticket = Some(next); }
        drop(rtnl);
        if let Some(ticket) = ticket { crate::control_event::publish(ticket); }
        for target in dad_targets { self.try_dad_probe(iface, target, now_ns); }
        routes_published();
    }

    pub(crate) fn ra_now_ns(&self) -> u64 {
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
        #[cfg(not(target_os = "oxide-kernel"))]
        { return self.ra_now_ns.load(core::sync::atomic::Ordering::Acquire); }
        #[allow(unreachable_code)]
        0
    }

    #[cfg(test)]
    pub(super) fn set_ra_now_ns(&self, now_ns: u64) {
        self.ra_now_ns.store(now_ns, core::sync::atomic::Ordering::Release);
        self.routes6.set_now_ns(now_ns);
    }
}

pub(super) fn lifetime_deadline(now_ns: u64, lifetime: u32) -> u64 {
    if lifetime == u32::MAX { INFINITE_DEADLINE }
    else { now_ns.saturating_add((lifetime as u64).saturating_mul(NS_PER_SEC))
        .min(MAX_FINITE_DEADLINE) }
}

pub(super) fn remaining_lifetime(now_ns: u64, deadline_ns: u64) -> u32 {
    if deadline_ns == INFINITE_DEADLINE { return u32::MAX; }
    ((deadline_ns.saturating_sub(now_ns) / NS_PER_SEC).min(u32::MAX as u64)) as u32
}

pub(super) fn slaac_eui64_addr(prefix: Ipv6Addr, mac: crate::addr::MacAddr) -> Ipv6Addr {
    let mut out = prefix.0;
    out[8] = mac.0[0] ^ 0x02;
    out[9] = mac.0[1];
    out[10] = mac.0[2];
    out[11] = 0xff;
    out[12] = 0xfe;
    out[13] = mac.0[3];
    out[14] = mac.0[4];
    out[15] = mac.0[5];
    Ipv6Addr(out)
}

pub(super) fn canonical_prefix(prefix: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let mut out = prefix.0;
    let full = (prefix_len.min(128) / 8) as usize;
    let rem = prefix_len.min(128) % 8;
    if rem != 0 {
        out[full] &= u8::MAX << (8 - rem);
        for byte in &mut out[full + 1..] { *byte = 0; }
    } else {
        for byte in &mut out[full..] { *byte = 0; }
    }
    Ipv6Addr(out)
}
