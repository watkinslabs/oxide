extern crate alloc;

use alloc::{string::String, vec::Vec};

use crate::control_event::{Addr6Event, ControlEvent, EventKind, IfaceOwner, NamespaceOwner,
    Route6Event};
use crate::route6::Route6Entry;
use crate::stack::NetStack;
use super::Ipv6AddrState;

pub(super) struct DadProbe {
    pub(super) namespace: network_namespace::NetworkNamespaceRef,
    pub(super) iface: crate::NetIfaceId,
    pub(super) generation: u64,
    pub(super) target: crate::Ipv6Addr,
    pub(super) retry_at_ns: u64,
}

impl NetStack {
    pub(super) fn ipv6_event_owner(&self, rtnl: &crate::RtnlGuard<'_>,
                                   lease: &crate::netdev::IngressLease) -> Option<IfaceOwner> {
        let generation = self.ifaces.control_generation_in_ns(
            rtnl, lease.iface(), lease.net_ns())?;
        if generation != lease.generation() { return None; }
        Some(IfaceOwner { iface: lease.iface(), generation })
    }

    pub(super) fn stage_addr6(&self, rtnl: &crate::RtnlGuard<'_>,
                              lease: &crate::netdev::IngressLease, label: String,
                              kind: EventKind, row: super::Ipv6IfaceAddr) -> Option<u64> {
        let owner = self.ipv6_event_owner(rtnl, lease)?;
        Some(crate::control_event::stage(rtnl, ControlEvent::Addr6(Addr6Event {
            kind, namespace: NamespaceOwner::Live(lease.namespace()), owner, label, row,
        })))
    }

    pub(super) fn stage_route6(&self, rtnl: &crate::RtnlGuard<'_>,
                               lease: &crate::netdev::IngressLease, kind: EventKind,
                               rows: Vec<Route6Entry>) -> Option<u64> {
        if rows.is_empty() { return None; }
        let owner = self.ipv6_event_owner(rtnl, lease)?;
        Some(crate::control_event::stage(rtnl, ControlEvent::Route6(Route6Event {
            kind, namespace: NamespaceOwner::Live(lease.namespace()),
            owners: alloc::vec![owner], rows,
        })))
    }

    /// Drive IPv6 address/route deadlines from the timer driver's process context. # C: O(N)
    /// # Ctx: schedulable process context
    pub fn ipv6_control_tick(&self, now_ns: u64) {
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            self.ra_now_ns.store(now_ns, core::sync::atomic::Ordering::Release);
            self.routes6.set_now_ns(now_ns);
        }
        let advertisements = core::mem::take(&mut *self.v6_ra_pending.lock());
        for pending in advertisements {
            let Some(lease) = self.ifaces.acquire_ingress(pending.iface) else { continue };
            let namespace = lease.namespace();
            if lease.generation() != pending.generation
                || !alloc::sync::Arc::ptr_eq(&namespace, &pending.namespace) { continue; }
            self.apply_router_advertisement_lease(&lease, pending.router,
                &pending.advertisement, || {});
        }
        let probes: Vec<_> = self.v6_addrs.lock().iter().flat_map(|(iface, rows)| rows.iter()
            .filter_map(|row| match row.state {
                Ipv6AddrState::Tentative { dad_until_ns: None, retry_at_ns, .. }
                    if retry_at_ns <= now_ns && row.valid_at(now_ns) => {
                        let lease = self.ifaces.acquire_ingress(*iface)?;
                        Some(DadProbe { namespace: lease.namespace(), iface: *iface,
                            generation: lease.generation(), target: row.addr, retry_at_ns })
                    }
                _ => None,
            })).collect();
        for probe in probes { self.try_dad_retry(&probe, now_ns); }
        let mut candidates: Vec<_> = self.v6_addrs.lock().keys().copied().collect();
        for iface in self.routes6.expired_ifaces(now_ns) {
            if !candidates.contains(&iface) { candidates.push(iface); }
        }
        let leases: Vec<_> = candidates.into_iter()
            .filter_map(|iface| self.ifaces.acquire_ingress(iface)).collect();
        let mut tickets = Vec::new();
        let mut dad_promotions = Vec::new();
        {
            let rtnl = self.rtnl_lock();
            for lease in &leases {
                let Some(owner) = self.ipv6_event_owner(&rtnl, lease) else { continue };
                let Some(label) = self.ifaces.lookup_in_ns(lease.iface(), lease.net_ns())
                    .map(|dev| String::from(dev.name())) else { continue };
                let mut removed = Vec::new();
                let mut changed = Vec::new();
                let mut failed = Vec::new();
                let mut assigned = Vec::new();
                let mut promoted = Vec::new();
                {
                    let mut all = self.v6_addrs.lock();
                    if let Some(rows) = all.get_mut(&lease.iface()) {
                        rows.retain_mut(|row| {
                            super::udp::refresh_slaac_lifetimes(row, now_ns);
                            if !row.valid_at(now_ns) {
                                removed.push(row.clone());
                                return false;
                            }
                            let mut notify = false;
                            if matches!(row.state, Ipv6AddrState::Tentative {
                                dad_until_ns: Some(deadline), .. } if deadline <= now_ns)
                            {
                                row.state = Ipv6AddrState::Assigned;
                                promoted.push(row.addr);
                                if let super::Ipv6AddrOrigin::Slaac { prefix, .. } = row.origin {
                                    assigned.push((prefix, row.addr));
                                }
                                notify = true;
                            }
                            if row.notify_pending {
                                row.notify_pending = false;
                                if row.state == Ipv6AddrState::DadFailed {
                                    failed.push(row.addr);
                                }
                                notify = true;
                            }
                            let deprecated = !row.preferred_at(now_ns);
                            if row.deprecated != deprecated {
                                row.deprecated = deprecated;
                                notify = true;
                            }
                            if notify { changed.push(row.clone()); }
                            if row.valid_at(now_ns) { return true; }
                            removed.push(row.clone());
                            false
                        });
                        if rows.is_empty() { all.remove(&lease.iface()); }
                    }
                }
                for (prefix, addr) in assigned {
                    self.routes6.activate_slaac_src_hint(lease.iface(), prefix, addr);
                }
                for addr in promoted {
                    dad_promotions.push((lease.iface(), lease.generation(), addr));
                }
                for addr in failed { self.routes6.clear_src_hint(lease.iface(), addr); }
                for row in changed {
                    tickets.push(crate::control_event::stage(&rtnl,
                        ControlEvent::Addr6(Addr6Event {
                            kind: EventKind::New,
                            namespace: NamespaceOwner::Live(lease.namespace()), owner,
                            label: label.clone(), row,
                        })));
                }
                for row in removed {
                    self.routes6.clear_src_hint(lease.iface(), row.addr);
                    tickets.push(crate::control_event::stage(&rtnl,
                        ControlEvent::Addr6(Addr6Event {
                            kind: EventKind::Delete,
                            namespace: NamespaceOwner::Live(lease.namespace()), owner,
                            label: label.clone(), row,
                        })));
                }
            }
            let admitted: Vec<_> = leases.iter().map(|lease| lease.iface()).collect();
            let expired_routes = self.routes6.take_expired_rtnl(&rtnl, now_ns, &admitted);
            for lease in &leases {
                let rows: Vec<_> = expired_routes.iter().filter_map(|(net_ns, row)| {
                    (*net_ns == lease.net_ns() && row.iface == lease.iface()).then_some(*row)
                }).collect();
                if let Some(ticket) = self.stage_route6(&rtnl, lease, EventKind::Delete, rows) {
                    tickets.push(ticket);
                }
            }
        }
        if let Some(ticket) = tickets.last().copied() { crate::control_event::publish(ticket); }
        for (iface, generation, addr) in dad_promotions {
            self.mld_link_local_dad_complete(iface, generation, addr);
        }
    }

    /// Mark a validated DAD duplicate without RTNL or notification publication. # C: O(N)
    /// # Ctx: IRQ/NAPI safe
    pub(crate) fn dad_duplicate_ingress(&self, iface: crate::NetIfaceId,
                                        target: crate::Ipv6Addr) {
        let mut all = self.v6_addrs.lock();
        let Some(row) = all.get_mut(&iface).and_then(|rows| rows.iter_mut()
            .find(|row| row.addr == target)) else { return };
        if !matches!(row.state, Ipv6AddrState::Tentative { .. }) { return; }
        row.state = Ipv6AddrState::DadFailed;
        row.notify_pending = true;
    }

    /// Queue validated RA work without acquiring RTNL or publishing notifications. # C: O(1)
    /// # Ctx: IRQ/NAPI safe
    pub(crate) fn queue_router_advertisement_ingress(&self, net_ns: u64,
        iface: crate::NetIfaceId, router: crate::Ipv6Addr,
        advertisement: crate::ndp::RouterAdvertisement)
    {
        let Some(lease) = self.ifaces.acquire_ingress(iface) else { return };
        if lease.net_ns() != net_ns { return; }
        self.v6_ra_pending.lock().push(super::types::PendingRa {
            namespace: lease.namespace(), iface, generation: lease.generation(),
            router, advertisement,
        });
    }

    pub(super) fn dad_probe_for(&self, lease: &crate::IngressLease,
                                target: crate::Ipv6Addr) -> Option<DadProbe> {
        let all = self.v6_addrs.lock();
        let row = all.get(&lease.iface())?.iter().find(|row| row.addr == target)?;
        let Ipv6AddrState::Tentative { dad_until_ns: None, retry_at_ns, .. } = row.state
            else { return None };
        Some(DadProbe { namespace: lease.namespace(), iface: lease.iface(),
            generation: lease.generation(), target, retry_at_ns })
    }

    pub(super) fn try_dad_probe(&self, iface: crate::NetIfaceId, target: crate::Ipv6Addr,
                                now_ns: u64) {
        let Some(lease) = self.ifaces.acquire_ingress(iface) else { return };
        let Some(probe) = self.dad_probe_for(&lease, target) else { return };
        self.try_dad_retry(&probe, now_ns);
    }

    pub(super) fn try_dad_retry(&self, probe: &DadProbe, now_ns: u64) {
        let Some(lease) = self.ifaces.acquire_ingress(probe.iface) else { return };
        if lease.generation() != probe.generation
            || !alloc::sync::Arc::ptr_eq(&lease.namespace(), &probe.namespace) { return; }
        {
            let all = self.v6_addrs.lock();
            let Some(row) = all.get(&probe.iface).and_then(|rows| rows.iter()
                .find(|row| row.addr == probe.target)) else { return };
            if !row.valid_at(now_ns) || !matches!(row.state, Ipv6AddrState::Tentative {
                dad_until_ns: None, retry_at_ns, .. } if retry_at_ns == probe.retry_at_ns
                    && retry_at_ns <= now_ns) { return; }
        }
        let sent = self.send_dad_solicitation(&lease, probe.target).unwrap_or(false);
        let mut all = self.v6_addrs.lock();
        let Some(row) = all.get_mut(&probe.iface).and_then(|rows| rows.iter_mut()
            .find(|row| row.addr == probe.target)) else { return };
        let Ipv6AddrState::Tentative {
            dad_until_ns, retry_at_ns, retrans_timer_ns,
        } = &mut row.state else { return };
        if dad_until_ns.is_some() || *retry_at_ns != probe.retry_at_ns { return; }
        if sent { *dad_until_ns = Some(now_ns.saturating_add(*retrans_timer_ns)); }
        else { *retry_at_ns = now_ns.saturating_add(*retrans_timer_ns); }
    }

    pub(crate) fn v6_select_source_current(&self, iface: crate::NetIfaceId,
        dst: crate::Ipv6Addr, hint: Option<crate::Ipv6Addr>, prefs: i32) -> Option<crate::Ipv6Addr>
    {
        let now_ns = self.ra_now_ns();
        let all = self.v6_addrs.lock();
        let addrs = all.get(&iface)?;
        addrs.iter().filter(|row| row.usable_at(now_ns)).min_by_key(|row| {
            let src_scope = ipv6_scope(row.addr);
            let dst_scope = ipv6_scope(dst);
            let scope_penalty = if src_scope < dst_scope {
                16u8.saturating_add(dst_scope - src_scope)
            } else { src_scope - dst_scope };
            (row.addr != dst, scope_penalty, !row.preferred_at(now_ns),
                source_preference_penalty(row.temporary, prefs), hint != Some(row.addr),
                u8::MAX - common_prefix_len(row.addr, dst))
        }).map(|row| row.addr)
    }
}

fn source_preference_penalty(temporary: bool, prefs: i32) -> bool {
    use crate::sock_opts::sol_ipv6::uapi::{IPV6_PREFER_SRC_PUBLIC, IPV6_PREFER_SRC_TMP};
    if prefs & IPV6_PREFER_SRC_TMP != 0 { return !temporary; }
    if prefs & IPV6_PREFER_SRC_PUBLIC != 0 { return temporary; }
    false
}

fn ipv6_scope(addr: crate::Ipv6Addr) -> u8 {
    if addr.is_multicast() { return addr.0[1] & 0x0f; }
    if addr.is_loopback() || addr.is_unspecified() { return 0; }
    if addr.is_link_local() { 2 } else { 14 }
}

fn common_prefix_len(a: crate::Ipv6Addr, b: crate::Ipv6Addr) -> u8 {
    let mut bits = 0;
    for (left, right) in a.0.iter().zip(b.0.iter()) {
        let different = left ^ right;
        if different != 0 { return bits + different.leading_zeros() as u8; }
        bits += 8;
    }
    bits
}
