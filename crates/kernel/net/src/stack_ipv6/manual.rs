//! Manually configured IPv6 interface addresses: the work functions behind
//! `RTM_NEWADDR` / `RTM_DELADDR` for `AF_INET6`.
//!
//! The rows live in the one IPv6 address table (`NetStack::v6_addrs`) the
//! receive path, source selection, MLD, DAD and the address dumps already
//! read; a manual address is a row in it with `Ipv6AddrOrigin::Static`, never
//! a second table beside it.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::control_event::EventKind;
use crate::mcast_filter::{FilterMode, SourceFilter6};
use crate::mcast_state::V6ReportWork;
use crate::netdev::NetResult;
use crate::netdev::iff;
use crate::route6::{Route6Entry, Route6Origin};
use crate::stack::NetStack;

use super::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr};

const TEMPADDR_RETRIES: usize = 8;
const MCAUTOJOIN_OWNER: usize = usize::MAX;

pub struct Ipv6McAutojoinWork(Option<V6ReportWork>);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ipv6PrefixRouteChange {
    pub removed: Vec<Route6Entry>,
    pub added: Vec<Route6Entry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6AddrChange {
    pub row: Ipv6IfaceAddr,
    pub routes: Ipv6PrefixRouteChange,
}

/// Everything a setter may state about a manual IPv6 address. The kernel-owned
/// bits (`IFA_F_PERMANENT`, `IFA_F_TENTATIVE`, `IFA_F_DADFAILED`,
/// `IFA_F_DEPRECATED`, `IFA_F_TEMPORARY`) are never carried here — they are
/// derived from the row's lifetime, state and origin.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv6AddrMeta {
    /// The masked `IFA_F_*` bits kept verbatim.
    pub user_flags: u32,
    pub proto: u8,
    pub rt_priority: u32,
    /// Seconds, `INFINITY_LIFE_TIME` for a lifetime that never expires.
    pub valid_lft: u32,
    pub preferred_lft: u32,
}

impl Ipv6AddrMeta {
    /// A permanent address with no setter-stated flags. # C: O(1)
    pub const PERMANENT: Self = Self {
        user_flags: 0, proto: 0, rt_priority: 0,
        valid_lft: crate::iface_addr::INFINITY_LIFE_TIME,
        preferred_lft: crate::iface_addr::INFINITY_LIFE_TIME,
    };
}

/// Duplicate Address Detection runs for an address unless the setter said
/// `IFA_F_NODAD` or the device runs no neighbour discovery at all. Matches the
/// reference's immediate-completion path for `IFF_NOARP` / `IFF_LOOPBACK`.
/// # C: O(1)
pub fn dad_applies(dev_flags: u32, user_flags: u32) -> bool {
    if user_flags & crate::iface_addr::IFA_F_NODAD != 0 { return false; }
    dev_flags & (iff::IFF_NOARP | iff::IFF_LOOPBACK) == 0
}

/// The live interface's inherited `net.ipv6.conf.*.disable_ipv6` policy. # C: O(N)
pub fn ipv6_disabled_in(ns: u64, iface: NetIfaceId) -> bool {
    crate::sock::stack().ifaces.ipv6_disabled_in(iface, ns)
}

impl NetStack {
    /// Add the address subsystem's socket-owned multicast membership.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn add_ipv6_mc_autojoin_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
        namespace: &network_namespace::NetworkNamespaceRef, ns: u64, iface: NetIfaceId,
        generation: u64, group: Ipv6Addr) -> NetResult<Ipv6McAutojoinWork>
    {
        let filter = SourceFilter6 { mode: FilterMode::Exclude, sources: Vec::new() };
        self.set_ipv6_multicast_rtnl(rtnl, namespace, ns, generation, MCAUTOJOIN_OWNER,
            iface, group, Ipv6Addr::ANY, Some(&filter)).map(Ipv6McAutojoinWork)
    }

    /// Remove the address subsystem's socket-owned multicast membership.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn remove_ipv6_mc_autojoin_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
        namespace: &network_namespace::NetworkNamespaceRef, ns: u64, iface: NetIfaceId,
        generation: u64, group: Ipv6Addr) -> Ipv6McAutojoinWork
    {
        Ipv6McAutojoinWork(self.release_ipv6_multicast_rtnl(rtnl, Some(namespace), ns,
            generation, MCAUTOJOIN_OWNER, iface, group))
    }

    /// Emit deferred MLD work after the caller releases RTNL. # C: O(N)
    pub fn finish_ipv6_mc_autojoin(&self, work: Ipv6McAutojoinWork) {
        self.finish_v6_multicast(work.0);
    }

    /// The row `iface` already holds for `addr`, at any prefix length — the
    /// reference screens `RTM_NEWADDR` by address alone, so a second add of one
    /// address naming a different prefix length is a replace, not a new row.
    /// The outer `None` means the interface left the named generation; the
    /// inner one means the address is not assigned.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn ipv6_addr_row_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64, iface: NetIfaceId,
                              generation: u64, addr: Ipv6Addr)
        -> Option<Option<Ipv6IfaceAddr>>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        Some(self.v6_addrs.lock().get(&iface)
            .and_then(|rows| rows.iter().find(|row| row.addr == addr).cloned()))
    }

    /// Insert one manual IPv6 address, tentative when DAD applies to it. The
    /// returned row is what the caller stages as the `RTM_NEWADDR`
    /// notification. `None` when the interface left the named generation.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn add_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                           iface: NetIfaceId, generation: u64, addr: Ipv6Addr,
                                           peer: Option<Ipv6Addr>, prefixlen: u8,
                                           meta: Ipv6AddrMeta, dad: bool)
        -> Option<Ipv6AddrChange>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let now_ns = self.ra_now_ns();
        let stamp = crate::iface_addr::now_centisecs();
        let row = Ipv6IfaceAddr {
            addr,
            peer: peer.filter(|peer| *peer != addr),
            prefixlen,
            preferred: meta.preferred_lft,
            valid: meta.valid_lft,
            preferred_until_ns: super::ra::lifetime_deadline(now_ns, meta.preferred_lft),
            valid_until_ns: super::ra::lifetime_deadline(now_ns, meta.valid_lft),
            origin: Ipv6AddrOrigin::Static,
            state: if dad {
                Ipv6AddrState::Tentative { dad_until_ns: None, retry_at_ns: now_ns,
                    retrans_timer_ns: super::ra::DAD_DELAY_NS }
            } else { Ipv6AddrState::Assigned },
            deprecated: meta.preferred_lft == 0,
            temporary: false, temporary_parent: None,
            user_flags: meta.user_flags,
            proto: meta.proto,
            rt_priority: meta.rt_priority,
            cstamp: stamp,
            tstamp: stamp,
            notify_pending: false,
        };
        let mut all = self.v6_addrs.lock();
        let rows = all.entry(iface).or_default();
        match rows.iter().position(|existing| existing.addr == addr) {
            Some(index) => rows[index] = row.clone(),
            None => rows.push(row.clone()),
        }
        drop(all);
        if meta.user_flags & crate::iface_addr::IFA_F_MANAGETEMPADDR != 0 {
            self.sync_managed_tempaddrs_rtnl(rtnl, ns, iface, generation, addr, false);
        }
        let routes = if meta.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE == 0 {
            self.install_ipv6_prefix_route_rtnl(rtnl, ns, iface, addr, prefixlen, true)
        } else { Ipv6PrefixRouteChange::default() };
        Some(Ipv6AddrChange { row, routes })
    }

    /// Apply a `NLM_F_REPLACE` update to an existing manual IPv6 address. The
    /// reference keeps the row's identity, prefix length and DAD state and
    /// rewrites only what the setter restated. `None` when the interface left
    /// the generation or the address is gone.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn modify_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                              iface: NetIfaceId, generation: u64, addr: Ipv6Addr,
                                              peer: Option<Ipv6Addr>, meta: Ipv6AddrMeta)
        -> Option<Ipv6AddrChange>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let now_ns = self.ra_now_ns();
        let mut all = self.v6_addrs.lock();
        let row = all.get_mut(&iface)?.iter_mut().find(|row| row.addr == addr)?;
        let had_prefixroute = row.valid_until_ns == super::ra::INFINITE_DEADLINE
            && row.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE == 0;
        let was_managed = row.user_flags & crate::iface_addr::IFA_F_MANAGETEMPADDR != 0;
        row.user_flags = meta.user_flags;
        row.proto = meta.proto;
        if meta.rt_priority != 0 { row.rt_priority = meta.rt_priority; }
        row.preferred = meta.preferred_lft;
        row.valid = meta.valid_lft;
        row.preferred_until_ns = super::ra::lifetime_deadline(now_ns, meta.preferred_lft);
        row.valid_until_ns = super::ra::lifetime_deadline(now_ns, meta.valid_lft);
        row.deprecated = !row.preferred_at(now_ns);
        row.tstamp = crate::iface_addr::now_centisecs();
        if let Some(peer) = peer.filter(|peer| *peer != addr) { row.peer = Some(peer); }
        let row = row.clone();
        drop(all);
        self.sync_managed_tempaddrs_rtnl(rtnl, ns, iface, generation, addr, was_managed);
        let routes = if row.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE == 0 {
            self.install_ipv6_prefix_route_rtnl(rtnl, ns, iface, addr, row.prefixlen, false)
        } else if had_prefixroute {
            self.cleanup_ipv6_prefix_route_rtnl(rtnl, ns, iface, addr, row.prefixlen)
        } else { Ipv6PrefixRouteChange::default() };
        Some(Ipv6AddrChange { row, routes })
    }

    /// Remove the exact manual IPv6 address/prefix a setter named, returning
    /// the removed row for the `RTM_DELADDR` notification. `None` when the
    /// interface left the generation or no row matches.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn remove_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                              iface: NetIfaceId, generation: u64,
                                              addr: Ipv6Addr, prefixlen: u8)
        -> Option<Ipv6AddrChange>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let now_ns = self.ra_now_ns();
        let mut all = self.v6_addrs.lock();
        let rows = all.get_mut(&iface)?;
        let index = rows.iter().position(|row| row.addr == addr && row.prefixlen == prefixlen)?;
        let mut removed = rows.remove(index);
        rows.retain(|row| row.temporary_parent != Some(addr));
        if rows.is_empty() { all.remove(&iface); }
        drop(all);
        super::addr_table::refresh_lifetimes(&mut removed, now_ns);
        self.routes6.clear_src_hint(iface, addr);
        let routes = if removed.valid_until_ns == super::ra::INFINITE_DEADLINE
            && removed.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE == 0
        {
            self.cleanup_ipv6_prefix_route_rtnl(rtnl, ns, iface, addr, prefixlen)
        } else { Ipv6PrefixRouteChange::default() };
        Some(Ipv6AddrChange { row: removed, routes })
    }

    /// Reconcile the one shared, address-created route for a local prefix.
    /// Static and router-advertisement routes are separate owners and are
    /// never removed here. # Lk: matching stack RTNL held. # C: O(N)
    fn install_ipv6_prefix_route_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
        iface: NetIfaceId, addr: Ipv6Addr, prefixlen: u8, preserve_existing: bool)
        -> Ipv6PrefixRouteChange
    {
        if self.ifaces.control_ready_in_ns(rtnl, iface, ns).is_none() {
            return Ipv6PrefixRouteChange::default();
        }
        let prefix = super::ra::canonical_prefix(addr, prefixlen);
        let existing = self.routes6.snapshot_in(ns).into_iter().find(|route| {
            route.iface == iface && route.table == crate::policy_rule::RT_TABLE_MAIN
                && route.prefix_len == prefixlen && route.dst == prefix
                && route.origin.is_address_prefix()
        });
        let eligible = self.v6_addrs.lock().get(&iface).into_iter().flatten()
            .filter(|row| row.prefixlen == prefixlen
                && super::ra::canonical_prefix(row.addr, row.prefixlen) == prefix
                && row.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE == 0)
            .cloned().collect::<Vec<_>>();
        let replacement = eligible.first().map(|first| {
            let selected = eligible.iter().find(|row| row.addr == addr).unwrap_or(first);
            let metric = if preserve_existing {
                existing.map(|route| route.origin.metric()).unwrap_or_else(|| {
                    if selected.rt_priority == 0 { crate::route6::IP6_RT_PRIO_ADDRCONF }
                    else { selected.rt_priority }
                })
            } else if selected.rt_priority == 0 { crate::route6::IP6_RT_PRIO_ADDRCONF }
            else { selected.rt_priority };
            Route6Entry { table: crate::policy_rule::RT_TABLE_MAIN, dst: prefix,
                prefix_len: prefixlen, iface, gateway: None, src_hint: None,
                origin: Route6Origin::AddressPrefix { metric,
                    valid_until_ns: eligible.iter().map(|row| row.valid_until_ns).max().unwrap() } }
        });
        if existing == replacement { return Ipv6PrefixRouteChange::default(); }
        let added = replacement.into_iter().collect::<Vec<_>>();
        let removed = self.routes6.replace_in_changes(ns, |route| {
            route.iface == iface && route.table == crate::policy_rule::RT_TABLE_MAIN
                && route.prefix_len == prefixlen && route.dst == prefix
                && route.origin.is_address_prefix()
        }, added.clone());
        Ipv6PrefixRouteChange { removed, added }
    }

    /// Apply the permanent-address prefix cleanup ladder after one row stops
    /// owning its route. # Lk: matching stack RTNL held. # C: O(N)
    fn cleanup_ipv6_prefix_route_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
        iface: NetIfaceId, removed_addr: Ipv6Addr, prefixlen: u8) -> Ipv6PrefixRouteChange
    {
        if self.ifaces.control_ready_in_ns(rtnl, iface, ns).is_none() {
            return Ipv6PrefixRouteChange::default();
        }
        let prefix = super::ra::canonical_prefix(removed_addr, prefixlen);
        let existing = self.routes6.snapshot_in(ns).into_iter().find(|route| {
            route.iface == iface && route.table == crate::policy_rule::RT_TABLE_MAIN
                && route.prefix_len == prefixlen && route.dst == prefix
                && route.origin.is_address_prefix()
        });
        let Some(existing) = existing else { return Ipv6PrefixRouteChange::default() };
        let peers = self.v6_addrs.lock().get(&iface).into_iter().flatten().filter(|row| {
            row.addr != removed_addr && row.prefixlen == prefixlen
                && super::ra::canonical_prefix(row.addr, row.prefixlen) == prefix
        }).cloned().collect::<Vec<_>>();
        if peers.iter().any(|row| row.valid_until_ns == super::ra::INFINITE_DEADLINE
            || row.user_flags & crate::iface_addr::IFA_F_NOPREFIXROUTE != 0)
        {
            return Ipv6PrefixRouteChange::default();
        }
        let replacement = peers.iter().map(|row| row.valid_until_ns).max().map(|deadline| {
            let mut route = existing;
            route.origin = Route6Origin::AddressPrefix {
                metric: existing.origin.metric(), valid_until_ns: deadline };
            route
        });
        if replacement == Some(existing) { return Ipv6PrefixRouteChange::default(); }
        let added = replacement.into_iter().collect::<Vec<_>>();
        let removed = self.routes6.replace_in_changes(ns, |route| *route == existing, added.clone());
        Ipv6PrefixRouteChange { removed, added }
    }

    /// Stage route notifications caused by one address mutation. # C: O(1)
    pub fn stage_ipv6_prefix_route_change_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
        lease: &crate::netdev::IngressLease, change: Ipv6PrefixRouteChange) -> Vec<u64>
    {
        let mut tickets = Vec::new();
        if let Some(ticket) = self.stage_route6(rtnl, lease, EventKind::Delete, change.removed) {
            tickets.push(ticket);
        }
        if let Some(ticket) = self.stage_route6(rtnl, lease, EventKind::New, change.added) {
            tickets.push(ticket);
        }
        tickets
    }

    /// Synchronize RFC 4941 children after a public address add or replace.
    /// # Lk: matching stack RTNL held. # C: O(N + retry count)
    fn sync_managed_tempaddrs_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
        iface: NetIfaceId, generation: u64, parent: Ipv6Addr, was_managed: bool)
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) { return; }
        let Some((use_tempaddr, max_valid, max_preferred)) =
            self.ifaces.ipv6_tempaddr_policy_in(iface, ns) else { return };
        let mut candidates = [[0u8; 8]; TEMPADDR_RETRIES];
        for candidate in &mut candidates { crng::fill(candidate); }
        let now_ns = self.ra_now_ns();
        let stamp = crate::iface_addr::now_centisecs();
        let mut all = self.v6_addrs.lock();
        let Some(rows) = all.get_mut(&iface) else { return };
        let Some(public) = rows.iter().find(|row| row.addr == parent && !row.temporary).cloned()
            else { return };
        let managed = public.user_flags & crate::iface_addr::IFA_F_MANAGETEMPADDR != 0;
        if was_managed && !managed {
            rows.retain(|row| row.temporary_parent != Some(parent));
            return;
        }
        if !managed { return; }
        let valid = public.valid.min(max_valid);
        let preferred = public.preferred.min(max_preferred).min(valid);
        for child in rows.iter_mut().filter(|row| row.temporary_parent == Some(parent)) {
            child.valid = valid;
            child.preferred = preferred;
            child.valid_until_ns = super::ra::lifetime_deadline(now_ns, valid);
            child.preferred_until_ns = super::ra::lifetime_deadline(now_ns, preferred);
            child.deprecated = preferred == 0;
            child.tstamp = stamp;
        }
        if use_tempaddr <= 0 || valid == 0 || preferred == 0
            || rows.iter().any(|row| row.temporary_parent == Some(parent)) { return; }
        for iid in candidates {
            let mut bytes = parent.0;
            bytes[8..].copy_from_slice(&iid);
            let addr = Ipv6Addr(bytes);
            if rows.iter().any(|row| row.addr == addr) { continue; }
            rows.push(Ipv6IfaceAddr {
                addr, peer: None, prefixlen: 64, preferred, valid,
                preferred_until_ns: super::ra::lifetime_deadline(now_ns, preferred),
                valid_until_ns: super::ra::lifetime_deadline(now_ns, valid),
                origin: Ipv6AddrOrigin::Static,
                state: Ipv6AddrState::Tentative { dad_until_ns: None, retry_at_ns: now_ns,
                    retrans_timer_ns: super::ra::DAD_DELAY_NS },
                deprecated: false, temporary: true, temporary_parent: Some(parent),
                user_flags: public.user_flags & crate::iface_addr::IFA_F_OPTIMISTIC,
                proto: public.proto, rt_priority: 0, cstamp: stamp, tstamp: stamp,
                notify_pending: false,
            });
            break;
        }
    }

    /// Stage one manual IPv6 address event for post-RTNL publication.
    /// # Lk: matching stack RTNL held. # C: O(1)
    pub fn stage_addr6_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                            lease: &crate::netdev::IngressLease, label: String,
                            kind: EventKind, row: Ipv6IfaceAddr) -> Option<u64> {
        self.stage_addr6(rtnl, lease, label, kind, row)
    }

    /// Probe DAD for a manual address the moment it is published, rather than
    /// waiting for the next control tick. # C: O(N)
    /// # Ctx: schedulable process context
    pub fn start_manual_dad(&self, iface: NetIfaceId, addr: Ipv6Addr) {
        self.try_dad_probe(iface, addr, self.ra_now_ns());
    }
}
