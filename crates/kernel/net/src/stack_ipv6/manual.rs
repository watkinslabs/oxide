//! Manually configured IPv6 interface addresses: the work functions behind
//! `RTM_NEWADDR` / `RTM_DELADDR` for `AF_INET6`.
//!
//! The rows live in the one IPv6 address table (`NetStack::v6_addrs`) the
//! receive path, source selection, MLD, DAD and the address dumps already
//! read; a manual address is a row in it with `Ipv6AddrOrigin::Static`, never
//! a second table beside it.

extern crate alloc;

use alloc::string::String;

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::control_event::EventKind;
use crate::netdev::iff;
use crate::stack::NetStack;

use super::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr};

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

/// `net.ipv6.conf.all.disable_ipv6` for one live namespace. # C: O(log N)
pub fn ipv6_disabled_in(ns: u64) -> bool {
    crate::sysctl::value_in(ns, crate::net_ns::NetSysctlKey::Ipv6DisableAll)
        .is_some_and(|value| value != 0)
}

impl NetStack {
    /// Whether `addr` is already assigned to `iface`, at any prefix length —
    /// the reference screens `RTM_NEWADDR` by address alone, so a second add
    /// of the same address with a different prefix length is a replace, not a
    /// new row. `None` when the interface left the generation.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn ipv6_addr_present_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                  iface: NetIfaceId, generation: u64, addr: Ipv6Addr)
        -> Option<bool>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        Some(self.v6_addrs.lock().get(&iface)
            .is_some_and(|rows| rows.iter().any(|row| row.addr == addr)))
    }

    /// Insert one manual IPv6 address, tentative when DAD applies to it. The
    /// returned row is what the caller stages as the `RTM_NEWADDR`
    /// notification. `None` when the interface left the named generation.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn add_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                           iface: NetIfaceId, generation: u64, addr: Ipv6Addr,
                                           peer: Option<Ipv6Addr>, prefixlen: u8,
                                           meta: Ipv6AddrMeta, dad: bool)
        -> Option<Ipv6IfaceAddr>
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
            temporary: false,
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
        Some(row)
    }

    /// Apply a `NLM_F_REPLACE` update to an existing manual IPv6 address. The
    /// reference keeps the row's identity, prefix length and DAD state and
    /// rewrites only what the setter restated. `None` when the interface left
    /// the generation or the address is gone.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn modify_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                              iface: NetIfaceId, generation: u64, addr: Ipv6Addr,
                                              peer: Option<Ipv6Addr>, meta: Ipv6AddrMeta)
        -> Option<Ipv6IfaceAddr>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let now_ns = self.ra_now_ns();
        let mut all = self.v6_addrs.lock();
        let row = all.get_mut(&iface)?.iter_mut().find(|row| row.addr == addr)?;
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
        Some(row.clone())
    }

    /// Remove the exact manual IPv6 address/prefix a setter named, returning
    /// the removed row for the `RTM_DELADDR` notification. `None` when the
    /// interface left the generation or no row matches.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn remove_ipv6_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                              iface: NetIfaceId, generation: u64,
                                              addr: Ipv6Addr, prefixlen: u8)
        -> Option<Ipv6IfaceAddr>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let now_ns = self.ra_now_ns();
        let mut all = self.v6_addrs.lock();
        let rows = all.get_mut(&iface)?;
        let index = rows.iter().position(|row| row.addr == addr && row.prefixlen == prefixlen)?;
        let mut removed = rows.remove(index);
        if rows.is_empty() { all.remove(&iface); }
        drop(all);
        super::udp::refresh_lifetimes(&mut removed, now_ns);
        self.routes6.clear_src_hint(iface, addr);
        Some(removed)
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
