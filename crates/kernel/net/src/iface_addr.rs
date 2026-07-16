extern crate alloc;

// Module manifest: `tests` owns IPv4 interface-address lifecycle coverage.
#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use sync::{Spinlock, Socket as SockLockClass};

use crate::{Ipv4Addr, NetIfaceId};

pub const IFA_F_PERMANENT: u32 = 0x80;
pub const IFA_F_DADFAILED: u32 = 0x08;
pub const IFA_F_DEPRECATED: u32 = 0x20;
pub const IFA_F_TENTATIVE: u32 = 0x40;
pub const INFINITY_LIFE_TIME: u32 = u32::MAX;
pub const RT_SCOPE_HOST: u8 = 254;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4AddrCacheInfo {
    pub preferred: u32,
    pub valid:     u32,
    pub cstamp:    u32,
    pub tstamp:    u32,
}

impl Ipv4AddrCacheInfo {
    pub const PERMANENT: Self = Self {
        preferred: INFINITY_LIFE_TIME,
        valid:     INFINITY_LIFE_TIME,
        cstamp:    0,
        tstamp:    0,
    };
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4IfaceAddr {
    pub ns:        u64,
    pub iface:     NetIfaceId,
    pub addr:      Ipv4Addr,
    pub peer:      Option<Ipv4Addr>,
    pub prefixlen: u8,
    pub mask:      u32,
    pub broadcast: Option<Ipv4Addr>,
    pub scope:     u8,
    pub flags:     u32,
    pub cacheinfo: Ipv4AddrCacheInfo,
}

impl Ipv4IfaceAddr {
    /// Linux `IFA_ADDRESS`: peer endpoint for point-to-point rows, local otherwise. # C: O(1)
    pub fn address(&self) -> Ipv4Addr { self.peer.unwrap_or(self.addr) }
}

static IPV4_ADDRS: Spinlock<Vec<Ipv4IfaceAddr>, SockLockClass> = Spinlock::new(Vec::new());

fn primary_addr(rows: &[Ipv4IfaceAddr], ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
    rows.iter().find(|r| r.ns == ns && r.iface == iface && !r.addr.is_unspecified())
        .map(|r| r.addr)
}

fn mask_from_prefix(prefixlen: u8) -> u32 {
    let prefixlen = prefixlen.min(32);
    if prefixlen == 0 { 0 } else { !0u32 << (32 - prefixlen) }
}

fn prefix_from_mask(mask: u32) -> u8 {
    if mask == 0 { 0 } else { 32 - mask.trailing_zeros() as u8 }
}

/// Insert or replace by `(ns, iface, addr, prefixlen)`.
/// # C: O(N)
pub fn insert(row: Ipv4IfaceAddr) {
    let mut g = IPV4_ADDRS.lock();
    let dup = g.iter().position(|r| {
        r.ns == row.ns && r.iface == row.iface && r.addr == row.addr && r.prefixlen == row.prefixlen
    });
    if let Some(i) = dup { g[i] = row; } else { g.push(row); }
}

/// Set an interface's primary IPv4 address, preserving its existing
/// netmask/prefix when present. # C: O(N)
pub fn set_primary_addr(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, scope: u8) {
    set_primary_addr_row(ns, iface, addr, scope);
}

fn set_primary_addr_row(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, scope: u8) {
    let mut g = IPV4_ADDRS.lock();
    if let Some(r) = g.iter_mut().find(|r| r.ns == ns && r.iface == iface) {
        r.addr = addr;
        r.peer = None;
        r.scope = scope;
    } else {
        g.push(Ipv4IfaceAddr {
            ns,
            iface,
            addr,
            peer: None,
            prefixlen: 0,
            mask: 0,
            broadcast: None,
            scope,
            flags: IFA_F_PERMANENT,
            cacheinfo: Ipv4AddrCacheInfo::PERMANENT,
        });
    }
}

/// Set an interface's primary IPv4 netmask, preserving the existing address.
/// # C: O(N)
pub fn set_primary_mask(ns: u64, iface: NetIfaceId, mask: u32) -> bool {
    set_primary_mask_row(ns, iface, mask)
}

fn set_primary_mask_row(ns: u64, iface: NetIfaceId, mask: u32) -> bool {
    let mut g = IPV4_ADDRS.lock();
    if let Some(r) = g.iter_mut().find(|r| r.ns == ns && r.iface == iface) {
        r.mask = mask;
        r.prefixlen = prefix_from_mask(mask);
        return true;
    }
    false
}

/// Deferred device update for an RTNL-committed primary IPv4 address.
pub struct Ipv4AddrEffect {
    effect: crate::netdev::ControlEffectLease,
    addr: Option<Ipv4Addr>,
}

impl Ipv4AddrEffect {
    /// Publish device-private state after releasing RTNL. # C: O(device runtime lookup)
    pub fn publish(self) { self.effect.apply_ipv4(self.addr); }
}

/// Set/replace from an rtnetlink prefix. # C: O(N)
pub fn set_prefix(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8, scope: u8) {
    set_prefix_meta(ns, iface, addr, None, prefixlen, scope, IFA_F_PERMANENT,
        Ipv4AddrCacheInfo::PERMANENT);
}

/// Set/replace from an rtnetlink prefix with Linux address metadata. # C: O(N)
pub fn set_prefix_meta(
    ns: u64,
    iface: NetIfaceId,
    addr: Ipv4Addr,
    peer: Option<Ipv4Addr>,
    prefixlen: u8,
    scope: u8,
    flags: u32,
    cacheinfo: Ipv4AddrCacheInfo,
) {
    set_prefix_meta_row(ns, iface, addr, peer, prefixlen, scope, flags, cacheinfo);
}

pub(crate) fn set_prefix_meta_row(ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                                  peer: Option<Ipv4Addr>, prefixlen: u8, scope: u8,
                                  flags: u32, cacheinfo: Ipv4AddrCacheInfo) {
    insert(Ipv4IfaceAddr {
        ns,
        iface,
        addr,
        peer: peer.filter(|peer| *peer != addr),
        prefixlen: prefixlen.min(32),
        mask: mask_from_prefix(prefixlen),
        broadcast: None,
        scope,
        flags,
        cacheinfo,
    });
}

impl crate::NetStack {
    /// Stage generation-exact IPv4 prefix metadata under matching RTNL. # C: O(N)
    pub fn set_ipv4_prefix_meta_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                                 iface: NetIfaceId, generation: u64,
                                                 addr: Ipv4Addr, peer: Option<Ipv4Addr>,
                                                 prefixlen: u8, scope: u8, flags: u32,
                                                 cacheinfo: Ipv4AddrCacheInfo)
        -> Option<Ipv4AddrEffect>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let effect = self.ifaces.admit_control_effect_in_ns(rtnl, iface, ns)?;
        set_prefix_meta_row(ns, iface, addr, peer, prefixlen, scope, flags, cacheinfo);
        let addr = primary_addr(&IPV4_ADDRS.lock(), ns, iface);
        Some(Ipv4AddrEffect { effect, addr })
    }

    /// Stage a generation-exact primary IPv4 mutation under matching RTNL. # C: O(N)
    pub fn set_primary_ipv4_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                             iface: NetIfaceId, generation: u64,
                                             addr: Ipv4Addr, scope: u8)
        -> Option<Ipv4AddrEffect>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let effect = self.ifaces.admit_control_effect_in_ns(rtnl, iface, ns)?;
        set_primary_addr_row(ns, iface, addr, scope);
        Some(Ipv4AddrEffect { effect, addr: Some(addr) })
    }

    /// Apply a generation-exact primary IPv4 mask under matching RTNL. # C: O(N)
    pub fn set_primary_ipv4_mask_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                                  iface: NetIfaceId, generation: u64,
                                                  mask: u32) -> bool {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return false;
        }
        set_primary_mask_row(ns, iface, mask)
    }

    /// Set explicit IPv4 broadcast state under generation-checked RTNL. # C: O(N)
    pub fn set_ipv4_broadcast_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                               iface: NetIfaceId, generation: u64,
                                               broadcast: Ipv4Addr) -> bool {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return false;
        }
        let mut rows = IPV4_ADDRS.lock();
        let Some(row) = rows.iter_mut().find(|r| r.ns == ns && r.iface == iface
            && !r.addr.is_unspecified()) else { return false };
        row.broadcast = Some(broadcast);
        true
    }

    /// Set primary IPv4 address if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_primary_ipv4_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                               scope: u8) -> bool {
        let effect = {
            let rtnl = self.rtnl_lock();
            let Some(effect) = self.ifaces.admit_control_effect_in_ns(&rtnl, iface, ns)
                else { return false };
            set_primary_addr_row(ns, iface, addr, scope);
            effect
        };
        effect.apply_ipv4(Some(addr));
        true
    }

    /// Set primary IPv4 mask if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_primary_ipv4_mask_in(&self, ns: u64, iface: NetIfaceId, mask: u32) -> bool {
        let rtnl = self.rtnl_lock();
        if self.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() { return false; }
        set_primary_mask_row(ns, iface, mask)
    }

    /// Set IPv4 prefix metadata if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_ipv4_prefix_meta_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                                   peer: Option<Ipv4Addr>, prefixlen: u8, scope: u8, flags: u32,
                                   cacheinfo: Ipv4AddrCacheInfo) -> bool {
        let (effect, primary) = {
            let rtnl = self.rtnl_lock();
            let Some(effect) = self.ifaces.admit_control_effect_in_ns(&rtnl, iface, ns)
                else { return false };
            set_prefix_meta_row(ns, iface, addr, peer, prefixlen, scope, flags, cacheinfo);
            (effect, primary_addr(&IPV4_ADDRS.lock(), ns, iface))
        };
        effect.apply_ipv4(primary);
        true
    }

    /// Remove an exact IPv4 prefix and stage the resulting primary-address device state.
    /// # Lk: matching stack RTNL held. # C: O(N)
    pub fn remove_ipv4_prefix_generation_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64,
                                               iface: NetIfaceId, generation: u64,
                                               addr: Ipv4Addr, address: Option<Ipv4Addr>,
                                               prefixlen: u8)
        -> Option<(Ipv4IfaceAddr, Ipv4AddrEffect)>
    {
        if self.ifaces.control_generation_in_ns(rtnl, iface, ns) != Some(generation) {
            return None;
        }
        let effect = self.ifaces.admit_control_effect_in_ns(rtnl, iface, ns)?;
        let mut rows = IPV4_ADDRS.lock();
        let pos = rows.iter().position(|r| {
            r.ns == ns && r.iface == iface && r.addr == addr && r.prefixlen == prefixlen
                && address.is_none_or(|address| r.address() == address)
        })?;
        let removed = rows.remove(pos);
        let next = primary_addr(&rows, ns, iface);
        drop(rows);
        Some((removed, Ipv4AddrEffect { effect, addr: next }))
    }

    /// Remove IPv4 prefix after control-ready revalidation in `ns`. # C: O(N)
    pub fn remove_ipv4_prefix_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                                 prefixlen: u8) -> Option<usize> {
        let rtnl = self.rtnl_lock();
        self.ifaces.control_ready_in_ns(&rtnl, iface, ns)?;
        Some(remove(ns, iface, addr, prefixlen))
    }
}

/// Remove rows matching `(ns, iface, addr, prefixlen)`. # C: O(N)
pub fn remove(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8) -> usize {
    let mut g = IPV4_ADDRS.lock();
    let before = g.len();
    g.retain(|r| !(r.ns == ns && r.iface == iface && r.addr == addr && r.prefixlen == prefixlen));
    before - g.len()
}

/// Remove every IPv4 address row for `iface` in namespace `ns`.
/// # C: O(N)
pub fn remove_iface(ns: u64, iface: NetIfaceId) -> usize {
    take_iface(ns, iface).len()
}

/// Remove and return every exact IPv4 address row for one interface. # C: O(N)
pub(crate) fn take_iface(ns: u64, iface: NetIfaceId) -> Vec<Ipv4IfaceAddr> {
    let mut g = IPV4_ADDRS.lock();
    let mut removed = Vec::new();
    let mut i = 0;
    while i < g.len() {
        if g[i].ns == ns && g[i].iface == iface { removed.push(g.remove(i)); }
        else { i += 1; }
    }
    removed
}

/// Primary address and netmask for ioctl callers. # C: O(N)
pub fn primary(ns: u64, iface: NetIfaceId) -> Option<(Ipv4Addr, u32)> {
    IPV4_ADDRS.lock().iter().find(|r| {
        r.ns == ns && r.iface == iface && !r.addr.is_unspecified()
    }).map(|r| (r.addr, r.mask))
}

/// Return explicit IPv4 broadcast state, or the subnet fallback. # C: O(N)
pub fn broadcast(ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
    IPV4_ADDRS.lock().iter().find(|r| r.ns == ns && r.iface == iface
        && !r.addr.is_unspecified()).map(|r| r.broadcast.unwrap_or(
            Ipv4Addr::from_u32(r.addr.as_u32() | !r.mask)))
}

/// Snapshot rows in network namespace `ns`. # C: O(N)
pub fn snapshot_ns(ns: u64) -> Vec<Ipv4IfaceAddr> {
    IPV4_ADDRS.lock().iter().filter(|r| r.ns == ns).cloned().collect()
}

/// Full snapshot for tests/diagnostics. # C: O(N)
pub fn snapshot() -> Vec<Ipv4IfaceAddr> {
    IPV4_ADDRS.lock().clone()
}

#[cfg(any(test, feature = "hosted"))]
/// Replace one namespace's rows atomically for hosted fixture restoration. # C: O(N)
pub(crate) fn restore_ns(ns: u64, rows: Vec<Ipv4IfaceAddr>) {
    debug_assert!(rows.iter().all(|row| row.ns == ns));
    let mut all = IPV4_ADDRS.lock();
    all.retain(|row| row.ns != ns);
    all.extend(rows);
}
