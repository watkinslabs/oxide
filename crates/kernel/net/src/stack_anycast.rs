// IPv6 anycast device ownership.  Linux keeps this independent from both
// unicast addresses and multicast/MLD subscriptions: several sockets may
// acquire one address on one device, and the address remains local until the
// final reference leaves.

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnycastAddr {
    pub(crate) addr: Ipv6Addr,
    refs: usize,
}

impl NetStack {
    /// True when an address is configured on any device in this namespace.
    /// An ordinary IPv6 address cannot become an anycast address. # C: O(N)
    pub(crate) fn v6_addr_owned_in(&self, net_ns: u64, addr: Ipv6Addr) -> bool {
        let now_ns = self.ra_now_ns();
        self.v6_addrs.lock().iter().any(|(iface, rows)| {
            self.ifaces.namespace(*iface) == Some(net_ns)
                && rows.iter().any(|row| row.addr == addr && row.usable_at(now_ns))
        })
    }

    /// True when `addr` belongs to one configured prefix on `iface`.
    /// Link-local anycast is valid without a separately configured prefix. # C: O(N)
    pub(crate) fn v6_anycast_prefix_on_iface(&self, iface: NetIfaceId, addr: Ipv6Addr) -> bool {
        if addr.is_link_local() { return true; }
        let now_ns = self.ra_now_ns();
        self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter().any(|row| {
            row.usable_at(now_ns) && prefix_matches(row.addr, addr, row.prefixlen)
        }))
    }

    /// Acquire device-local IPv6 anycast ownership.  Caller holds RTNL and
    /// has resolved a live interface in `net_ns`. # C: O(N addresses)
    pub(crate) fn v6_anycast_acquire(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
                                     iface: NetIfaceId, addr: Ipv6Addr) -> NetResult<()> {
        if self.ifaces.control_generation_in_ns(rtnl, iface, net_ns).is_none() {
            return Err(NetError::Enodev);
        }
        let mut all = self.v6_anycast.lock();
        let rows = all.entry(iface).or_default();
        if let Some(row) = rows.iter_mut().find(|row| row.addr == addr) {
            row.refs = row.refs.checked_add(1).ok_or(NetError::Enomem)?;
        } else {
            rows.push(AnycastAddr { addr, refs: 1 });
        }
        Ok(())
    }

    /// Drop one socket's reference to a device-local anycast address.
    /// Device removal may already have discarded the map, matching Linux's
    /// best-effort close after a netdevice disappears. # C: O(N addresses)
    pub(crate) fn v6_anycast_release(&self, iface: NetIfaceId, addr: Ipv6Addr) {
        let _rtnl = self.rtnl_lock();
        let mut all = self.v6_anycast.lock();
        let Some(rows) = all.get_mut(&iface) else { return };
        let Some(index) = rows.iter().position(|row| row.addr == addr) else { return };
        if rows[index].refs > 1 { rows[index].refs -= 1; } else { rows.swap_remove(index); }
        if rows.is_empty() { all.remove(&iface); }
    }

    /// Local-input/NDP ownership for an IPv6 anycast address. # C: O(N)
    pub(crate) fn v6_anycast_owned_by(&self, iface: NetIfaceId, addr: Ipv6Addr) -> bool {
        self.v6_anycast.lock().get(&iface).is_some_and(|rows| rows.iter()
            .any(|row| row.addr == addr && row.refs != 0))
    }

    /// Snapshot live IPv6 anycast addresses in one network namespace. # C: O(N addresses)
    pub fn v6_anycast_snapshot_in(&self, net_ns: u64) -> Vec<(NetIfaceId, Ipv6Addr)> {
        let all = self.v6_anycast.lock();
        let mut rows = Vec::new();
        for (iface, addrs) in all.iter() {
            if self.ifaces.ifindex_in_ns(*iface, net_ns).is_none() { continue; }
            for row in addrs {
                if row.refs != 0 { rows.push((*iface, row.addr)); }
            }
        }
        rows
    }
}

fn prefix_matches(left: Ipv6Addr, right: Ipv6Addr, prefixlen: u8) -> bool {
    let prefixlen = prefixlen.min(128);
    let full = (prefixlen / 8) as usize;
    let rem = prefixlen % 8;
    if left.0[..full] != right.0[..full] { return false; }
    rem == 0 || (left.0[full] & (!0u8 << (8 - rem))) == (right.0[full] & (!0u8 << (8 - rem)))
}
