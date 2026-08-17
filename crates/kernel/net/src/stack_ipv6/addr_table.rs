//! The IPv6 interface-address table: the one place a row is inserted,
//! refreshed, expired-against and read back, whatever created it.
//!
//! Split out of `udp` because it is address state, not transport state, and
//! because `udp` reached the file-size cap.

use alloc::vec::Vec;

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::stack::NetStack;

use super::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr};

impl NetStack {
    /// Insert a permanent host address, already verified. # C: O(N)
    pub fn add_v6_addr(&self, iface: NetIfaceId, ip: Ipv6Addr) {
        self.add_v6_addr_meta(iface, ip, 128, u32::MAX, u32::MAX);
    }

    /// Insert a static address with its prefix and lifetimes. # C: O(N)
    pub fn add_v6_addr_meta(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
    ) {
        self.add_v6_addr_meta_with_temporary(iface, ip, prefixlen, valid, preferred, false);
    }

    /// Insert a static IPv6 address with its privacy-address classification.
    /// # C: O(N)
    pub fn add_v6_addr_meta_with_temporary(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
        temporary: bool,
    ) {
        let now_ns = self.ra_now_ns();
        let mut all = self.v6_addrs.lock();
        let addrs = all.entry(iface).or_default();
        let row = Ipv6IfaceAddr {
            addr: ip, peer: None, prefixlen, preferred, valid,
            preferred_until_ns: super::ra::lifetime_deadline(now_ns, preferred),
            valid_until_ns: super::ra::lifetime_deadline(now_ns, valid),
            origin: Ipv6AddrOrigin::Static,
            state: Ipv6AddrState::Assigned, deprecated: preferred == 0, temporary,
            user_flags: 0, proto: 0, rt_priority: 0,
            cstamp: crate::iface_addr::now_centisecs(), tstamp: crate::iface_addr::now_centisecs(),
            notify_pending: false,
        };
        match addrs.iter().position(|addr| addr.addr == ip) {
            Some(i) => addrs[i] = row,
            None => addrs.push(row),
        }
    }

    /// Insert or refresh one autoconfigured address from an advertised prefix.
    /// `None` when a zero valid lifetime withdraws an address we do not hold;
    /// `Some(true)` when the row is new. # C: O(N)
    pub(crate) fn upsert_slaac_addr(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
        prefix: Ipv6Addr,
        now_ns: u64,
        retrans_timer_ns: Option<u64>,
    ) -> Option<bool> {
        let mut all = self.v6_addrs.lock();
        let addrs = all.entry(iface).or_default();
        match addrs.iter_mut().find(|addr| addr.addr == ip) {
            Some(row) => {
                if matches!(row.origin, Ipv6AddrOrigin::Static) { return Some(false); }
                row.valid_until_ns = slaac_valid_deadline(row.valid_until_ns, valid, now_ns);
                row.preferred_until_ns = super::ra::lifetime_deadline(now_ns, preferred);
                refresh_lifetimes(row, now_ns);
                row.deprecated = !row.preferred_at(now_ns);
                row.tstamp = crate::iface_addr::now_centisecs();
                if let (Some(retrans_timer_ns), Ipv6AddrState::Tentative {
                    retrans_timer_ns: current, ..
                }) = (retrans_timer_ns, &mut row.state) { *current = retrans_timer_ns; }
                row.valid_at(now_ns).then_some(false)
            }
            None => {
                if valid == 0 { return None; }
                let stamp = crate::iface_addr::now_centisecs();
                addrs.push(Ipv6IfaceAddr {
                    addr: ip, peer: None, prefixlen, preferred, valid,
                    preferred_until_ns: super::ra::lifetime_deadline(now_ns, preferred),
                    valid_until_ns: super::ra::lifetime_deadline(now_ns, valid),
                    origin: Ipv6AddrOrigin::Slaac { prefix },
                    state: Ipv6AddrState::Tentative {
                        dad_until_ns: None, retry_at_ns: now_ns,
                        retrans_timer_ns: retrans_timer_ns.unwrap_or(super::ra::DAD_DELAY_NS) },
                    deprecated: preferred == 0, temporary: false,
                    user_flags: 0, proto: 0, rt_priority: 0, cstamp: stamp, tstamp: stamp,
                    notify_pending: false,
                });
                Some(true)
            }
        }
    }

    /// Snapshot the initial namespace's IPv6 addresses. # C: O(N)
    pub fn v6_addr_snapshot(&self) -> Vec<(NetIfaceId, Ipv6IfaceAddr)> {
        self.v6_addr_snapshot_in(0)
    }

    /// Snapshot IPv6 interface addresses owned by one network namespace. # C: O(N)
    pub fn v6_addr_snapshot_in(&self, net_ns: u64) -> Vec<(NetIfaceId, Ipv6IfaceAddr)> {
        let now_ns = self.ra_now_ns();
        let mut out = Vec::new();
        for (iface, addrs) in self.v6_addrs.lock().iter() {
            if self.ifaces.namespace(*iface) != Some(net_ns) { continue; }
            for addr in addrs {
                let mut row = addr.clone();
                refresh_lifetimes(&mut row, now_ns);
                out.push((*iface, row));
            }
        }
        out
    }
}

/// Recompute the reported remaining lifetimes from the row's deadlines. Every
/// origin ages the same way: the reference reports `valid_lft`/`prefered_lft`
/// minus the age of the row's update stamp regardless of how it was created.
pub(super) fn refresh_lifetimes(row: &mut Ipv6IfaceAddr, now_ns: u64) {
    row.valid = super::ra::remaining_lifetime(now_ns, row.valid_until_ns);
    row.preferred = super::ra::remaining_lifetime(now_ns, row.preferred_until_ns);
}

fn slaac_valid_deadline(old_deadline_ns: u64, advertised: u32, now_ns: u64) -> u64 {
    let advertised_deadline = super::ra::lifetime_deadline(now_ns, advertised);
    let two_hours_deadline = super::ra::lifetime_deadline(now_ns, super::ra::TWO_HOURS_SECS);
    if advertised > super::ra::TWO_HOURS_SECS || advertised_deadline > old_deadline_ns {
        advertised_deadline
    } else if old_deadline_ns <= two_hours_deadline {
        old_deadline_ns
    } else {
        two_hours_deadline
    }
}
