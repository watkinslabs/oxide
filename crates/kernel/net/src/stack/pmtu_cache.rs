use alloc::collections::BTreeMap;

use sync::{Socket as StackLockClass, Spinlock};

use crate::addr::{IpAddr, NetIfaceId};

pub(crate) const IPV4_MIN_PMTU: u32 = 512 + 20 + 20;
pub(crate) const PMTU_EXPIRES_NS: u64 = 10 * 60 * 1_000_000_000;
const PMTU_REFRESH_NS: u64 = PMTU_EXPIRES_NS / 2;

type PmtuKey = (NetIfaceId, IpAddr);

#[derive(Copy, Clone)]
struct PmtuEntry {
    mtu: u32,
    expires_ns: u64,
    locked: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct PmtuLookup {
    pub(crate) mtu: u32,
    pub(crate) locked: bool,
}

pub(crate) struct PmtuCache {
    entries: Spinlock<BTreeMap<PmtuKey, PmtuEntry>, StackLockClass>,
}

impl PmtuCache {
    /// Create an empty path-MTU exception cache. # C: O(1)
    pub(crate) fn new() -> Self {
        Self { entries: Spinlock::new(BTreeMap::new()) }
    }

    /// Return effective PMTU state and discard an exception expired at `now_ns`. # C: O(log N)
    pub(crate) fn lookup_at(&self, iface: NetIfaceId, dst: IpAddr, link_mtu: u32,
                            now_ns: u64) -> PmtuLookup {
        let key = (iface, dst);
        let mut entries = self.entries.lock();
        match entries.get(&key).copied() {
            Some(entry) if now_ns < entry.expires_ns => PmtuLookup {
                mtu: entry.mtu.min(link_mtu), locked: entry.locked,
            },
            Some(_) => {
                entries.remove(&key);
                PmtuLookup { mtu: link_mtu, locked: false }
            }
            None => PmtuLookup { mtu: link_mtu, locked: false },
        }
    }

    /// Return effective PMTU state using the production monotonic clock. # C: O(log N)
    pub(crate) fn lookup(&self, iface: NetIfaceId, dst: IpAddr, link_mtu: u32) -> PmtuLookup {
        self.lookup_at(iface, dst, link_mtu, monotonic_ns_safe())
    }

    /// Return effective PMTU using the canonical state lookup. # C: O(log N)
    pub(crate) fn get_at(&self, iface: NetIfaceId, dst: IpAddr, link_mtu: u32,
                         now_ns: u64) -> u32 {
        self.lookup_at(iface, dst, link_mtu, now_ns).mtu
    }

    /// Return effective PMTU using the canonical state lookup. # C: O(log N)
    pub(crate) fn get(&self, iface: NetIfaceId, dst: IpAddr, link_mtu: u32) -> u32 {
        self.lookup(iface, dst, link_mtu).mtu
    }

    /// Apply reduction/floor/refresh policy and return the cached PMTU. # C: O(log N)
    pub(crate) fn update_at(&self, iface: NetIfaceId, dst: IpAddr, reported_mtu: u32,
                            link_mtu: u32, min_mtu: u32, now_ns: u64) -> u32 {
        let key = (iface, dst);
        let mut entries = self.entries.lock();
        if entries.get(&key).is_some_and(|entry| now_ns >= entry.expires_ns) {
            entries.remove(&key);
        }

        let old_mtu = entries.get(&key).map_or(link_mtu, |entry| entry.mtu.min(link_mtu));
        if old_mtu < reported_mtu { return old_mtu; }
        if entries.get(&key).is_some_and(|entry| entry.locked) { return old_mtu; }
        let locked = reported_mtu < min_mtu;
        let mtu = if locked { old_mtu.min(min_mtu) } else { reported_mtu };
        if let Some(entry) = entries.get(&key).copied() {
            if mtu > entry.mtu { return old_mtu; }
            if mtu == entry.mtu && !locked
                && now_ns < entry.expires_ns.saturating_sub(PMTU_REFRESH_NS)
            {
                return old_mtu;
            }
        }

        entries.insert(key, PmtuEntry {
            mtu,
            expires_ns: now_ns.saturating_add(PMTU_EXPIRES_NS),
            locked,
        });
        mtu
    }

    /// Apply reduction/floor/refresh policy using the production monotonic clock. # C: O(log N)
    pub(crate) fn update(&self, iface: NetIfaceId, dst: IpAddr, reported_mtu: u32,
                         link_mtu: u32, min_mtu: u32) -> u32 {
        self.update_at(iface, dst, reported_mtu, link_mtu, min_mtu, monotonic_ns_safe())
    }

    /// Drop every cached destination learned through one departing interface. # C: O(N)
    pub(crate) fn remove_iface(&self, iface: NetIfaceId) -> usize {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|(entry_iface, _), _| *entry_iface != iface);
        before - entries.len()
    }
}

/// Read monotonic nanoseconds without imposing a hosted wall-clock dependency. # C: O(1)
fn monotonic_ns_safe() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Ipv4Addr, Ipv6Addr};

    const LINK_MTU: u32 = 1_500;
    const START_NS: u64 = 7_000_000_000;

    fn v4(a: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(192, 0, 2, a)) }

    #[test]
    fn keys_include_interface_and_destination() {
        let cache = PmtuCache::new();
        let first = NetIfaceId::from_raw(1);
        let second = NetIfaceId::from_raw(2);
        cache.update_at(first, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        assert_eq!(cache.get_at(first, v4(1), LINK_MTU, START_NS), 1_400);
        assert_eq!(cache.get_at(second, v4(1), LINK_MTU, START_NS), LINK_MTU);
        assert_eq!(cache.get_at(first, v4(2), LINK_MTU, START_NS), LINK_MTU);
    }

    #[test]
    fn removing_interface_drops_all_destination_exceptions() {
        let cache = PmtuCache::new();
        let removed = NetIfaceId::from_raw(1);
        let retained = NetIfaceId::from_raw(2);
        cache.update_at(removed, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        cache.update_at(removed, v4(2), 1_300, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        cache.update_at(retained, v4(1), 1_200, LINK_MTU, IPV4_MIN_PMTU, START_NS);

        assert_eq!(cache.remove_iface(removed), 2);
        assert_eq!(cache.get_at(removed, v4(1), LINK_MTU, START_NS), LINK_MTU);
        assert_eq!(cache.get_at(removed, v4(2), LINK_MTU, START_NS), LINK_MTU);
        assert_eq!(cache.get_at(retained, v4(1), LINK_MTU, START_NS), 1_200);
    }

    #[test]
    fn expiry_is_exact_and_lookup_removes_entry() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU,
            START_NS + PMTU_EXPIRES_NS - 1), 1_400);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU,
            START_NS + PMTU_EXPIRES_NS), LINK_MTU);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU, START_NS), LINK_MTU);
    }

    #[test]
    fn updates_only_reduce() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        assert_eq!(cache.update_at(iface, v4(1), 1_450, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + 1), 1_400);
        assert_eq!(cache.update_at(iface, v4(1), 1_300, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + 2), 1_300);
    }

    #[test]
    fn equal_value_refreshes_after_half_life() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + PMTU_REFRESH_NS - 1);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU,
            START_NS + PMTU_EXPIRES_NS), LINK_MTU);

        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + PMTU_EXPIRES_NS + 1);
        cache.update_at(iface, v4(1), 1_400, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + PMTU_EXPIRES_NS + 1 + PMTU_REFRESH_NS);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU,
            START_NS + 2 * PMTU_EXPIRES_NS + 1), 1_400);
    }

    #[test]
    fn floor_locks_until_expiry() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        assert_eq!(cache.update_at(iface, v4(1), 296, LINK_MTU, IPV4_MIN_PMTU, START_NS),
            IPV4_MIN_PMTU);
        cache.update_at(iface, v4(1), 200, LINK_MTU, IPV4_MIN_PMTU,
            START_NS + PMTU_REFRESH_NS);
        assert_eq!(cache.get_at(iface, v4(1), LINK_MTU,
            START_NS + PMTU_EXPIRES_NS), LINK_MTU);
    }

    #[test]
    fn below_floor_update_exposes_lock_state() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        cache.update_at(iface, v4(1), 296, LINK_MTU, IPV4_MIN_PMTU, START_NS);
        assert_eq!(cache.lookup_at(iface, v4(1), LINK_MTU, START_NS), PmtuLookup {
            mtu: IPV4_MIN_PMTU, locked: true,
        });
        assert_eq!(cache.lookup_at(iface, v4(1), LINK_MTU,
            START_NS + PMTU_EXPIRES_NS), PmtuLookup { mtu: LINK_MTU, locked: false });
    }

    #[test]
    fn generic_floor_and_link_clamp_apply_to_ipv6_keys() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        let dst = IpAddr::V6(Ipv6Addr([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1]));
        assert_eq!(cache.update_at(iface, dst, 900, LINK_MTU, 1_280, START_NS), 1_280);
        assert_eq!(cache.get_at(iface, dst, 1_200, START_NS), 1_200);
    }

    #[test]
    fn report_above_link_mtu_is_not_cached() {
        let cache = PmtuCache::new();
        let iface = NetIfaceId::from_raw(1);
        assert_eq!(cache.update_at(iface, v4(1), 2_000, LINK_MTU, IPV4_MIN_PMTU,
            START_NS), LINK_MTU);
        assert_eq!(cache.get_at(iface, v4(1), 9_000, START_NS), 9_000);
    }
}
