// Address-lifetime ageing.
//
// The reference stamps an address with the current time when it is installed
// and, on every readback, reports the lifetimes that REMAIN — a permanent
// address reports infinity, and a leased one counts down. Reporting the stored
// lifetimes verbatim tells a DHCP client its lease never expires.

use super::{Ipv4AddrCacheInfo, IFA_F_PERMANENT, INFINITY_LIFE_TIME};

/// `cstamp`/`tstamp` are `clock_t`: hundredths of a second since boot.
pub const CENTISECS_PER_SEC: u64 = 100;

/// Monotonic time in the units `ifa_cacheinfo` stamps carry. # C: O(1)
pub fn now_centisecs() -> u32 {
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::TimerOps;
        #[cfg(target_arch = "x86_64")]
        let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
        #[cfg(target_arch = "aarch64")]
        let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        (ns / (1_000_000_000 / CENTISECS_PER_SEC)) as u32
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Stamp a freshly installed address. The setter states the lifetimes; the
/// timestamps are the kernel's, never the caller's. # C: O(1)
pub fn stamp(ci: Ipv4AddrCacheInfo, now: u32) -> Ipv4AddrCacheInfo {
    Ipv4AddrCacheInfo { preferred: ci.preferred, valid: ci.valid, cstamp: now, tstamp: now }
}

/// The lifetimes that remain, as a readback reports them. # C: O(1)
pub fn age(ci: Ipv4AddrCacheInfo, flags: u32, now: u32) -> Ipv4AddrCacheInfo {
    if flags & IFA_F_PERMANENT != 0 {
        return Ipv4AddrCacheInfo { preferred: INFINITY_LIFE_TIME, valid: INFINITY_LIFE_TIME,
                                   cstamp: ci.cstamp, tstamp: ci.tstamp };
    }
    if ci.preferred == INFINITY_LIFE_TIME {
        return ci;
    }
    let elapsed = (now.wrapping_sub(ci.tstamp) as u64 / CENTISECS_PER_SEC).min(u32::MAX as u64) as u32;
    let preferred = ci.preferred.saturating_sub(elapsed);
    let valid = if ci.valid == INFINITY_LIFE_TIME { ci.valid } else { ci.valid.saturating_sub(elapsed) };
    Ipv4AddrCacheInfo { preferred, valid, cstamp: ci.cstamp, tstamp: ci.tstamp }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE: Ipv4AddrCacheInfo =
        Ipv4AddrCacheInfo { preferred: 3600, valid: 7200, cstamp: 1_000, tstamp: 1_000 };

    #[test]
    fn a_permanent_address_reports_infinity_whatever_was_stored() {
        let stored = Ipv4AddrCacheInfo { preferred: 5, valid: 9, cstamp: 1, tstamp: 1 };
        let out = age(stored, IFA_F_PERMANENT, 500_000);
        assert_eq!((out.preferred, out.valid), (INFINITY_LIFE_TIME, INFINITY_LIFE_TIME));
        // The install timestamps are facts about the address and do not move.
        assert_eq!((out.cstamp, out.tstamp), (1, 1));
    }

    #[test]
    fn a_lease_counts_down_in_whole_seconds() {
        // 1000 centiseconds later is 10 seconds.
        let out = age(LEASE, 0, LEASE.tstamp + 1_000);
        assert_eq!((out.preferred, out.valid), (3590, 7190));
        // Sub-second elapsed time does not move either lifetime.
        let out = age(LEASE, 0, LEASE.tstamp + 99);
        assert_eq!((out.preferred, out.valid), (3600, 7200));
    }

    #[test]
    fn a_lease_that_ran_out_reports_zero_rather_than_wrapping() {
        let out = age(LEASE, 0, LEASE.tstamp + 1_000_000);
        assert_eq!((out.preferred, out.valid), (0, 0));
    }

    #[test]
    fn an_infinite_preferred_lifetime_is_left_alone() {
        let ci = Ipv4AddrCacheInfo { preferred: INFINITY_LIFE_TIME, valid: INFINITY_LIFE_TIME,
                                     cstamp: 7, tstamp: 7 };
        assert_eq!(age(ci, 0, 900_000), ci);
    }

    #[test]
    fn a_valid_lifetime_may_be_infinite_while_preferred_counts_down() {
        let ci = Ipv4AddrCacheInfo { preferred: 100, valid: INFINITY_LIFE_TIME,
                                     cstamp: 0, tstamp: 0 };
        let out = age(ci, 0, 1_000);
        assert_eq!((out.preferred, out.valid), (90, INFINITY_LIFE_TIME));
    }

    #[test]
    fn the_install_stamps_are_the_kernels_not_the_callers() {
        let asked = Ipv4AddrCacheInfo { preferred: 600, valid: 1200, cstamp: 0xdead, tstamp: 0xbeef };
        let out = stamp(asked, 4_242);
        assert_eq!((out.preferred, out.valid), (600, 1200));
        assert_eq!((out.cstamp, out.tstamp), (4_242, 4_242));
    }

    #[test]
    fn ageing_a_freshly_stamped_lease_returns_it_unchanged() {
        let now = 55_000;
        let out = age(stamp(LEASE, now), 0, now);
        assert_eq!((out.preferred, out.valid), (3600, 7200));
    }
}
