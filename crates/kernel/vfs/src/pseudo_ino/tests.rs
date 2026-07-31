// The registry's own contract. `REGIONS_ARE_DISJOINT` already fails the build
// on an overlap; these name WHICH pair overlaps when someone adds one, and pin
// the two collisions that were live before this table existed.

use super::*;

/// The two pairs that were minting into each other's ranges. Named by value so
/// the test states the historical fact rather than restating current consts.
const OLD_SHARED_EPOLL_EVDEV_BASE: Ino = 0x7400_0000;
const OLD_SHARED_TIMERFD_BPF_BASE: Ino = 0x7300_0000;
const OLD_SHARED_CGROUP_DEVPTS_BASE: Ino = 0x6000_0000;

#[test]
fn no_two_regions_overlap() {
    for (i, a) in REGIONS.iter().enumerate() {
        for b in REGIONS.iter().skip(i + 1) {
            assert!(!overlaps(a, b),
                "{} [{:#x}..={:#x}] overlaps {} [{:#x}..={:#x}]",
                a.name(), a.start(), a.end(), b.name(), b.start(), b.end());
        }
    }
}

#[test]
fn every_region_is_non_empty() {
    for r in REGIONS { assert!(r.start() <= r.end(), "{} is empty", r.name()); }
}

#[test]
fn region_names_are_unique() {
    for (i, a) in REGIONS.iter().enumerate() {
        for b in REGIONS.iter().skip(i + 1) {
            assert_ne!(a.name(), b.name(), "duplicate region name {}", a.name());
        }
    }
}

#[test]
fn the_compile_time_check_is_the_same_check() {
    assert!(REGIONS_ARE_DISJOINT);
    assert!(all_disjoint(REGIONS));
}

#[test]
fn an_overlapping_pair_is_rejected() {
    // The check has to actually fail on a collision, or the build-time
    // assertion proves nothing.
    let clash = [Region::new("a", 0x10, 0x20), Region::new("b", 0x20, 0x30)];
    assert!(!all_disjoint(&clash));
    let touching = [Region::new("a", 0x10, 0x1F), Region::new("b", 0x20, 0x30)];
    assert!(all_disjoint(&touching));
}

#[test]
fn exactly_one_region_claims_each_historically_shared_base() {
    for base in [OLD_SHARED_EPOLL_EVDEV_BASE, OLD_SHARED_TIMERFD_BPF_BASE,
                 OLD_SHARED_CGROUP_DEVPTS_BASE] {
        let owners: alloc::vec::Vec<&'static str> =
            REGIONS.iter().filter(|r| r.contains(base)).map(|r| r.name()).collect();
        assert_eq!(owners.len(), 1, "{base:#x} claimed by {owners:?}");
    }
}

#[test]
fn the_moved_owners_left_the_base_they_shared() {
    assert!(!EVDEV.contains(OLD_SHARED_EPOLL_EVDEV_BASE));
    assert!(EPOLL.contains(OLD_SHARED_EPOLL_EVDEV_BASE));
    assert!(!BPF.contains(OLD_SHARED_TIMERFD_BPF_BASE));
    assert!(TIMERFD.contains(OLD_SHARED_TIMERFD_BPF_BASE));
    assert!(!DEVPTS.contains(OLD_SHARED_CGROUP_DEVPTS_BASE));
    assert!(CGROUP_DIR.contains(OLD_SHARED_CGROUP_DEVPTS_BASE));
}

#[test]
fn a_counter_wraps_inside_its_region_instead_of_escaping_it() {
    static SMALL: Region = Region::new("small", 0x100, 0x102);
    static A: RegionAllocator = RegionAllocator::new(&SMALL);
    let got: alloc::vec::Vec<Ino> = (0..5).map(|_| A.alloc()).collect();
    assert_eq!(got, [0x100, 0x101, 0x102, 0x100, 0x101]);
    for ino in got { assert!(SMALL.contains(ino)); }
}

#[test]
fn folding_an_index_never_leaves_the_region() {
    for r in REGIONS {
        for n in [0u64, 1, 0xFFFF, u64::MAX] {
            assert!(r.contains(r.at(n)), "{} escaped for n={n:#x}", r.name());
        }
    }
}

#[test]
fn low_space_regions_stay_below_the_first_tag_family() {
    // A low-space owner that grew a 64-bit number would land inside a tag
    // family; a tag family with a zero high half would land in low space.
    for r in REGIONS {
        let low = r.end() >> 32 == 0;
        let high = r.start() >> 32 != 0;
        assert!(low || high, "{} straddles the 32-bit boundary", r.name());
    }
}
