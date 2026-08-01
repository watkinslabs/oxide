// `MMF_TOPDOWN` — which direction `get_unmapped_area` searches from this mm's
// arena anchor. Linux `mm_get_unmapped_area` picks between
// `arch_get_unmapped_area_topdown` and `arch_get_unmapped_area`; the legacy
// (bottom-up) arm is what `personality(ADDR_COMPAT_LAYOUT)` selects.
//
// The persona bit is only implemented if a hint-less mmap actually LANDS low
// and grows upward. These tests drive `AddressSpace::mmap` itself, so a layout
// flag that is stored but never consulted fails here.

use super::*;

/// A low anchor well clear of both `MIN_USER_VA` and any top-down arena, so a
/// placement can be attributed to the direction rather than to the address.
const LEGACY_FLOOR: u64 = 0x2000_0000;
/// A high anchor standing in for `mmap_base`.
const TOPDOWN_CEIL: u64 = 0x4000_0000_0000;

fn anon_at(as_: &AddressSpace, len: usize) -> u64 {
    as_.mmap(None, len, r_w(), priv_anon(), VmaBacking::Anonymous, false)
        .expect("hint-less mmap").as_u64()
}

#[test]
fn the_default_layout_is_top_down() {
    // Linux's default, and the direction every non-legacy exec gets.
    let as_ = AddressSpace::new(0).unwrap();
    assert!(as_.mmap_topdown(), "a fresh mm must default to MMF_TOPDOWN");
    as_.set_mmap_layout(TOPDOWN_CEIL, true);
    let first = anon_at(&as_, PAGE);
    let second = anon_at(&as_, PAGE);
    assert_eq!(first + PAGE as u64, TOPDOWN_CEIL, "top-down did not start at the ceiling");
    assert!(second < first, "top-down allocation did not descend");
}

#[test]
fn addr_compat_layout_allocates_upward_from_the_floor() {
    let as_ = AddressSpace::new(0).unwrap();
    as_.set_mmap_layout(LEGACY_FLOOR, false);
    assert!(!as_.mmap_topdown());
    let first = anon_at(&as_, PAGE);
    let second = anon_at(&as_, PAGE);
    let third = anon_at(&as_, 2 * PAGE);
    assert_eq!(first, LEGACY_FLOOR, "legacy layout did not start at TASK_UNMAPPED_BASE");
    assert_eq!(second, LEGACY_FLOOR + PAGE as u64, "legacy allocation did not ascend");
    assert_eq!(third, LEGACY_FLOOR + 2 * PAGE as u64);
    as_.audit().unwrap();
}

#[test]
fn the_two_directions_place_the_same_request_in_opposite_halves() {
    // The whole point of the persona bit: identical requests, opposite ends of
    // the address space. A layout flag that is stored but never read would
    // make these two equal.
    let len = 4 * PAGE;
    let low = AddressSpace::new(0).unwrap();
    low.set_mmap_layout(LEGACY_FLOOR, false);
    let high = AddressSpace::new(0).unwrap();
    high.set_mmap_layout(TOPDOWN_CEIL, true);
    let a = anon_at(&low, len);
    let b = anon_at(&high, len);
    assert!(a < b, "legacy placement {a:#x} is not below top-down {b:#x}");
    assert_eq!(a, LEGACY_FLOOR);
    assert_eq!(b + len as u64, TOPDOWN_CEIL);
}

#[test]
fn a_legacy_search_steps_over_an_occupied_span_and_fills_the_first_gap() {
    // First fit, ascending: the lowest gap at or above the floor that holds
    // the request — not simply "above everything".
    let as_ = AddressSpace::new(0).unwrap();
    as_.set_mmap_layout(LEGACY_FLOOR, false);
    let blocker = uva(LEGACY_FLOOR);
    as_.mmap(Some(blocker), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    let far = uva(LEGACY_FLOOR + 8 * PAGE as u64);
    as_.mmap(Some(far), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    // The 6-page gap between them takes a 3-page request at its low end…
    assert_eq!(anon_at(&as_, 3 * PAGE), LEGACY_FLOOR + 2 * PAGE as u64);
    // …and the next 3 pages fill the rest of that same gap, still ascending.
    assert_eq!(anon_at(&as_, 3 * PAGE), LEGACY_FLOOR + 5 * PAGE as u64);
    // A request too big for the remaining gap goes above the far mapping.
    assert_eq!(anon_at(&as_, 4 * PAGE), LEGACY_FLOOR + 9 * PAGE as u64);
    as_.audit().unwrap();
}

#[test]
fn a_legacy_search_never_hands_out_the_null_page() {
    // A floor of 0 (the uninitialised sentinel, or an anchor a caller got
    // wrong) must still start at MIN_USER_VA: VA 0 belongs to the null trap
    // and to the SVr4 emulation, never to an ordinary anonymous mmap.
    let as_ = AddressSpace::new(0).unwrap();
    as_.set_mmap_layout(0, false);
    let got = anon_at(&as_, PAGE);
    assert_eq!(got, MIN_USER_VA);
    assert!(got >= PAGE as u64);
}

#[test]
fn the_layout_direction_is_inherited_by_fork() {
    // Linux copies the mm flags — `MMF_INIT_MASK` includes `MMF_TOPDOWN` — so
    // a child of an `ADDR_COMPAT_LAYOUT` process keeps allocating bottom-up
    // until it execs something that says otherwise.
    let parent = AddressSpace::new(0).unwrap();
    parent.set_mmap_layout(LEGACY_FLOOR, false);
    let child = parent.fork(0).unwrap();
    assert!(!child.mmap_topdown(), "fork lost MMF_TOPDOWN's cleared state");
    assert_eq!(child.mmap_base(), LEGACY_FLOOR);
    assert_eq!(anon_at(&child, PAGE), LEGACY_FLOOR);
}
