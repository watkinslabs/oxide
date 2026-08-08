use super::*;

/// The break-before-make level sits in bits [55:52]; reading it from any other
/// position answers a different feature's question entirely.
#[test]
fn break_before_make_level_is_read_from_its_own_field() {
    assert_eq!(bbm_level(0), 0);
    assert_eq!(bbm_level(2 << 52), 2);
    assert_eq!(bbm_level(0xf << 52), 0xf);
    // Neighbouring fields must not bleed in.
    assert_eq!(bbm_level(!0u64 & !(0xfu64 << 52)), 0);
    assert_eq!(bbm_level(u64::MAX), 0xf);
}

/// Level 2 is the promise; anything below it is not, and anything above it
/// still is.
#[test]
fn only_level_two_and_above_permits_a_live_granularity_change() {
    assert!(!bbm_allows_live_split(0 << 52));
    assert!(!bbm_allows_live_split(1 << 52));
    assert!(bbm_allows_live_split(2 << 52));
    assert!(bbm_allows_live_split(3 << 52));
    assert!(bbm_allows_live_split(0xf << 52));
}

/// The capability is the UNION of two independent mechanisms. Gating it on the
/// feature register alone answers "no" on a machine whose linear map already
/// has a bottom-level leaf for every page of RAM — where removing a page needs
/// no granularity change at all — and the only visible effect is that every
/// contract built on it reports itself unimplemented.
#[test]
fn a_page_granular_map_needs_no_feature_to_remove_a_page() {
    let no_feature = 0u64;
    assert!(!bbm_allows_live_split(no_feature));
    assert!(page_removable_from_linear_map(true, no_feature));
}

/// The other half of the union: a map built from large leaves is still
/// serviceable on an implementation that advertises the relaxed behaviour.
#[test]
fn a_block_mapped_linear_map_still_works_where_the_feature_is_advertised() {
    assert!(page_removable_from_linear_map(false, BBM_LEVEL2 << 52));
    assert!(!page_removable_from_linear_map(false, 0));
}

/// The boot policy this architecture ships: RAM in the linear map is page
/// granular, so the capability holds on every implementation. The trampoline
/// that builds the map checks itself against this same declaration at compile
/// time, so a change to one without the other does not build.
#[test]
fn boot_policy_makes_the_capability_hold_without_any_feature() {
    assert!(LINEAR_MAP_RAM_PAGE_GRANULAR);
    assert!(page_removable_from_linear_map(LINEAR_MAP_RAM_PAGE_GRANULAR, read_id_aa64mmfr2()));
}
