//! Every arm of the reserved-pool decision, and the two figures it produces.

use super::*;

fn caller(fsuid: u32, in_res_group: bool, cap_sys_resource: bool) -> ReservedCaller {
    ReservedCaller { fsuid, in_res_group, cap_sys_resource }
}

const R: Reserve = Reserve { blocks: 100, nodes: 10, resuid: 500, resgid: 600 };

#[test]
fn kernel_context_reaches_the_reserve() {
    assert!(allow_reserved_root(&R, None, false, false));
}

#[test]
fn a_quota_file_reaches_the_reserve() {
    let c = caller(1000, false, false);
    assert!(allow_reserved_root(&R, Some(&c), true, true));
}

#[test]
fn the_reserved_uid_reaches_the_reserve() {
    let c = caller(500, false, false);
    assert!(allow_reserved_root(&R, Some(&c), false, false));
}

#[test]
fn the_reserved_group_reaches_the_reserve() {
    let c = caller(1000, true, false);
    assert!(allow_reserved_root(&R, Some(&c), false, false));
}

#[test]
fn a_default_reserved_gid_does_not_hand_the_pool_to_group_zero() {
    // The membership bit is SET, so only the option's own default value keeps
    // the caller out. A volume that never named a group has reserved for none.
    let r = Reserve { resgid: ROOT_GID, ..R };
    let c = caller(1000, true, false);
    assert!(!allow_reserved_root(&r, Some(&c), false, false));
}

#[test]
fn cap_sys_resource_reaches_the_reserve_only_where_the_call_site_honours_it() {
    let c = caller(1000, false, true);
    assert!(allow_reserved_root(&R, Some(&c), false, true));
    assert!(!allow_reserved_root(&R, Some(&c), false, false));
}

#[test]
fn an_ordinary_caller_is_refused_every_arm() {
    let c = caller(1000, false, false);
    assert!(!allow_reserved_root(&R, Some(&c), false, true));
}

#[test]
fn the_decision_is_what_moves_the_two_figures() {
    assert_eq!(available_blocks(1000, &R, false), 900);
    assert_eq!(available_blocks(1000, &R, true), 1000);
    assert_eq!(available_nodes(50, &R, false), 40);
    assert_eq!(available_nodes(50, &R, true), 50);
}

#[test]
fn a_reserve_larger_than_the_volume_floors_at_zero_rather_than_wrapping() {
    let r = Reserve { blocks: 5000, nodes: 5000, ..R };
    assert_eq!(available_blocks(1000, &r, false), 0);
    assert_eq!(available_nodes(50, &r, false), 0);
}

#[test]
fn an_unset_option_reserves_nothing_from_anyone() {
    let r = Reserve { blocks: 0, nodes: 0, resuid: 0, resgid: 0 };
    let c = caller(1000, false, false);
    assert!(!allow_reserved_root(&r, Some(&c), false, false));
    assert_eq!(available_blocks(1000, &r, false), 1000);
    assert_eq!(available_nodes(50, &r, false), 50);
}
