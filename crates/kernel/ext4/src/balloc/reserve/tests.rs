// The reserved-block admission, with no device behind it.

use alloc::vec;

use super::*;
use crate::mount_opts::Ext4Behaviour;

/// Behaviour with the reserve owned by `uid`/`gid`.
fn owned_by(uid: u32, gid: u32) -> Ext4Behaviour {
    Ext4Behaviour { resuid: uid, resgid: gid, ..Default::default() }
}

fn user(uid: u32) -> AllocCred {
    AllocCred { uid, gids: Vec::new(), cap_sys_resource: false }
}

/// Space outside the reserve is available to anybody.
#[test]
fn a_filesystem_with_room_to_spare_serves_everyone() {
    assert!(has_free_blocks(100, 1, 10, false));
    assert!(has_free_blocks(100, 90, 10, false));
}

/// The reserve is left behind by an allocation with no claim on it — that is
/// the whole of what reserving blocks means.
#[test]
fn the_reserve_is_not_handed_to_a_caller_without_a_claim() {
    assert!(!has_free_blocks(10, 1, 10, false));
    assert!(!has_free_blocks(10, 5, 10, false));
    assert!(!has_free_blocks(11, 2, 10, false));
}

/// A caller WITH a claim reaches it.
#[test]
fn a_claim_reaches_the_reserve() {
    assert!(has_free_blocks(10, 1, 10, true));
    assert!(has_free_blocks(10, 10, 10, true));
}

/// A claim is not a licence to allocate blocks that do not exist.
#[test]
fn a_claim_does_not_conjure_free_blocks() {
    assert!(!has_free_blocks(3, 4, 10, true));
    assert!(!has_free_blocks(0, 1, 0, true));
}

/// A reserve of nothing changes nothing: every caller is admitted on the
/// free count alone.
#[test]
fn an_unreserved_filesystem_admits_on_free_blocks_alone() {
    assert!(has_free_blocks(1, 1, 0, false));
    assert!(!has_free_blocks(0, 1, 0, false));
}

/// A r_blocks_count large enough to overflow the addition must not wrap into
/// a tiny threshold that admits everybody.
#[test]
fn an_absurd_reserve_does_not_wrap_into_no_reserve() {
    assert!(!has_free_blocks(u64::MAX - 1, 4, u64::MAX, false));
    assert!(has_free_blocks(u64::MAX - 1, 4, u64::MAX, true));
}

/// `resuid=` is the user the reserve is FOR.
#[test]
fn the_reserved_user_has_a_claim_and_nobody_else_does() {
    let b = owned_by(1000, DEFAULT_RESGID_FOR_TESTS);
    assert!(may_dip_into_reserve(&b, &user(1000), ReserveFlags::DATA));
    assert!(!may_dip_into_reserve(&b, &user(1001), ReserveFlags::DATA));
    assert!(!may_dip_into_reserve(&b, &user(ROOT_UID), ReserveFlags::DATA),
        "a mount that moved the reserve moved it away from root too");
}

/// The default mount reserves for root, which is the answer every filesystem
/// that names no option gets.
#[test]
fn the_default_reserve_belongs_to_root() {
    let b = Ext4Behaviour::default();
    assert!(may_dip_into_reserve(&b, &user(ROOT_UID), ReserveFlags::DATA));
    assert!(!may_dip_into_reserve(&b, &user(1000), ReserveFlags::DATA));
}

/// `resgid=` admits a MEMBER of that group, and only when the option named a
/// group: treating the default as "everyone in group 0" would hand the reserve
/// to a class of processes the option never named.
#[test]
fn the_reserved_group_admits_its_members_only_when_it_was_named() {
    let named = owned_by(ROOT_UID, 50);
    let member = AllocCred { uid: 1000, gids: vec![10, 50], cap_sys_resource: false };
    let outsider = AllocCred { uid: 1000, gids: vec![10, 51], cap_sys_resource: false };
    assert!(may_dip_into_reserve(&named, &member, ReserveFlags::DATA));
    assert!(!may_dip_into_reserve(&named, &outsider, ReserveFlags::DATA));

    let unnamed = Ext4Behaviour::default();
    let in_group_zero = AllocCred { uid: 1000, gids: vec![0], cap_sys_resource: false };
    assert!(!may_dip_into_reserve(&unnamed, &in_group_zero, ReserveFlags::DATA));
}

/// The capability that overrides resource limits reaches the reserve whoever
/// holds it.
#[test]
fn the_resource_capability_reaches_the_reserve() {
    let b = owned_by(1000, DEFAULT_RESGID_FOR_TESTS);
    let capable = AllocCred { uid: 1001, gids: Vec::new(), cap_sys_resource: true };
    assert!(may_dip_into_reserve(&b, &capable, ReserveFlags::DATA));
}

/// Quota files and committed metadata reach it on the allocation's own account,
/// with no credential at all.
#[test]
fn the_allocations_own_flags_reach_the_reserve() {
    let b = owned_by(1000, DEFAULT_RESGID_FOR_TESTS);
    let nobody = user(1001);
    assert!(!may_dip_into_reserve(&b, &nobody, ReserveFlags::DATA));
    assert!(may_dip_into_reserve(&b, &nobody, ReserveFlags::QUOTA_FILE));
    assert!(may_dip_into_reserve(&b, &nobody, ReserveFlags::METADATA_NOFAIL));
}

/// A context with no task behind it is the kernel's own and is admitted: the
/// mount path allocates before any task exists.
#[test]
fn a_kernel_context_is_admitted() {
    let b = owned_by(1000, DEFAULT_RESGID_FOR_TESTS);
    assert!(may_dip_into_reserve(&b, &AllocCred::kernel_context(), ReserveFlags::DATA));
}

/// Hosted, there is no running task, so the fetch answers with the kernel
/// context rather than inventing a user.
#[test]
fn the_fetch_answers_for_a_context_with_no_task() {
    assert_eq!(current_alloc_cred(), AllocCred::kernel_context());
}

/// The `resgid=` a mount that named none gets.
const DEFAULT_RESGID_FOR_TESTS: u32 = 0;
