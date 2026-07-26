use crate::engine::{self, contains, IdMapKind, SetgroupsPolicy, UserNsError};
use crate::extent::IdMapExtent;
use crate::translate::{to_host, to_ns, OverflowId};
use crate::uapi::{OVERFLOW_UID, UID_GID_MAP_MAX_EXTENTS};
use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};

fn child_of(parent: &NamespaceRef) -> NamespaceRef {
    allocate(NamespaceKind::User, parent.clone(), Some(parent.clone())).unwrap()
}

fn root_child() -> NamespaceRef { child_of(&initial(NamespaceKind::User)) }

fn ext(ns_id: u32, host_id: u32, count: u32) -> IdMapExtent { IdMapExtent { ns_id, host_id, count } }

// --- extent validation / translation round-trip --------------------------

#[test]
fn round_trips_a_multi_line_map() {
    let owner = root_child();
    let extents = [ext(0, 100_000, 1000), ext(1000, 0, 1)];
    engine::write_map(&owner, IdMapKind::Uid, true, 0, &extents).unwrap();
    assert_eq!(engine::snapshot_map(&owner, IdMapKind::Uid).unwrap().as_slice(), &extents[..]);
}

#[test]
fn overlapping_ns_ranges_are_rejected() {
    let owner = root_child();
    let extents = [ext(0, 100_000, 100), ext(50, 0, 10)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, true, 0, &extents),
        Err(UserNsError::Overlap));
}

#[test]
fn overlapping_host_ranges_are_rejected() {
    let owner = root_child();
    let extents = [ext(0, 100_000, 100), ext(1000, 100_050, 10)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, true, 0, &extents),
        Err(UserNsError::Overlap));
}

#[test]
fn too_many_extents_are_rejected() {
    let owner = root_child();
    let extents: alloc::vec::Vec<IdMapExtent> = (0..(UID_GID_MAP_MAX_EXTENTS as u32 + 1))
        .map(|i| ext(i, i, 1)).collect();
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, true, 0, &extents),
        Err(UserNsError::TooManyExtents));
}

#[test]
fn empty_extent_batch_is_rejected() {
    let owner = root_child();
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, true, 0, &[]),
        Err(UserNsError::EmptyExtents));
}

// --- write-once ------------------------------------------------------------

#[test]
fn second_write_to_a_populated_map_is_write_once_rejected() {
    let owner = root_child();
    let first = [ext(0, 0, 1)];
    engine::write_map(&owner, IdMapKind::Uid, true, 0, &first).unwrap();
    let second = [ext(0, 1, 1)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, true, 0, &second),
        Err(UserNsError::AlreadyPopulated));
    // Original mapping survives the rejected second write.
    assert_eq!(engine::snapshot_map(&owner, IdMapKind::Uid).unwrap().as_slice(), &first[..]);
}

// --- unprivileged single-line-own-id rule ----------------------------------

#[test]
fn unprivileged_writer_may_map_only_its_own_effective_id() {
    let owner = root_child();
    let not_own = [ext(0, 2000, 1)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, false, 1000, &not_own),
        Err(UserNsError::UnprivilegedNotOwnId));

    let owner2 = root_child();
    let own = [ext(0, 1000, 1)];
    assert!(engine::write_map(&owner2, IdMapKind::Uid, false, 1000, &own).is_ok());
}

#[test]
fn unprivileged_writer_cannot_use_multiple_extents_even_if_first_is_own_id() {
    let owner = root_child();
    let extents = [ext(0, 1000, 1), ext(1, 1001, 1)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Uid, false, 1000, &extents),
        Err(UserNsError::UnprivilegedNotOwnId));
}

#[test]
fn privileged_writer_may_map_arbitrary_extents() {
    let owner = root_child();
    let extents = [ext(0, 5000, 1), ext(5, 6000, 1)];
    assert!(engine::write_map(&owner, IdMapKind::Uid, true, 1000, &extents).is_ok());
}

// --- setgroups <-> gid_map interlock (CVE-2014-8989) -----------------------

#[test]
fn setgroups_must_be_denied_before_unprivileged_gid_map_write() {
    let owner = root_child();
    let own = [ext(0, 1000, 1)];
    assert_eq!(engine::write_map(&owner, IdMapKind::Gid, false, 1000, &own),
        Err(UserNsError::SetgroupsMustDenyFirst));
    engine::write_setgroups(&owner, SetgroupsPolicy::Deny).unwrap();
    assert!(engine::write_map(&owner, IdMapKind::Gid, false, 1000, &own).is_ok());
}

#[test]
fn privileged_gid_map_write_does_not_require_setgroups_deny() {
    let owner = root_child();
    let extents = [ext(0, 1000, 1)];
    assert!(engine::write_map(&owner, IdMapKind::Gid, true, 1000, &extents).is_ok());
    assert_eq!(engine::setgroups_policy(&owner).unwrap(), SetgroupsPolicy::Allow);
}

#[test]
fn setgroups_cannot_move_back_to_allow_after_gid_map_written() {
    let owner = root_child();
    engine::write_setgroups(&owner, SetgroupsPolicy::Deny).unwrap();
    let own = [ext(0, 1000, 1)];
    engine::write_map(&owner, IdMapKind::Gid, false, 1000, &own).unwrap();
    assert_eq!(engine::write_setgroups(&owner, SetgroupsPolicy::Allow),
        Err(UserNsError::SetgroupsLockedAfterGidMap));
    // Even re-asserting Deny is locked once gid_map is populated.
    assert_eq!(engine::write_setgroups(&owner, SetgroupsPolicy::Deny),
        Err(UserNsError::SetgroupsLockedAfterGidMap));
}

// --- write-once ownership / initial namespace guards -----------------------

#[test]
fn initial_namespace_reports_fixed_identity_and_rejects_writes() {
    let init = initial(NamespaceKind::User);
    assert_eq!(engine::snapshot_map(&init, IdMapKind::Uid).unwrap().as_slice(), &[ext(0, 0, u32::MAX)][..]);
    assert_eq!(engine::setgroups_policy(&init).unwrap(), SetgroupsPolicy::Allow);
    assert_eq!(engine::write_map(&init, IdMapKind::Uid, true, 0, &[ext(0, 0, 1)]),
        Err(UserNsError::InitialOwner));
    assert_eq!(engine::write_setgroups(&init, SetgroupsPolicy::Deny),
        Err(UserNsError::InitialOwner));
}

#[test]
fn unset_non_initial_map_reads_empty() {
    let owner = root_child();
    assert!(engine::snapshot_map(&owner, IdMapKind::Uid).unwrap().is_empty());
    assert!(engine::snapshot_map(&owner, IdMapKind::Gid).unwrap().is_empty());
}

#[test]
fn final_owner_drop_removes_state() {
    let owner = root_child();
    let id = owner.id();
    engine::write_map(&owner, IdMapKind::Uid, true, 0, &[ext(0, 0, 1)]).unwrap();
    assert!(contains(id));
    drop(owner);
    assert!(!contains(id));
}

// --- translation -------------------------------------------------------

#[test]
fn translate_mapped_unmapped_and_boundary_ids() {
    let map = [ext(0, 100_000, 10), ext(1000, 0, 1)];
    assert_eq!(to_host(&map, 0, OverflowId::Uid), 100_000);
    assert_eq!(to_host(&map, 9, OverflowId::Uid), 100_009);
    assert_eq!(to_host(&map, 10, OverflowId::Uid), OVERFLOW_UID);
    assert_eq!(to_host(&map, 1000, OverflowId::Uid), 0);
    assert_eq!(to_ns(&map, 100_000, OverflowId::Uid), 0);
    assert_eq!(to_ns(&map, 100_009, OverflowId::Uid), 9);
    assert_eq!(to_ns(&map, 100_010, OverflowId::Uid), OVERFLOW_UID);
}
