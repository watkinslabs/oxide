use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};
use user_namespace::{write_map, IdMapExtent, IdMapKind, OVERFLOW_GID, OVERFLOW_PROJID, OVERFLOW_UID};

use super::*;

fn child() -> NamespaceRef {
    let init = initial(NamespaceKind::User);
    allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap()
}

fn ext(ns_id: u32, host_id: u32, count: u32) -> IdMapExtent { IdMapExtent { ns_id, host_id, count } }

/// A container-style namespace: ids 0..65535 inside map to 100000..165535
/// outside, for every class.
fn container() -> NamespaceRef {
    let ns = child();
    for kind in [IdMapKind::Uid, IdMapKind::Gid, IdMapKind::Projid] {
        write_map(&ns, kind, true, 0, &[ext(0, 100_000, 65_536)]).unwrap();
    }
    ns
}

#[test]
fn the_initial_namespace_is_the_identity_map_for_every_quota_class() {
    let init = initial(NamespaceKind::User);
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        for id in [0u32, 1, 1000, 65_534, u32::MAX - 1] {
            let qid = make_kqid(&init, kind, id).expect("initial namespace maps every id");
            assert_eq!(qid, Kqid { kind, id });
            assert_eq!(from_kqid_munged(&init, qid), id);
            assert!(qid_has_mapping(&init, qid));
        }
    }
}

#[test]
fn the_minus_one_sentinel_is_an_invalid_quota_id_even_in_the_initial_namespace() {
    let init = initial(NamespaceKind::User);
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        assert_eq!(make_kqid(&init, kind, u32::MAX), None);
    }
}

#[test]
fn a_mapped_id_resolves_to_its_internal_identity_and_reports_back_unchanged() {
    let ns = container();
    let qid = make_kqid(&ns, QuotaType::User, 1000).unwrap();
    assert_eq!(qid, Kqid::user(101_000), "an in-namespace uid names a different internal account");
    assert_eq!(from_kqid_munged(&ns, qid), 1000);
    // The very same identity seen from the initial namespace is the raw
    // internal number, which is what an on-disk quota file records.
    assert_eq!(from_kqid_munged(&initial(NamespaceKind::User), qid), 101_000);
}

#[test]
fn an_id_outside_the_namespace_map_is_invalid_not_the_overflow_id() {
    // The failure this guards: munging an unmapped id to 65534 would silently
    // read or write the limits of whatever account 65534 names.
    let ns = container();
    assert_eq!(make_kqid(&ns, QuotaType::User, 65_536), None);
    assert_eq!(make_kqid(&ns, QuotaType::Group, 70_000), None);
    assert_eq!(make_kqid(&ns, QuotaType::Project, 100_000), None);
}

#[test]
fn a_namespace_with_no_written_map_can_name_no_quota_id_at_all() {
    let ns = child();
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        assert_eq!(make_kqid(&ns, kind, 0), None);
        assert!(!qid_has_mapping(&ns, Kqid { kind, id: 0 }));
    }
}

#[test]
fn each_quota_class_translates_through_its_own_map() {
    let ns = child();
    write_map(&ns, IdMapKind::Uid, true, 0, &[ext(0, 100_000, 10)]).unwrap();
    write_map(&ns, IdMapKind::Projid, true, 0, &[ext(0, 7_000, 10)]).unwrap();
    assert_eq!(make_kqid(&ns, QuotaType::User, 3), Some(Kqid::user(100_003)));
    assert_eq!(make_kqid(&ns, QuotaType::Project, 3), Some(Kqid::project(7_003)));
    // gid_map was never written, so no group quota id exists in this namespace
    // even though the uid of the same number does.
    assert_eq!(make_kqid(&ns, QuotaType::Group, 3), None);
}

#[test]
fn an_unmappable_identity_leaves_as_the_class_overflow_id() {
    let ns = container();
    assert_eq!(from_kqid_munged(&ns, Kqid::user(7)), OVERFLOW_UID);
    assert_eq!(from_kqid_munged(&ns, Kqid::group(7)), OVERFLOW_GID);
    assert_eq!(from_kqid_munged(&ns, Kqid::project(7)), OVERFLOW_PROJID);
    assert!(!qid_has_mapping(&ns, Kqid::user(7)));
}

#[test]
fn has_mapping_separates_an_unmapped_identity_from_one_named_by_the_overflow_id() {
    let ns = child();
    write_map(&ns, IdMapKind::Uid, true, 0, &[ext(0, OVERFLOW_UID, 1)]).unwrap();
    // Both report 65534 through the munged path; only the mapping probe can
    // tell "genuinely id 65534 outside" from "no mapping".
    assert_eq!(from_kqid_munged(&ns, Kqid::user(OVERFLOW_UID)), 0);
    assert_eq!(from_kqid_munged(&ns, Kqid::user(12_345)), OVERFLOW_UID);
    assert!(qid_has_mapping(&ns, Kqid::user(OVERFLOW_UID)));
    assert!(!qid_has_mapping(&ns, Kqid::user(12_345)));
}

#[test]
fn a_handle_that_is_not_a_user_namespace_names_no_quota_id() {
    let uts = allocate(NamespaceKind::Uts, initial(NamespaceKind::User), None).unwrap();
    assert_eq!(make_kqid(&uts, QuotaType::User, 0), None);
    assert!(!qid_has_mapping(&uts, Kqid::user(0)));
}

#[test]
fn quota_classes_select_the_matching_id_map() {
    assert_eq!(super::id_map_kind(QuotaType::User), IdMapKind::Uid);
    assert_eq!(super::id_map_kind(QuotaType::Group), IdMapKind::Gid);
    assert_eq!(super::id_map_kind(QuotaType::Project), IdMapKind::Projid);
}

#[test]
fn from_kqid_reports_the_sentinel_where_the_munged_form_reports_an_account() {
    let ns = container();
    let mapped = Kqid::user(100_007);
    assert_eq!(from_kqid(&ns, mapped), Some(7));
    assert_eq!(from_kqid_munged(&ns, mapped), 7);
    let unmapped = Kqid::user(7);
    assert_eq!(from_kqid(&ns, unmapped), None,
        "an id this namespace cannot name has no number, not account 65534");
    assert_eq!(from_kqid_munged(&ns, unmapped), OVERFLOW_UID);
}
