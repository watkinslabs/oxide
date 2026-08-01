// Family registration: id spaces, static reservations, and refusal cases.

extern crate alloc;

use alloc::vec::Vec;

use super::harness::*;
use crate::genetlink::family::{self, GenlFamilySpec, GenlOp, GenlRegError};
use crate::genetlink::uapi::*;

#[test]
fn controller_and_quota_take_their_reserved_ids() {
    boot();
    let ctrl = family::find_by_name(CTRL_FAMILY_NAME).unwrap();
    assert_eq!(ctrl.id, GENL_ID_CTRL);
    assert_eq!(ctrl.mcgrp_offset, GENL_ID_CTRL as u32);
    let quota = family::find_by_name(crate::genetlink::quota::QUOTA_FAMILY_NAME).unwrap();
    assert_eq!(quota.id, GENL_ID_VFS_DQUOT);
    // The three static families historically doubled their family id as their
    // multicast group id, so both reservations must agree.
    assert_eq!(quota.mcgrp_offset, GENL_ID_VFS_DQUOT as u32);
}

#[test]
fn dynamic_ids_start_past_the_static_reservations() {
    let fam = register_test_family("dynid", Vec::new(), 1);
    assert!(fam.id >= GENL_START_ALLOC && fam.id <= GENL_MAX_ID);
    assert!(fam.mcgrp_offset >= GENL_GRP_ID_MIN);
    // A dynamic group may never land on a reserved id.
    for grp in &fam.mcgrps {
        assert_ne!(grp.id, 0);
        assert_ne!(grp.id, GENL_GRP_ID_NET_DM);
        assert_ne!(grp.id, GENL_ID_CTRL as u32);
        assert_ne!(grp.id, GENL_ID_VFS_DQUOT as u32);
        assert_ne!(grp.id, GENL_ID_PMCRAID as u32);
    }
}

#[test]
fn multiple_groups_are_allocated_contiguously() {
    let fam = register_test_family("contig", Vec::new(), 3);
    assert_eq!(fam.mcgrps.len(), 3);
    for (i, grp) in fam.mcgrps.iter().enumerate() {
        assert_eq!(grp.id, fam.mcgrp_offset + i as u32);
        assert_eq!(fam.group_id(i), Some(grp.id));
    }
    assert_eq!(fam.group_id(3), None);
}

#[test]
fn two_families_never_share_a_group_id() {
    let a = register_test_family("share-a", Vec::new(), 2);
    let b = register_test_family("share-b", Vec::new(), 2);
    let a_ids: Vec<u32> = a.mcgrps.iter().map(|g| g.id).collect();
    for grp in &b.mcgrps { assert!(!a_ids.contains(&grp.id)); }
}

#[test]
fn duplicate_name_is_eexist() {
    let fam = register_test_family("dup", Vec::new(), 0);
    let again = family::register_family(GenlFamilySpec {
        name: alloc::string::String::leak(alloc::string::String::from(fam.name.as_str())),
        version: 1, hdrsize: 0, maxattr: 0, ops: Vec::new(), mcgrps: Vec::new(),
        netnsok: true, resv_start_op: 0,
    });
    assert_eq!(again, Err(GenlRegError::Eexist));
}

#[test]
fn an_op_without_do_or_dump_is_einval() {
    boot();
    let bad = family::register_family(GenlFamilySpec {
        name: "oxide-t-badop", version: 1, hdrsize: 0, maxattr: 0,
        ops: alloc::vec![GenlOp { cmd: 1, flags: op_flags::GENL_ADMIN_PERM, policy: &[] }],
        mcgrps: Vec::new(), netnsok: true, resv_start_op: 0,
    });
    assert_eq!(bad, Err(GenlRegError::Einval));
    assert!(family::find_by_name("oxide-t-badop").is_none());
}

#[test]
fn a_name_or_group_name_longer_than_the_wire_field_is_einval() {
    boot();
    let long: &'static str = alloc::string::String::leak(alloc::string::String::from(
        "0123456789abcdef"));
    assert_eq!(long.len(), GENL_NAMSIZ);
    assert_eq!(family::register_family(GenlFamilySpec {
        name: long, version: 1, hdrsize: 0, maxattr: 0, ops: Vec::new(),
        mcgrps: Vec::new(), netnsok: true, resv_start_op: 0,
    }), Err(GenlRegError::Einval));
    assert_eq!(family::register_family(GenlFamilySpec {
        name: "oxide-t-lgrp", version: 1, hdrsize: 0, maxattr: 0, ops: Vec::new(),
        mcgrps: alloc::vec![long], netnsok: true, resv_start_op: 0,
    }), Err(GenlRegError::Einval));
}

#[test]
fn unregister_frees_the_id_and_reports_enoent_twice() {
    // The claim has to span BOTH registrations. `register_test_family` holds
    // it for one registration only, so a sibling registering between this
    // test's unregister and its re-register takes the group id this test just
    // freed and is asserting comes back.
    let _serial = crate::test_serial::genl();
    let fam = register_unserialised("unreg", Vec::new(), 1);
    let freed: Vec<u32> = fam.mcgrps.iter().map(|g| g.id).collect();
    assert_eq!(family::unregister_family(fam.id), Ok(()));
    assert!(family::find_by_id(fam.id).is_none());
    assert!(family::find_by_name(&fam.name).is_none());
    assert_eq!(family::unregister_family(fam.id), Err(GenlRegError::Enoent));
    // The released group ids come back into the allocation pool.
    let next = register_unserialised("unreg-next", Vec::new(), 1);
    assert!(freed.contains(&next.mcgrps[0].id));
    assert_eq!(family::unregister_family(next.id), Ok(()));
}

#[test]
fn socket_group_count_covers_every_registered_group() {
    let fam = register_test_family("ngroups", Vec::new(), 2);
    let highest = fam.mcgrp_offset + fam.mcgrps.len() as u32;
    assert!(family::mcast_ngroups() >= highest);
    assert!(family::mcast_ngroups() >= crate::groups::NETLINK_MIN_NGROUPS);
}
