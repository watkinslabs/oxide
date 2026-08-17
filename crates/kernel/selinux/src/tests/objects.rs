// Path-prefix contexts and the initial-SID table.

use crate::services::fixture::*;

use crate::context::Context;
use crate::mapping::Mapping;
use crate::services::{genfs_sid, initial_sid_context, load_initial_sids};
use crate::sidtab::Sidtab;
use crate::uapi::classmap::class_by_name;
use crate::uapi::initsid::InitSid;

fn kcls(name: &str) -> u16 { class_by_name(name).expect("kernel class") }

#[test]
fn the_most_specific_path_prefix_wins() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    let file = kcls("file");
    let nested = genfs_sid(&db, "proc", "/net/dev", file, &map).expect("context");
    assert_eq!(nested.ty, T_ETC);
    let root = genfs_sid(&db, "proc", "/self/status", file, &map).expect("context");
    assert_eq!(root.ty, T_FILE);
}

#[test]
fn a_filesystem_with_no_entries_has_no_context() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    assert!(genfs_sid(&db, "sysfs", "/", kcls("file"), &map).is_none());
}

#[test]
fn an_entry_naming_a_class_matches_only_that_class() {
    let db = policy();
    let map = Mapping::build(&db).expect("mapping");
    // The `/net` entry names the file class; a directory falls through to the
    // class-less root entry instead.
    let as_dir = genfs_sid(&db, "proc", "/net/dev", kcls("dir"), &map).expect("context");
    assert_eq!(as_dir.ty, T_FILE);
}

#[test]
fn initial_sids_load_into_the_table() {
    let db = policy();
    let mut sidtab = Sidtab::new();
    load_initial_sids(&db, &mut sidtab).expect("load");
    let kernel = sidtab.lookup(InitSid::Kernel.sid()).and_then(Context::valid).expect("kernel");
    assert_eq!(kernel.ty, T_INIT);
    let unlabeled = sidtab.lookup(InitSid::Unlabeled.sid()).and_then(Context::valid)
        .expect("unlabeled");
    assert_eq!(unlabeled.ty, T_FILE);
    // A slot the policy never names stays empty rather than borrowing another.
    assert!(sidtab.lookup(InitSid::Netif.sid()).is_none());
}

#[test]
fn the_policy_states_each_initial_context() {
    let db = policy();
    assert_eq!(initial_sid_context(&db, InitSid::Kernel.sid()).map(|c| c.ty), Some(T_INIT));
    assert_eq!(initial_sid_context(&db, InitSid::Netif.sid()).map(|c| c.ty), None);
}

/// An initial SID this kernel has no slot for is SKIPPED, not refused.
///
/// Policies are written against newer kernels than the one loading them, so a
/// policy naming a SID this kernel never asks about must still load. Refusing
/// the image would leave the system with no policy at all — strictly worse than
/// ignoring a slot nothing here reads.
#[test]
fn an_initial_sid_beyond_this_kernels_range_is_skipped_not_refused() {
    use crate::uapi::initsid::SECINITSID_NUM;
    let mut db = policy();
    // A slot past the end of this kernel's table, as a newer policy would carry.
    db.ocontexts.isids.push(crate::policydb::sections::IsidCon {
        sid: SECINITSID_NUM + 5, context: ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]),
    });
    let mut sidtab = Sidtab::new();
    load_initial_sids(&db, &mut sidtab)
        .expect("a SID this kernel does not use must not refuse the whole policy");
    // The slots this kernel DOES name still loaded.
    assert!(sidtab.lookup(InitSid::Kernel.sid()).is_some());
    assert!(sidtab.lookup(InitSid::Unlabeled.sid()).is_some());
}

/// SID 0 is the "no SID" value. A context assigned to it means the image is
/// malformed, and that IS refused — the skip above must not swallow it.
#[test]
fn a_context_assigned_to_the_no_sid_value_refuses_the_policy() {
    let mut db = policy();
    db.ocontexts.isids.push(crate::policydb::sections::IsidCon {
        sid: 0, context: ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]),
    });
    let mut sidtab = Sidtab::new();
    assert!(load_initial_sids(&db, &mut sidtab).is_err());
}

/// Without the `userspace_initial_context` capability the first user process's
/// label takes the KERNEL's context, not the placeholder the policy declares.
#[test]
fn the_first_process_label_follows_the_kernels_without_the_capability() {
    let db = policy();
    assert!(!db.policycap(crate::uapi::policycap::POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT),
        "the fixture policy does not advertise it; this test is about that case");
    let mut sidtab = Sidtab::new();
    load_initial_sids(&db, &mut sidtab).expect("load");
    let kernel = sidtab.lookup(InitSid::Kernel.sid()).and_then(Context::valid).expect("kernel");
    let init = sidtab.lookup(InitSid::Init.sid()).and_then(Context::valid)
        .expect("the first process's label must be set even though policy skips it");
    assert_eq!(init.ty, kernel.ty);
    assert_eq!(init.ty, T_INIT);
}
