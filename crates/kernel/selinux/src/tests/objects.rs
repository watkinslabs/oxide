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
