// `/sys/subsystem` completeness and layout.

use alloc::string::String;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, DirEmit, FileType, InodeBuilder, InodeOps, InodeRef};

use super::{make_sys_subsystem_inode, BUS_ROOT, CLASS_ROOT, DEVICES, DRIVERS};
use crate::{ids, DIR_PERM};

struct Empty;
impl InodeOps for Empty {}
impl vfs::FileOps for Empty {}

fn stub_dir() -> InodeRef {
    InodeBuilder::new(ids::ROOT, mk_mode(FileType::Directory, DIR_PERM),
        alloc::sync::Arc::new(Empty), alloc::sync::Arc::new(Empty)).build()
}

/// Register one name under a classification root and return the unified view.
fn with_registered(classes: &[&str], buses: &[&str]) -> InodeRef {
    for c in classes { crate::register(&alloc::format!("/sys/{CLASS_ROOT}/{c}"), stub_dir()); }
    for b in buses { crate::register(&alloc::format!("/sys/{BUS_ROOT}/{b}/{DEVICES}"), stub_dir()); }
    make_sys_subsystem_inode()
}

struct Collect(Vec<String>);
impl DirEmit for Collect {
    fn emit(&mut self, name: &str, _ino: u64, _d: FileType, _next: u64) -> bool {
        self.0.push(String::from(name));
        true
    }
}

/// Every name one directory lists, excluding the `.`/`..` self entries. # C: O(N)
fn names(dir: &InodeRef) -> Vec<String> {
    let mut actor = Collect(Vec::new());
    let mut ctx = DirContext::new(0, &mut actor);
    dir.readdir(&mut ctx).expect("readdir");
    actor.0.into_iter().filter(|n| n != "." && n != "..").collect()
}

// The whole safety of publishing this directory rests on it being COMPLETE:
// a consumer that finds it may stop scanning /sys/class and /sys/bus, so
// every name under either must appear here. It is a projection, so a class
// registered with no knowledge of this view still shows up.
#[test]
fn every_class_and_bus_appears_in_the_unified_view() {
    let view = with_registered(&["ssnet", "ssblock"], &["ssvirtio", "sspci"]);
    let listed = names(&view);
    for expected in ["ssnet", "ssblock", "ssvirtio", "sspci"] {
        assert!(listed.iter().any(|n| n == expected), "{expected} missing from {listed:?}");
    }
}

#[test]
fn a_name_under_neither_root_is_not_found() {
    let view = with_registered(&[], &[]);
    assert!(view.lookup("ssnothing").is_err());
}

// `<name>/devices` points at the canonical directory instead of re-rendering
// it, so the device targets underneath resolve against that directory's own
// path and one set of targets stays correct at both depths.
#[test]
fn a_class_subsystem_points_at_its_class_directory() {
    let view = with_registered(&["sstty"], &[]);
    let dir = view.lookup("sstty").expect("class subsystem present");
    let link = dir.lookup(DEVICES).expect("devices entry");
    assert_eq!(link.readlink().expect("readlink"),
        alloc::format!("../../{CLASS_ROOT}/sstty").into_bytes());
    assert_eq!(names(&dir), alloc::vec![String::from(DEVICES)],
        "a class has no drivers directory");
}

#[test]
fn a_bus_subsystem_points_at_its_bus_devices_and_drivers() {
    let view = with_registered(&[], &["sspci2"]);
    let dir = view.lookup("sspci2").expect("bus subsystem present");
    assert_eq!(dir.lookup(DEVICES).expect("devices").readlink().expect("readlink"),
        alloc::format!("../../{BUS_ROOT}/sspci2/{DEVICES}").into_bytes());
    assert_eq!(dir.lookup(DRIVERS).expect("drivers").readlink().expect("readlink"),
        alloc::format!("../../{BUS_ROOT}/sspci2/{DRIVERS}").into_bytes());
}

// A name registered as both keeps ONE entry, in the bus layout whose shape
// this directory follows.
#[test]
fn a_name_in_both_roots_appears_once_in_the_bus_layout() {
    let view = with_registered(&["ssboth"], &["ssboth"]);
    let listed = names(&view);
    assert_eq!(listed.iter().filter(|n| *n == "ssboth").count(), 1);
    let dir = view.lookup("ssboth").expect("present");
    assert_eq!(dir.lookup(DEVICES).expect("devices").readlink().expect("readlink"),
        alloc::format!("../../{BUS_ROOT}/ssboth/{DEVICES}").into_bytes());
}
