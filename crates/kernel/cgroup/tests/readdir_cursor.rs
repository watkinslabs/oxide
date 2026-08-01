//! The cgroupfs readdir CURSOR over a REAL cgroup2 hierarchy.
//!
//! cgroupfs synthesizes its directory contents on every call: control files
//! from the controller tables, children from the live tree. Before F775 the
//! cursor was an ORDINAL into the CONCATENATION of those two lists, so systemd
//! creating or removing a sub-cgroup between two `getdents` pages shifted every
//! later ordinal — `ls /sys/fs/cgroup` under a starting unit duplicated or
//! skipped entries, and a `seekdir(3)` cookie named a different entry after the
//! mutation. Linux cgroupfs is kernfs-backed: its `d_off` is a hash of the NAME.
//!
//! The second defect fixed here: `lookup(name).map(|i| i.ino()).unwrap_or(0)`
//! emitted a live entry with `d_ino == 0`, which userspace reads as "deleted
//! placeholder". An entry whose cgroup vanished between the snapshot and the
//! resolve is now absent from the listing instead.

use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;

use vfs::{DirContext, DirEmit, FileType, InodeRef};

/// Emit actor with a hard record budget — the pagination a full user buffer
/// imposes on `getdents`.
struct Page {
    out: Vec<(String, u64, FileType)>,
    budget: usize,
}
impl DirEmit for Page {
    fn emit(&mut self, name: &str, ino: u64, d_type: FileType, _next: u64) -> bool {
        if self.out.len() == self.budget { return false; }
        self.out.push((String::from(name), ino, d_type));
        true
    }
}

fn page(dir: &InodeRef, pos: u64, budget: usize) -> (Vec<(String, u64, FileType)>, u64) {
    let mut actor = Page { out: Vec::new(), budget };
    let mut ctx = DirContext::new(pos, &mut actor);
    dir.readdir(&mut ctx).expect("readdir");
    let end = ctx.pos;
    (actor.out, end)
}

fn drain(dir: &InodeRef, budget: usize) -> Vec<(String, u64, FileType)> {
    let mut all = Vec::new();
    let mut pos = 0u64;
    loop {
        let (got, end) = page(dir, pos, budget);
        if got.is_empty() { break; }
        all.extend(got);
        pos = end;
    }
    all
}

/// The root cgroup exists only once the hierarchy is mounted; the tests share
/// one process-wide hierarchy, exactly as the kernel does.
fn mounted_root() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| { let _ = cgroup::fs::realize_tree(); });
}

/// A fresh sub-cgroup of the root, holding `kids` children of its own. Every
/// test works inside its own subtree so the shared hierarchy stays usable.
fn fixture(tag: &str, kids: &[&str]) -> InodeRef {
    mounted_root();
    let id = cgroup::mkdir_child(cgroup::ROOT_CGROUP, tag, 0, 0).expect("mkdir fixture");
    for k in kids { cgroup::mkdir_child(id, k, 0, 0).expect("mkdir kid"); }
    cgroup::inode::make_cg_dir(id)
}

#[test]
fn a_full_listing_is_complete_and_duplicate_free_at_every_page_size() {
    let kids = ["alpha", "bravo", "charlie", "delta"];
    let dir = fixture("fx-complete", &kids);
    let want: BTreeSet<String> = drain(&dir, usize::MAX).into_iter().map(|r| r.0).collect();
    assert!(want.len() > kids.len(), "control files list alongside the children");
    for k in kids { assert!(want.contains(k), "child {k:?} listed"); }

    for budget in 1..=4 {
        let got = drain(&dir, budget);
        assert_eq!(got.len(), want.len(), "page size {budget}: exactly one record per entry");
        assert_eq!(got.iter().map(|r| r.0.clone()).collect::<BTreeSet<_>>(), want, "page size {budget}");
    }
}

#[test]
fn no_entry_is_emitted_with_d_ino_zero() {
    let dir = fixture("fx-dino", &["one", "two"]);
    let got = drain(&dir, 3);
    assert!(!got.is_empty());
    for (name, ino, _) in got { assert_ne!(ino, 0, "entry {name:?} emitted d_ino == 0"); }
}

#[test]
fn control_files_and_children_report_their_real_types() {
    let dir = fixture("fx-types", &["kid"]);
    let got = drain(&dir, 2);
    let kid = got.iter().find(|r| r.0 == "kid").expect("child listed");
    assert_eq!(kid.2, FileType::Directory, "a child cgroup is a directory");
    let f = got.iter().find(|r| r.0 == "cgroup.procs").expect("control file listed");
    assert_eq!(f.2, FileType::Regular, "a control file is a regular file");
}

#[test]
fn creating_a_child_mid_listing_neither_duplicates_nor_skips() {
    let initial = ["aa", "bb", "cc", "dd"];
    let dir = fixture("fx-create", &initial);
    let id = cgroup::node_child_id(cgroup::ROOT_CGROUP, "fx-create").expect("fixture id");

    let (first, pos) = page(&dir, 0, 4);
    assert_eq!(first.len(), 4);

    // Names sorting before and after the emitted prefix: each one shifts every
    // later ORDINAL, which is exactly what the old cursor exposed.
    for n in ["a0", "m0", "zz"] { cgroup::mkdir_child(id, n, 0, 0).expect("mkdir mid-listing"); }

    let mut all: Vec<String> = first.iter().map(|r| r.0.clone()).collect();
    let mut p = pos;
    loop {
        let (got, end) = page(&dir, p, 4);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|r| r.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for n in initial {
        assert!(uniq.contains(n), "child {n:?} present for the whole listing was skipped: {all:?}");
    }
}

#[test]
fn removing_a_child_mid_listing_neither_duplicates_nor_skips() {
    let initial = ["aa", "bb", "cc", "dd", "ee", "ff"];
    let dir = fixture("fx-remove", &initial);
    let id = cgroup::node_child_id(cgroup::ROOT_CGROUP, "fx-remove").expect("fixture id");

    // Drain past the control files so the first page ends inside the children.
    let (first, pos) = page(&dir, 0, usize::MAX - 1);
    let emitted: Vec<String> = first.iter().map(|r| r.0.clone()).collect();
    assert!(emitted.iter().any(|n| n == "aa"), "the first page reached the children");

    // Remove two children that were ALREADY emitted: under a concatenated
    // ordinal the whole tail slides down by two and two survivors vanish.
    for n in ["aa", "bb"] { cgroup::rmdir_child(id, n).expect("rmdir mid-listing"); }

    let mut all = emitted.clone();
    let mut p = pos;
    loop {
        let (got, end) = page(&dir, p, 4);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|r| r.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for n in ["cc", "dd", "ee", "ff"] {
        assert!(uniq.contains(n), "surviving child {n:?} was skipped: {all:?}");
    }
}

#[test]
fn a_seekdir_cookie_names_the_same_suffix_across_a_create_and_rmdir() {
    let dir = fixture("fx-seek", &["one", "two", "three", "four"]);
    let id = cgroup::node_child_id(cgroup::ROOT_CGROUP, "fx-seek").expect("fixture id");

    let (_, cookie) = page(&dir, 0, 3);
    let before = drain_from(&dir, cookie);

    cgroup::mkdir_child(id, "transient", 0, 0).expect("mkdir");
    cgroup::rmdir_child(id, "transient").expect("rmdir");

    let after = drain_from(&dir, cookie);
    assert_eq!(before, after, "the cookie names the same suffix across a create+rmdir");
}

fn drain_from(dir: &InodeRef, mut pos: u64) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let (got, end) = page(dir, pos, 3);
        if got.is_empty() { break; }
        out.extend(got.into_iter().map(|r| r.0));
        pos = end;
    }
    out
}
