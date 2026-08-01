//! The `/proc` readdir CURSOR and the entry set `/proc`'s root publishes.
//!
//! `/proc` has no stored child list: the pid set is re-snapshotted from the
//! scheduler registry on EVERY `getdents` call. Before F775 the cursor was an
//! ORDINAL into that snapshot, which makes it the worst instance of the defect
//! in the tree — a process exiting mid-listing shifts every later ordinal, so
//! `ls /proc` (and every `ps`, `top`, `pgrep` walking it) duplicated or skipped
//! processes, and a `seekdir(3)` cookie taken before the exit named a different
//! pid after it. The cursor is now a hash of the NAME
//! (`vfs::readdir_cookie`), which no neighbour's arrival or departure can move.
//!
//! Second defect fixed here: the root did
//! `inode.lookup(name).map(|i| i.ino()).unwrap_or(0)`, so a pid that exited
//! between the snapshot and the lookup was still LISTED, carrying `d_ino == 0`
//! — the value userspace reads as "deleted placeholder".
//!
//! `procfs::live::root`'s `iterate` is `cfg(target_os = "oxide-kernel")`, so a
//! test cannot call it: a `#[cfg(test)]` block inside a target-gated file
//! compiles away silently. The decisions it makes therefore live in the UNGATED
//! `procfs::readdir` (entry set, `d_type`, drop-the-vanished, emit order), and
//! the gated `iterate` is the two-line shim that calls it. These drive that
//! module directly, in the same shape the shim uses.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::string::String;
use std::vec::Vec;

use procfs::readdir::{decimal_name, emit_resolved, proc_root_dynamic, push_resolved, PROC_SELF, PROC_THREAD_SELF};
use vfs::{CookieEntry, DirContext, DirEmit, FileType};

/// Inode numbers `/proc`'s root hands out, so no entry can accidentally test
/// clean with a zero it never had.
const STATIC_INO_BASE: u64 = 0x1000;
const MAGIC_LINK_INO_BASE: u64 = 0x2000;
const PID_INO_BASE: u64 = 0x3000;

/// The live pid registry, standing in for `sched::live::registry`. A test
/// mutates it BETWEEN two pages, which is the only way to expose an ordinal
/// cursor — a boot cannot schedule the exit at a controlled point.
struct Registry {
    /// Statically registered `/proc` children (`meminfo`, `uptime`, …).
    statics: BTreeMap<String, u64>,
    vpids: RefCell<BTreeSet<u32>>,
}

impl Registry {
    fn new(statics: &[&str], vpids: &[u32]) -> Self {
        Self {
            statics: statics.iter().enumerate()
                .map(|(i, n)| (String::from(*n), STATIC_INO_BASE + i as u64)).collect(),
            vpids: RefCell::new(vpids.iter().copied().collect()),
        }
    }

    fn vpids(&self) -> Vec<u32> { self.vpids.borrow().iter().copied().collect() }

    /// `inode.lookup(name)` — resolves against the registry AS IT IS NOW, which
    /// is what makes a mid-listing exit observable: a pid in the snapshot but
    /// gone by the resolve has no inode.
    fn lookup(&self, name: &str) -> Option<u64> {
        match name {
            PROC_SELF => Some(MAGIC_LINK_INO_BASE),
            PROC_THREAD_SELF => Some(MAGIC_LINK_INO_BASE + 1),
            _ => match name.parse::<u32>() {
                Ok(p) if self.vpids.borrow().contains(&p) => Some(PID_INO_BASE + p as u64),
                Ok(_) => None,
                Err(_) => None,
            },
        }
    }
}

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

/// One `getdents` call on `/proc`'s root, in the exact shape
/// `ProcRootOps::iterate` uses: statics carry their own ino (no lookup), the
/// dynamic set is resolved and the vanished dropped.
fn page(r: &Registry, pos: u64, budget: usize) -> (Vec<(String, u64, FileType)>, u64) {
    let mut actor = Page { out: Vec::new(), budget };
    let mut ctx = DirContext::new(pos, &mut actor);
    let mut es: Vec<CookieEntry> = r.statics.iter()
        .map(|(n, i)| CookieEntry::new(n.clone(), *i, FileType::Regular)).collect();
    push_resolved(&mut es, proc_root_dynamic(&r.vpids()), |n| r.lookup(n));
    vfs::emit_by_cookie(&mut es, &mut ctx).expect("readdir");
    let end = ctx.pos;
    (actor.out, end)
}

fn drain(r: &Registry, budget: usize) -> Vec<(String, u64, FileType)> {
    let mut all = Vec::new();
    let mut pos = 0u64;
    loop {
        let (got, end) = page(r, pos, budget);
        if got.is_empty() { break; }
        all.extend(got);
        pos = end;
    }
    all
}

fn fixture() -> Registry {
    Registry::new(&["meminfo", "uptime", "cpuinfo", "stat", "cmdline"], &[1, 2, 47, 512, 4096])
}

// --------------------------------------------------- /proc/self is DT_LNK --

#[test]
fn proc_self_and_thread_self_are_symlinks_in_a_paginated_listing() {
    // `/proc/self` and `/proc/thread-self` are magic SYMLINKS (they recompute
    // their target on every readlink). Reporting `DT_DIR` makes `ls -F` print
    // them as directories and makes `find /proc` descend, double-counting every
    // process in the tree.
    let r = fixture();
    for budget in [1usize, 2, 3, 5, 64] {
        let got = drain(&r, budget);
        for magic in [PROC_SELF, PROC_THREAD_SELF] {
            let e = got.iter().find(|e| e.0 == magic)
                .unwrap_or_else(|| std::panic!("page size {budget}: {magic} listed"));
            assert_eq!(e.2, FileType::Symlink, "page size {budget}: {magic} reports DT_LNK");
            assert_ne!(e.1, 0, "{magic} carries a real inode number");
        }
    }
}

#[test]
fn a_pid_directory_is_not_a_symlink() {
    // The two magic names are the ONLY symlinks in `/proc`'s root; every pid is
    // a real directory, so the d_type must not be applied wholesale.
    let r = fixture();
    let got = drain(&r, 4);
    for p in [1u32, 47, 4096] {
        let n = decimal_name(p);
        let e = got.iter().find(|e| e.0 == n).expect("pid listed");
        assert_eq!(e.2, FileType::Directory, "pid {p} is a directory");
    }
}

#[test]
fn the_dynamic_entry_set_is_exactly_the_two_magic_links_plus_every_live_pid() {
    let es = proc_root_dynamic(&[7, 9]);
    assert_eq!(es.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(),
        std::vec![PROC_SELF, PROC_THREAD_SELF, "7", "9"]);
    assert_eq!(es.iter().map(|e| e.1).collect::<Vec<_>>(),
        std::vec![FileType::Symlink, FileType::Symlink, FileType::Directory, FileType::Directory]);
}

// ------------------------------------------------------------ pagination --

#[test]
fn a_full_listing_is_complete_and_duplicate_free_at_every_page_size() {
    let r = fixture();
    let want: BTreeSet<String> = drain(&r, usize::MAX).into_iter().map(|e| e.0).collect();
    assert_eq!(want.len(), 5 + 2 + 5, "5 statics + self/thread-self + 5 pids");
    for budget in 1..=want.len() + 2 {
        let got = drain(&r, budget);
        assert_eq!(got.len(), want.len(), "page size {budget}: exactly one record per entry");
        assert_eq!(got.iter().map(|e| e.0.clone()).collect::<BTreeSet<_>>(), want, "page size {budget}");
    }
}

#[test]
fn no_entry_is_emitted_with_d_ino_zero() {
    let r = fixture();
    for (name, ino, _) in drain(&r, 3) { assert_ne!(ino, 0, "entry {name:?} emitted d_ino == 0"); }
}

// ------------------------------------------- the reason cookies exist --

/// A fixture whose entry set is mostly pids, so a page ends inside them.
fn busy() -> Registry {
    Registry::new(&["meminfo", "uptime"],
        &[1, 2, 17, 47, 88, 129, 256, 401, 512, 777, 1024, 4096])
}

#[test]
fn a_process_exiting_mid_listing_neither_duplicates_nor_skips() {
    let r = busy();

    // Page 1: take six records, remember the resume cursor.
    let (first, pos) = page(&r, 0, 6);
    assert_eq!(first.len(), 6);
    let emitted: Vec<String> = first.iter().map(|e| e.0.clone()).collect();

    // Two processes ALREADY emitted this listing exit. Under an ordinal cursor
    // into the freshly-snapshotted pid list, the whole tail slides down by two
    // and two still-live processes are silently skipped.
    let gone: Vec<u32> = emitted.iter().filter_map(|n| n.parse::<u32>().ok()).take(2).collect();
    assert_eq!(gone.len(), 2, "the first page reached the pid entries: {emitted:?}");
    for p in &gone { r.vpids.borrow_mut().remove(p); }

    let mut all = emitted.clone();
    let mut p = pos;
    loop {
        let (got, end) = page(&r, p, 6);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|e| e.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for p in busy().vpids().into_iter().filter(|p| !gone.contains(p)) {
        let n = decimal_name(p);
        assert!(uniq.contains(&n), "pid {n} live for the whole listing was skipped: {all:?}");
    }
    for n in [PROC_SELF, PROC_THREAD_SELF, "meminfo", "uptime"] {
        assert!(uniq.contains(n), "entry {n:?} present for the whole listing was skipped: {all:?}");
    }
}

#[test]
fn a_process_starting_mid_listing_neither_duplicates_nor_skips() {
    let r = busy();
    let (first, pos) = page(&r, 0, 6);
    let emitted: Vec<String> = first.iter().map(|e| e.0.clone()).collect();

    // A fork storm: enough new pids that some of their cookies land BEFORE the
    // resume cursor, which under an ordinal cursor pushes already-emitted
    // entries past it and re-emits them.
    for p in [3u32, 5, 48, 90, 300, 999, 2048, 99999] { r.vpids.borrow_mut().insert(p); }

    let mut all = emitted.clone();
    let mut p = pos;
    loop {
        let (got, end) = page(&r, p, 6);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|e| e.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for p in busy().vpids() {
        let n = decimal_name(p);
        assert!(uniq.contains(&n), "pid {n} live for the whole listing was skipped: {all:?}");
    }
}

#[test]
fn a_pid_that_exits_between_the_snapshot_and_the_resolve_is_not_listed_at_all() {
    // The `d_ino == 0` defect: the old root emitted the vanished pid anyway,
    // with the placeholder inode number. It must simply be absent.
    let r = fixture();
    let snapshot = r.vpids();
    r.vpids.borrow_mut().remove(&512);

    let mut actor = Page { out: Vec::new(), budget: usize::MAX };
    let mut ctx = DirContext::new(0, &mut actor);
    emit_resolved(proc_root_dynamic(&snapshot), |n| r.lookup(n), &mut ctx).expect("readdir");

    assert!(!actor.out.iter().any(|e| e.0 == "512"), "the exited pid is absent, not a d_ino==0 record");
    for (name, ino, _) in &actor.out { assert_ne!(*ino, 0, "entry {name:?} emitted d_ino == 0"); }
    for p in [1u32, 2, 47, 4096] {
        assert!(actor.out.iter().any(|e| e.0 == decimal_name(p)), "surviving pid {p} still listed");
    }
}

#[test]
fn a_seekdir_cookie_names_the_same_suffix_across_a_fork_and_exit() {
    let r = fixture();
    let (_, cookie) = page(&r, 0, 3);
    let before = drain_from(&r, cookie);

    r.vpids.borrow_mut().insert(31337);
    r.vpids.borrow_mut().remove(&31337);

    let after = drain_from(&r, cookie);
    assert_eq!(before, after, "the cookie names the same suffix across a fork+exit");
}

fn drain_from(r: &Registry, mut pos: u64) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let (got, end) = page(r, pos, 3);
        if got.is_empty() { break; }
        out.extend(got.into_iter().map(|e| e.0));
        pos = end;
    }
    out
}
