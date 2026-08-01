//! The tmpfs readdir CURSOR over a REAL tmpfs directory.
//!
//! Before F775 `shmem`'s `iterate` was `kids.iter().skip(ctx.pos)` — an ORDINAL
//! index into the live `BTreeMap`. `getdents` is paginated, so a create or an
//! unlink between two calls shifted every later ordinal and the listing
//! duplicated or skipped names; a `seekdir(3)` cookie taken before the mutation
//! named a different entry after it. /tmp and /run are written by concurrent
//! processes constantly, so this is the hottest instance of the defect.
//!
//! The cookie is now a hash of the NAME (`vfs::readdir_cookie`), which no
//! neighbour's arrival or departure can move.

use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;

use fs::tmpfs::TmpfsFs;
use vfs::inode_ops::CreateCtx;
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

/// One `getdents` call: resume at `pos`, take at most `budget` records, return
/// the records taken and the cursor to resume from.
fn page(dir: &InodeRef, pos: u64, budget: usize) -> (Vec<(String, u64, FileType)>, u64) {
    let mut actor = Page { out: Vec::new(), budget };
    let mut ctx = DirContext::new(pos, &mut actor);
    dir.readdir(&mut ctx).expect("readdir");
    let end = ctx.pos;
    (actor.out, end)
}

/// Drain the whole directory `budget` records at a time.
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

/// A tmpfs `/dir` holding `names` as regular files.
fn fixture(names: &[&str]) -> (std::sync::Arc<TmpfsFs>, InodeRef) {
    let fs = TmpfsFs::new(String::from("fixture"));
    let root = fs.root_inode();
    let dir = root.mkdir("dir", 0o755, &CreateCtx::root()).expect("mkdir dir");
    for n in names { dir.create_child(n, 0o644, &CreateCtx::root()).expect("create"); }
    (fs, dir)
}

#[test]
fn a_full_listing_is_complete_and_duplicate_free_at_every_page_size() {
    let names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf"];
    let (_fs, dir) = fixture(&names);
    let want: BTreeSet<String> = names.iter().map(|s| String::from(*s)).collect();
    for budget in 1..=names.len() + 2 {
        let got = drain(&dir, budget);
        assert_eq!(got.len(), names.len(), "page size {budget}: exactly one record per entry");
        assert_eq!(got.iter().map(|r| r.0.clone()).collect::<BTreeSet<_>>(), want, "page size {budget}");
    }
}

#[test]
fn no_entry_is_emitted_with_d_ino_zero() {
    // `d_ino == 0` is how a filesystem marks a deleted placeholder; a live
    // entry carrying it makes `ls -i`, `find -inum` and rsync's dedupe wrong.
    let (_fs, dir) = fixture(&["a", "b", "c", "d"]);
    let got = drain(&dir, 2);
    assert_eq!(got.len(), 4);
    for (name, ino, _) in got { assert_ne!(ino, 0, "entry {name:?} emitted d_ino == 0"); }
}

#[test]
fn creating_an_entry_mid_listing_neither_duplicates_nor_skips() {
    let initial = ["aa", "bb", "cc", "dd", "ee", "ff"];
    let (_fs, dir) = fixture(&initial);

    // Page 1: three records, remember the resume cursor.
    let (first, pos) = page(&dir, 0, 3);
    assert_eq!(first.len(), 3);

    // Create names that sort BEFORE and AFTER what was already emitted. Under
    // an ordinal cursor every one of these shifts the index of every later
    // entry, so the resumed pages re-emit or drop entries.
    for n in ["a0", "b0", "m0", "zz"] { dir.create_child(n, 0o644, &CreateCtx::root()).expect("create"); }

    let mut all: Vec<String> = first.iter().map(|r| r.0.clone()).collect();
    let mut p = pos;
    loop {
        let (got, end) = page(&dir, p, 3);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|r| r.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for n in initial {
        assert!(uniq.contains(n), "entry {n:?} present for the whole listing was skipped: {all:?}");
    }
}

#[test]
fn unlinking_an_entry_mid_listing_neither_duplicates_nor_skips() {
    let initial = ["aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh"];
    let (_fs, dir) = fixture(&initial);

    let (first, pos) = page(&dir, 0, 3);
    let emitted: Vec<String> = first.iter().map(|r| r.0.clone()).collect();

    // Remove two entries that were ALREADY emitted: under an ordinal cursor the
    // whole tail slides down by two and two survivors are silently skipped.
    for n in emitted.iter().take(2) { dir.unlink_child(n).expect("unlink"); }

    let mut all = emitted.clone();
    let mut p = pos;
    loop {
        let (got, end) = page(&dir, p, 3);
        if got.is_empty() { break; }
        all.extend(got.into_iter().map(|r| r.0));
        p = end;
    }

    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    for n in initial.iter().filter(|n| !emitted.iter().take(2).any(|e| e == *n)) {
        assert!(uniq.contains(*n), "surviving entry {n:?} was skipped: {all:?}");
    }
}

#[test]
fn a_seekdir_cookie_names_the_same_suffix_across_a_create_and_unlink() {
    let (_fs, dir) = fixture(&["one", "two", "three", "four", "five"]);
    let (_, cookie) = page(&dir, 0, 2);
    let before: Vec<String> = drain_from(&dir, cookie);

    dir.create_child("transient", 0o644, &CreateCtx::root()).expect("create");
    dir.unlink_child("transient").expect("unlink");

    let after: Vec<String> = drain_from(&dir, cookie);
    assert_eq!(before, after, "the cookie names the same suffix across a create+unlink");
}

fn drain_from(dir: &InodeRef, mut pos: u64) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let (got, end) = page(dir, pos, 2);
        if got.is_empty() { break; }
        out.extend(got.into_iter().map(|r| r.0));
        pos = end;
    }
    out
}
