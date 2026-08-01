//! The synthetic-filesystem readdir CURSOR (Linux fs/kernfs/dir.c
//! `kernfs_fop_readdir`). Every pseudo filesystem built on `PseudoDir` — devfs,
//! devpts, sysfs's static tree, procfs's registered tree, tracefs/debugfs,
//! configfs — shares this one loop, so these are the tests for all of them.
//!
//! Before F775 the cursor was an ORDINAL index into a freshly-snapshotted child
//! vector. `getdents` is paginated, so creating or removing an entry between two
//! calls shifted every later ordinal and the listing duplicated or skipped
//! entries. A boot cannot show that — it needs a mutation at a controlled point
//! mid-listing, which is exactly what these tests do.

use std::collections::BTreeSet;
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use kernfs::{PseudoDir, PseudoSymlink};
use vfs::readdir_cookie::{name_cookie, order_by_cookie, CookieEntry, COOKIE_MAX, COOKIE_MIN};
use vfs::{DirContext, DirEmit, FileType};

fn root() -> Arc<PseudoDir> { PseudoDir::new_root(0x5000_0001, 0xDEAD) }

fn add(r: &Arc<PseudoDir>, name: &str, ino: u64) {
    r.insert_path(&std::format!("/{name}"), PseudoSymlink::new(ino, 0, name.as_bytes()));
}

/// Emit actor with a hard record budget — the pagination `getdents` imposes.
struct Page {
    out: Vec<(String, u64)>,
    budget: usize,
    /// Resume cursor of the LAST accepted record, i.e. the `d_off` a
    /// `telldir(3)` after this page would report.
    next: u64,
}
impl Page {
    fn new(budget: usize) -> Self { Self { out: Vec::new(), budget, next: 0 } }
}
impl DirEmit for Page {
    fn emit(&mut self, name: &str, ino: u64, _d: FileType, next: u64) -> bool {
        if self.out.len() == self.budget { return false; }
        self.out.push((String::from(name), ino));
        self.next = next;
        true
    }
}

/// One `getdents` call: resume at `pos`, take at most `budget` records, return
/// the names taken and the cursor to resume from.
fn page(r: &Arc<PseudoDir>, pos: u64, budget: usize) -> (Vec<(String, u64)>, u64) {
    let mut actor = Page::new(budget);
    let mut ctx = DirContext::new(pos, &mut actor);
    r.as_inode().readdir(&mut ctx).expect("readdir");
    let end = ctx.pos;
    (actor.out, end)
}

/// Drain the whole directory `budget` records at a time.
fn drain(r: &Arc<PseudoDir>, budget: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = 0u64;
    loop {
        let (got, end) = page(r, pos, budget);
        if got.is_empty() { break; }
        names.extend(got.into_iter().map(|(n, _)| n));
        pos = end;
    }
    names
}

// ------------------------------------------------------------- cookie space --

#[test]
fn a_name_cookie_never_lands_on_the_reserved_dot_cursors() {
    // Cursors 0 and 1 are `.` and `..`; a child that hashed onto them would be
    // emitted a second time by the dots wrapper's cursor space.
    for n in ["", ".", "..", "a", "self", "thread-self", "0", "zram0", "999999"] {
        let c = name_cookie(n);
        assert!(c >= COOKIE_MIN, "{n:?} cookie {c} collides with `.`/`..`");
        assert!(c <= COOKIE_MAX, "{n:?} cookie {c} leaves room for +1 and the dots shift");
    }
}

#[test]
fn a_name_cookie_depends_only_on_the_name() {
    // The entire premise: the cookie must not encode position, so it cannot
    // move when a neighbour appears or disappears.
    assert_eq!(name_cookie("queue"), name_cookie("queue"));
    assert_ne!(name_cookie("queue"), name_cookie("quene"));
}

#[test]
fn colliding_cookies_are_separated_so_no_entry_shares_a_position() {
    let mut es = std::vec![
        CookieEntry { cookie: 100, name: String::from("b"), ino: 2, d_type: FileType::Regular },
        CookieEntry { cookie: 100, name: String::from("a"), ino: 1, d_type: FileType::Regular },
        CookieEntry { cookie: 100, name: String::from("c"), ino: 3, d_type: FileType::Regular },
    ];
    order_by_cookie(&mut es);
    assert_eq!(es.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), std::vec!["a", "b", "c"],
        "a collision group orders by name");
    assert_eq!(es.iter().map(|e| e.cookie).collect::<Vec<_>>(), std::vec![100, 101, 102],
        "and each takes a distinct position");
}

// ----------------------------------------------------------- basic listing --

#[test]
fn a_full_listing_is_complete_and_duplicate_free_at_every_page_size() {
    let r = root();
    let want: BTreeSet<String> =
        ["z", "a", "m", "queue", "0", "zram0", "self"].iter().map(|s| String::from(*s)).collect();
    for (i, n) in want.iter().enumerate() { add(&r, n, 100 + i as u64); }

    for budget in 1..=want.len() + 2 {
        let got = drain(&r, budget);
        assert_eq!(got.len(), want.len(), "page size {budget}: exactly one record per entry");
        assert_eq!(got.iter().cloned().collect::<BTreeSet<_>>(), want, "page size {budget}");
    }
}

#[test]
fn cookies_strictly_increase_across_a_listing() {
    // `seekdir(3)`/`telldir(3)` require a monotone cursor: a page's resume
    // cookie must be greater than every cookie already consumed.
    let r = root();
    for (i, n) in ["delta", "alpha", "charlie", "bravo"].iter().enumerate() { add(&r, n, 200 + i as u64); }
    let mut pos = 0u64;
    let mut seen = Vec::new();
    loop {
        let (got, end) = page(&r, pos, 1);
        if got.is_empty() { break; }
        assert!(end > pos, "cursor advanced past the record just emitted");
        seen.push(got[0].0.clone());
        pos = end;
    }
    assert_eq!(seen.len(), 4);
}

// ------------------------------------------------- the reason cookies exist --

#[test]
fn inserting_an_entry_mid_listing_neither_duplicates_nor_skips() {
    let r = root();
    let initial = ["aa", "bb", "cc", "dd", "ee", "ff"];
    for (i, n) in initial.iter().enumerate() { add(&r, n, 300 + i as u64); }

    // Page 1: take three records, remember the resume cursor.
    let (first, pos) = page(&r, 0, 3);
    assert_eq!(first.len(), 3);
    let emitted: BTreeSet<String> = first.iter().map(|(n, _)| n.clone()).collect();

    // Mutate: insert several new names, some of which sort BEFORE the entries
    // already emitted. With an ordinal cursor each of these shifts the index of
    // every later entry, so the resumed page re-emits or drops entries.
    for (i, n) in ["a0", "b0", "zz", "m0"].iter().enumerate() { add(&r, n, 400 + i as u64); }

    // Page 2..n: drain from the SAME cookie taken before the mutation.
    let mut rest = Vec::new();
    let mut p = pos;
    loop {
        let (got, end) = page(&r, p, 3);
        if got.is_empty() { break; }
        rest.extend(got.into_iter().map(|(n, _)| n));
        p = end;
    }

    // No entry appears twice across the whole listing.
    let mut all = Vec::new();
    all.extend(emitted.iter().cloned());
    all.extend(rest.iter().cloned());
    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");

    // Every entry that existed at the START of the listing appears exactly once.
    for n in initial {
        assert!(uniq.contains(n), "entry {n:?} present for the whole listing was skipped: {all:?}");
    }
}

#[test]
fn removing_an_entry_mid_listing_neither_duplicates_nor_skips() {
    let r = root();
    let initial = ["aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh"];
    for (i, n) in initial.iter().enumerate() { add(&r, n, 500 + i as u64); }

    let (first, pos) = page(&r, 0, 3);
    let emitted: Vec<String> = first.iter().map(|(n, _)| n.clone()).collect();

    // Remove two entries that were ALREADY emitted. Under an ordinal cursor the
    // whole tail slides down by two and two entries are silently skipped.
    let already = emitted.clone();
    for n in already.iter().take(2) { assert!(r.remove_subtree(&std::format!("/{n}")) > 0, "removed {n}"); }

    let mut rest = Vec::new();
    let mut p = pos;
    loop {
        let (got, end) = page(&r, p, 3);
        if got.is_empty() { break; }
        rest.extend(got.into_iter().map(|(n, _)| n));
        p = end;
    }

    let mut all = emitted.clone();
    all.extend(rest.iter().cloned());
    let uniq: BTreeSet<String> = all.iter().cloned().collect();
    assert_eq!(all.len(), uniq.len(), "an entry was emitted twice: {all:?}");
    // Every survivor must be in the listing exactly once.
    for n in initial.iter().filter(|n| !already.iter().any(|e| e == *n)) {
        assert!(uniq.contains(*n), "surviving entry {n:?} was skipped: {all:?}");
    }
}

#[test]
fn a_seekdir_cookie_still_names_the_same_position_after_a_mutation() {
    // `telldir(3)` -> mutate -> `seekdir(3)`: the suffix a cookie names must not
    // change identity because a sibling was created. This is the property an
    // ordinal cursor cannot have.
    let r = root();
    for (i, n) in ["one", "two", "three", "four", "five"].iter().enumerate() { add(&r, n, 600 + i as u64); }

    let (_, cookie) = page(&r, 0, 2);
    let before: Vec<String> = drain_from(&r, cookie);

    add(&r, "inserted-elsewhere", 700);
    assert!(r.remove_subtree("/inserted-elsewhere") > 0, "removed");

    let after: Vec<String> = drain_from(&r, cookie);
    assert_eq!(before, after, "the cookie names the same suffix across a create+unlink");
}

fn drain_from(r: &Arc<PseudoDir>, mut pos: u64) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let (got, end) = page(r, pos, 2);
        if got.is_empty() { break; }
        out.extend(got.into_iter().map(|(n, _)| n));
        pos = end;
    }
    out
}

#[test]
fn every_entry_reports_its_real_inode_number() {
    // `d_ino == 0` is how a filesystem says "deleted placeholder"; the shared
    // loop carries the child's own ino, so it can never emit one.
    let r = root();
    for (i, n) in ["p", "q", "r"].iter().enumerate() { add(&r, n, 800 + i as u64); }
    let (got, _) = page(&r, 0, 16);
    assert_eq!(got.len(), 3);
    for (name, ino) in got {
        assert_ne!(ino, 0, "entry {name:?} emitted d_ino == 0");
    }
}
