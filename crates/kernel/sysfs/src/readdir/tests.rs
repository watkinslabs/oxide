// Cursor contract for sysfs's synthetic directories: a paginated `getdents`
// over a LIVE registry must stay complete and duplicate-free, and must never
// emit `d_ino == 0`.
//
// The ordinal cursor these directories used before F775 cannot be caught by a
// boot: it needs a registry mutation at a controlled point mid-listing, which
// is exactly what `disk_added_and_removed_mid_listing_*` does.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::format;
use alloc::vec::Vec;

use sync::TaskList;
use vfs::{DirContext, DirEmit, FileType, InodeRef};

use crate::block::make_sys_block_inode;

/// Test disks are one 512-byte block; only their names matter here.
const TEST_BLOCK_SIZE: u32 = 512;
const TEST_BLOCK_COUNT: u64 = 1;
/// Registry serial that gives a disk dir its optional `device/` child.
const TEST_SERIAL: &str = "oxreaddir-test";
/// Page budgets exercised by every pagination test — 1 forces a resume per
/// entry, the largest drains in one call, the rest land mid-listing.
const PAGE_BUDGETS: &[usize] = &[1, 2, 3, 5, 64];
/// `d_ino == 0` marks a DELETED placeholder entry; no live entry may carry it.
const DELETED_PLACEHOLDER_INO: u64 = 0;

/// Emit actor with a hard record budget — the pagination `getdents` imposes.
struct Page {
    out: Vec<(String, u64)>,
    budget: usize,
}
impl DirEmit for Page {
    fn emit(&mut self, name: &str, ino: u64, _d: FileType, _next: u64) -> bool {
        if self.out.len() == self.budget { return false; }
        self.out.push((String::from(name), ino));
        true
    }
}

/// One `getdents` call: resume at `pos`, take at most `budget` records, return
/// the records taken and the cursor to resume from.
fn page(dir: &InodeRef, pos: u64, budget: usize) -> (Vec<(String, u64)>, u64) {
    let mut actor = Page { out: Vec::new(), budget };
    let end = {
        let mut ctx = DirContext::new(pos, &mut actor);
        dir.readdir(&mut ctx).expect("readdir");
        ctx.pos
    };
    (actor.out, end)
}

/// Drain a whole directory `budget` records at a time.
fn drain(dir: &InodeRef, budget: usize) -> Vec<(String, u64)> {
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

fn names_of(records: &[(String, u64)]) -> Vec<&str> {
    records.iter().map(|(n, _)| n.as_str()).collect()
}

fn count_of(records: &[(String, u64)], name: &str) -> usize {
    records.iter().filter(|(n, _)| n == name).count()
}

/// No live entry may be reported as a deleted placeholder.
fn assert_no_zero_ino(records: &[(String, u64)]) {
    for (name, ino) in records.iter() {
        assert_ne!(*ino, DELETED_PLACEHOLDER_INO, "{name} emitted with d_ino == 0");
    }
}

fn register_disk(name: &str) {
    let dev: Arc<dyn block::BlockDevice> =
        block::MemDisk::<TaskList>::new(TEST_BLOCK_SIZE, TEST_BLOCK_COUNT);
    assert_ne!(block::registry::register(name, dev), 0);
}

fn register_disk_with_serial(name: &str) {
    let dev: Arc<dyn block::BlockDevice> =
        block::MemDisk::<TaskList>::new(TEST_BLOCK_SIZE, TEST_BLOCK_COUNT);
    assert_ne!(block::registry::register_with_serial(name, Some(TEST_SERIAL), dev), 0);
}

/// Disk names owned by one test. The registry is global and other tests
/// register into it concurrently, so every assertion is scoped to these.
fn disk_names(prefix: &str, count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{prefix}{i}")).collect()
}

// ------------------------------------------ dynamic-children dir: /sys/block --

#[test]
fn sys_block_paginates_completely_at_every_page_size() {
    let names = disk_names("rdblkpage", 5);
    for name in names.iter() { register_disk(name); }
    let root = make_sys_block_inode();

    for budget in PAGE_BUDGETS.iter().copied() {
        let got = drain(&root, budget);
        assert_no_zero_ino(&got);
        for name in names.iter() {
            assert_eq!(count_of(&got, name), 1,
                "budget {budget}: {name} appears {} times, want 1", count_of(&got, name));
        }
    }

    for name in names.iter() { assert!(block::registry::unregister(name)); }
}

#[test]
fn sys_block_disk_added_and_removed_mid_listing_neither_duplicates_nor_skips() {
    // Four disks registered in order; the listing is taken in two pages with a
    // registry mutation in between. Under the old ORDINAL cursor, dropping a
    // disk that the first page already emitted shifted every later ordinal, so
    // the resumed page skipped a disk that was present the whole time.
    let names = disk_names("rdblkmut", 4);
    for name in names.iter() { register_disk(name); }
    let root = make_sys_block_inode();

    // `/sys/block` also lists disks other tests own, so page until one of THIS
    // test's disks has been emitted — that one is the mid-listing removal.
    let mut all: Vec<(String, u64)> = Vec::new();
    let mut pos = 0u64;
    let dropped = loop {
        let (got, end) = page(&root, pos, 2);
        assert!(!got.is_empty(), "listing ended before any owned disk appeared");
        assert_no_zero_ino(&got);
        all.extend(got);
        pos = end;
        if let Some(name) = all.iter().map(|(n, _)| n).find(|n| names.contains(n)) {
            break name.clone();
        }
    };

    // Mutate: add a fifth disk, then remove one the listing already emitted.
    let added = String::from("rdblkmutadded");
    register_disk(&added);
    assert!(block::registry::unregister(&dropped));

    loop {
        let (got, end) = page(&root, pos, 2);
        if got.is_empty() { break; }
        assert_no_zero_ino(&got);
        all.extend(got);
        pos = end;
    }

    // Every disk present for the WHOLE listing appears exactly once.
    for name in names.iter().filter(|n| **n != dropped) {
        assert_eq!(count_of(&all, name), 1,
            "{name} was present throughout but appears {} times", count_of(&all, name));
    }
    // The removed disk is never listed twice either.
    assert!(count_of(&all, &dropped) <= 1, "{dropped} duplicated across the mutation");

    assert!(block::registry::unregister(&added));
    for name in names.iter().filter(|n| **n != dropped) {
        assert!(block::registry::unregister(name));
    }
}

#[test]
fn sys_block_lists_in_name_cookie_order_not_registration_order() {
    // The cursor is a hash of the NAME, so the listing order is a property of
    // the names alone — it does not track the order disks were registered, and
    // therefore does not move when a neighbour is registered or removed.
    let names = disk_names("rdblkord", 6);
    for name in names.iter() { register_disk(name); }

    let listed: Vec<String> = names_of(&drain(&make_sys_block_inode(), 64)).iter()
        .filter(|n| n.starts_with("rdblkord")).map(|n| String::from(*n)).collect();
    let mut want = names.clone();
    want.sort_by_key(|n| vfs::name_cookie(n));
    assert_eq!(listed, want);
    // Guard the test itself: registration order and cookie order must differ,
    // or this would pass against an ordinal cursor too.
    assert_ne!(want, names);

    for name in names.iter() { assert!(block::registry::unregister(name)); }
}

// ------------------------------- static-attr dir: /sys/block/<dev> and queue/ --

#[test]
fn disk_dir_paginates_completely_at_every_page_size() {
    let name = "rdblkattrs";
    register_disk_with_serial(name);
    let dir = make_sys_block_inode().lookup(name).expect("disk dir");

    let full = drain(&dir, 64);
    assert_no_zero_ino(&full);
    // Static attrs + `queue/` + `device/` (serial present) + `subsystem`.
    for want in ["size", "ro", "removable", "dev", "uevent", "queue", "device", "subsystem"] {
        assert_eq!(count_of(&full, want), 1, "{want} missing or duplicated");
    }

    for budget in PAGE_BUDGETS.iter().copied() {
        let got = drain(&dir, budget);
        assert_no_zero_ino(&got);
        assert_eq!(names_of(&got), names_of(&full), "budget {budget} changed the listing");
    }

    assert!(block::registry::unregister(name));
}

#[test]
fn queue_dir_paginates_completely_at_every_page_size() {
    let name = "rdblkqueue";
    register_disk(name);
    let dir = make_sys_block_inode().lookup(name).expect("disk dir")
        .lookup("queue").expect("queue dir");

    let full = drain(&dir, 64);
    assert_no_zero_ino(&full);
    for want in ["logical_block_size", "physical_block_size", "minimum_io_size",
                 "optimal_io_size", "discard_max_bytes", "stable_writes"] {
        assert_eq!(count_of(&full, want), 1, "{want} missing or duplicated");
    }
    for budget in PAGE_BUDGETS.iter().copied() {
        assert_eq!(names_of(&drain(&dir, budget)), names_of(&full),
            "budget {budget} changed the listing");
    }

    assert!(block::registry::unregister(name));
}

#[test]
fn a_name_whose_lookup_fails_is_not_listed_at_all() {
    // `DiskDirOps` offers `device/` for every disk; the lookup that resolves its
    // ino is what decides. A disk with no registry serial has no `device`, so
    // the entry must VANISH from the listing — not appear with `d_ino == 0`.
    let name = "rdblknoserial";
    register_disk(name);
    let dir = make_sys_block_inode().lookup(name).expect("disk dir");

    let got = drain(&dir, 64);
    assert_no_zero_ino(&got);
    assert_eq!(count_of(&got, "device"), 0, "device listed for a disk with no serial");
    assert_eq!(count_of(&got, "queue"), 1);

    assert!(block::registry::unregister(name));
}
