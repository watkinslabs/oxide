//! Name resolution: `lookup` finds a stored name, refuses one that is not
//! there, and the listing itself comes back in the sorted order `lookup`
//! relies on to stop early.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::opts::Options;
use crate::test_image::Builder;
use crate::uapi::itype;
use crate::volume::Volume;

fn mounted() -> (Volume<sectors::MemImage>, crate::volume::Inode) {
    let img = Builder::new()
        .file("zebra", b"z")
        .file("apple", b"a")
        .file("mango", b"m")
        .symlink("link", "apple")
        .build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    (vol, root)
}

#[test]
fn read_dir_returns_entries_in_sorted_name_order() {
    let (vol, root) = mounted();
    let names: Vec<_> = vol.read_dir(&root).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["apple", "link", "mango", "zebra"]);
}

#[test]
fn next_pos_is_strictly_increasing_and_offset_past_the_synthetic_entries() {
    let (vol, root) = mounted();
    let entries = vol.read_dir(&root).unwrap();
    let mut prev = crate::volume::dir::SYNTHETIC_ENTRIES;
    for e in &entries {
        assert!(e.next_pos > prev);
        prev = e.next_pos;
    }
}

#[test]
fn lookup_finds_a_stored_name() {
    let (vol, root) = mounted();
    let hit = vol.lookup(&root, "mango").unwrap();
    assert_eq!(hit.name, "mango");
    let inode = vol.read_inode(hit.reference).unwrap();
    assert_eq!(inode.type_word, itype::REG);
    assert_eq!(vol.read_whole(&inode).unwrap(), b"m");
}

#[test]
fn lookup_of_a_missing_name_is_enoent() {
    let (vol, root) = mounted();
    assert_eq!(vol.lookup(&root, "nowhere").err(), Some(Errno::Enoent));
}

#[test]
fn lookup_of_a_name_sorting_past_every_entry_is_enoent() {
    let (vol, root) = mounted();
    assert_eq!(vol.lookup(&root, "zzzzz").err(), Some(Errno::Enoent));
}

#[test]
fn lookup_resolves_a_symlink_target() {
    let (vol, root) = mounted();
    let hit = vol.lookup(&root, "link").unwrap();
    let inode = vol.read_inode(hit.reference).unwrap();
    assert_eq!(inode.type_word, itype::SYMLINK);
    let crate::volume::Kind::Symlink { target } = &inode.kind else { panic!("not a symlink") };
    assert_eq!(target, b"apple");
}

#[test]
fn a_name_longer_than_the_format_allows_is_refused_without_touching_the_medium() {
    let (vol, root) = mounted();
    let long = "x".repeat(crate::limits::NAME_LEN + 1);
    assert_eq!(vol.lookup(&root, &long).err(), Some(Errno::Enametoolong));
}

/// An EMPTY directory stores size 3 — the count of the two names it does not
/// store, plus one. Its listing occupies no bytes, so the walk must not read a
/// single header: in a real image the bytes at its listing position belong to
/// the NEXT directory in the shared metadata stream, and reading them lists
/// another directory's names under this one.
///
/// Built by pointing an inode of size 3 at a listing that DOES have content —
/// the fixture's root — which is exactly the situation an empty directory is
/// in, and the strongest form of the case: anything the walk reads is visibly
/// wrong. Observed as a boot in which systemd ran fifteen unit generators as
/// environment generators, `system-environment-generators` being empty.
#[test]
fn an_empty_directory_lists_nothing_of_its_neighbour() {
    let (vol, root) = mounted();
    let mut empty = root.clone();
    empty.size = crate::volume::dir::SYNTHETIC_ENTRIES;
    assert!(!vol.read_dir(&root).unwrap().is_empty(), "the fixture's root has entries to spill");
    assert_eq!(vol.read_dir(&empty).unwrap(), Vec::new(),
        "an empty directory read its neighbour's listing");
}

/// The same bound seen from the other side: a directory's walk stops at its
/// own last entry rather than three bytes into what follows.
#[test]
fn a_listing_stops_at_the_size_the_directory_stores() {
    let (vol, root) = mounted();
    let all = vol.read_dir(&root).unwrap();
    let last = all.last().expect("entries");
    assert_eq!(last.next_pos, root.size,
        "the last entry must end exactly at the directory's stored size");
}
