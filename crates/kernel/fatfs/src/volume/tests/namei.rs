//! Creating, deleting and removing names against a real volume image.
//!
//! These run the whole stack: a name is turned into records, the records land
//! in a directory's clusters, and the volume is read back through the same
//! reader a mount uses. Nothing is asserted about the intermediate structures
//! — only about what a reader of the medium afterwards sees.

use super::*;

use alloc::string::ToString;

use crate::dirent::{ATTR_DIR, DELETED_FLAG, ENTRY_BYTES};
use crate::namei::{dir_is_empty, DOT, DOTDOT};

/// A writable volume with the standard fixture in it.
fn writable() -> Volume<Image> {
    let (img, _) = populated();
    Volume::mount(img.image(true)).expect("mount")
}

/// The names a directory lists, in order.
fn names<S: SectorSource>(v: &Volume<S>, cluster: Option<u32>) -> Vec<String> {
    v.read_dir(cluster).expect("read").into_iter().map(|e| e.name).collect()
}

/// A created file appears under the name asked for and holds nothing.
#[test]
fn a_created_file_is_found_under_the_name_asked_for() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "NEW.TXT", when()).expect("create");
    assert_eq!(made.size(), 0);
    assert_eq!(made.entry.cluster, 0, "an empty file names no cluster");
    let again = v.find_entry(&root, "NEW.TXT").expect("found again");
    assert_eq!(again.slot, made.slot);
    assert_eq!(again.nr_slots, 1);
}

/// A long name round-trips: it is stored in slots and read back whole, and
/// the slots and the short entry are one contiguous group.
#[test]
fn a_long_name_round_trips_through_the_medium() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "A Rather Long File Name.txt", when()).expect("create");
    assert!(made.nr_slots > 1, "it needed slots");
    let again = v.find_entry(&root, "A Rather Long File Name.txt").expect("found again");
    assert_eq!(again.name, "A Rather Long File Name.txt");
    assert_eq!(again.nr_slots, made.nr_slots);
    assert_eq!(again.group_start(), again.slot - ((again.nr_slots - 1) * ENTRY_BYTES) as u64);
}

/// `uni_xlate` is the legacy Linux spelling: escaped UTF-16 units are stored
/// as their real units and are escaped again when the directory is read.
#[test]
fn unicode_xlate_names_round_trip_through_creation_and_readdir() {
    let (img, _) = populated();
    let mut opts = crate::opts::Options::vfat();
    opts.utf8 = true;
    opts.uni_xlate = true;
    let mut v = Volume::mount_with(img.image(true), opts).expect("mount");
    assert!(!v.options().utf8, "uni_xlate overrides utf8 at mount");
    let root = root_of(&v);
    let name = "Aé:03A9-long-name.txt";
    let made = v.create_file(&root, name, when()).expect("create");
    assert!(made.nr_slots > 1, "the escaped name needs long-name slots");
    assert_eq!(v.find_entry(&root, name).expect("lookup").slot, made.slot);
    assert!(names(&v, root.cluster).contains(&name.to_string()));
}

/// With the UTF-8 exchange flag, long-name units are presented as Unicode
/// rather than through the legacy single-byte conversion path.
#[test]
fn utf8_names_are_returned_as_unicode() {
    let (img, _) = populated();
    let mut opts = crate::opts::Options::vfat();
    opts.utf8 = true;
    let mut v = Volume::mount_with(img.image(true), opts).expect("mount");
    let root = root_of(&v);
    let name = "AéΩ-long-name.txt";
    v.create_file(&root, name, when()).expect("create");
    assert!(names(&v, root.cluster).contains(&name.to_string()));
}

/// A name already there is `EEXIST`, and the directory is left as it was.
#[test]
fn a_duplicate_name_is_refused() {
    let mut v = writable();
    let root = root_of(&v);
    let before = names(&v, root.cluster);
    assert_eq!(v.create_file(&root, "DATA.BIN", when()).err(), Some(Errno::Eexist));
    assert_eq!(names(&v, root.cluster), before);
}

/// A created file's timestamps are the ones it was stamped with, at the
/// granularity each field has. A creation that leaves them zero reports every
/// new file as made at the start of 1980.
#[test]
fn a_created_file_carries_the_time_it_was_made() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "STAMP.TXT", when()).expect("create");
    let raw = v.read_dir_record(root.cluster, made.slot).expect("read record");
    let r = crate::dirent::Record::parse(&raw).expect("a record");
    assert_eq!(r.times.create, when());
    assert_eq!(r.times.access_date, when().date);
    assert_eq!(r.times.modify.date, when().date);
}

/// Unlinking removes every record of the name and gives its clusters back.
#[test]
fn unlinking_removes_the_whole_group_and_frees_the_chain() {
    let mut v = writable();
    let root = root_of(&v);
    let before = v.free_clusters();
    let hit = v.find_entry(&root, "a long file name.txt").expect("present");
    let start = hit.group_start();
    let slots = hit.nr_slots;
    assert!(slots > 1);
    v.unlink(&root, "a long file name.txt", when()).expect("unlink");
    assert_eq!(v.find_entry(&root, "a long file name.txt").err(), Some(Errno::Enoent));
    assert!(v.free_clusters() > before, "its clusters came back");
    // Every record of the group, slots included, is marked free — a slot left
    // behind is one the next name that needs a run of that length skips.
    for i in 0..slots {
        let raw = v.read_dir_record(root.cluster, start + (i * ENTRY_BYTES) as u64).unwrap();
        assert_eq!(raw[0], DELETED_FLAG, "record {i} of the group");
    }
}

/// A directory is not unlinked: the caller wanted the other operation, and
/// removing its record would leave everything inside it unreachable.
#[test]
fn unlink_refuses_a_directory_and_rmdir_refuses_a_file() {
    let mut v = writable();
    let root = root_of(&v);
    assert_eq!(v.unlink(&root, "SUBDIR", when()).err(), Some(Errno::Eisdir));
    assert_eq!(v.rmdir(&root, "DATA.BIN", when()).err(), Some(Errno::Enotdir));
    assert!(v.find_entry(&root, "SUBDIR").is_ok(), "and neither was touched");
    assert!(v.find_entry(&root, "DATA.BIN").is_ok());
}

/// A new directory begins with `.` and `..`, and its cluster is CLEARED
/// first: an unzeroed one makes whatever the medium last held read back as
/// entries, and a scan runs past the real end into them.
#[test]
fn a_new_directory_starts_with_its_two_entries_in_a_cleared_cluster() {
    let (mut img, _) = populated();
    img.scribble_free_clusters();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let root = root_of(&v);
    let made = v.create_dir(&root, "MADE", when()).expect("mkdir");
    assert!(made.is_dir());
    let bytes = v.directory_bytes(Some(made.entry.cluster)).expect("read it");
    assert!(dir_is_empty(&bytes), "it holds nothing but its dots");
    let dot = crate::dirent::Record::parse(&bytes[..ENTRY_BYTES]).unwrap();
    let dotdot = crate::dirent::Record::parse(&bytes[ENTRY_BYTES..2 * ENTRY_BYTES]).unwrap();
    assert_eq!(dot.short.raw_name, DOT);
    assert_eq!(dotdot.short.raw_name, DOTDOT);
    assert_eq!(dot.short.cluster, made.entry.cluster);
    assert_eq!(dot.short.attr, ATTR_DIR);
    // Everything past the two entries is zero, which is what ends a scan.
    assert!(bytes[2 * ENTRY_BYTES..].iter().all(|b| *b == 0), "the cluster was cleared");
}

/// `..` of a directory made in the ROOT names cluster ZERO, not the root's
/// own cluster number. A `..` naming it would be a second way to reach the
/// root, which every checker reports.
#[test]
fn dotdot_of_a_directory_made_in_the_root_names_zero() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_dir(&root, "ATROOT", when()).expect("mkdir");
    let bytes = v.directory_bytes(Some(made.entry.cluster)).expect("read it");
    let dotdot = crate::dirent::Record::parse(&bytes[ENTRY_BYTES..2 * ENTRY_BYTES]).unwrap();
    assert_eq!(dotdot.short.cluster, 0);
}

/// ...and `..` of a directory made in a SUBDIRECTORY names that
/// subdirectory's own cluster.
#[test]
fn dotdot_of_a_nested_directory_names_its_parent() {
    let mut v = writable();
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let handle = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    let made = v.create_dir(&handle, "DEEPER", when()).expect("mkdir");
    let bytes = v.directory_bytes(Some(made.entry.cluster)).expect("read it");
    let dotdot = crate::dirent::Record::parse(&bytes[ENTRY_BYTES..2 * ENTRY_BYTES]).unwrap();
    assert_eq!(dotdot.short.cluster, sub.entry.cluster);
}

/// A directory holding anything cannot be removed, and the refusal changes
/// nothing.
#[test]
fn a_directory_with_a_name_in_it_is_not_removed() {
    let mut v = writable();
    let root = root_of(&v);
    assert_eq!(v.rmdir(&root, "SUBDIR", when()).err(), Some(Errno::Enotempty));
    assert!(v.find_entry(&root, "SUBDIR").is_ok());
    let sub = v.find_entry(&root, "SUBDIR").unwrap();
    assert!(!names(&v, Some(sub.entry.cluster)).is_empty());
}

/// A directory whose only names have been deleted IS empty. Counting a freed
/// record makes a directory that once held a file impossible to remove.
#[test]
fn a_directory_emptied_by_deletion_can_be_removed() {
    let mut v = writable();
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let handle = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    v.unlink(&handle, "nested.txt", when()).expect("unlink the one file");
    let before = v.free_clusters();
    v.rmdir(&root, "SUBDIR", when()).expect("now it is empty");
    assert_eq!(v.find_entry(&root, "SUBDIR").err(), Some(Errno::Enoent));
    assert!(v.free_clusters() > before, "its cluster came back");
}

/// A created name is found again after being written, deleted and recreated
/// in the slot it left — the released slot is reusable, which is the only way
/// a directory stops growing.
#[test]
fn a_released_slot_is_reused_by_the_next_name() {
    let mut v = writable();
    let root = root_of(&v);
    let first = v.create_file(&root, "ONE.TXT", when()).expect("create");
    v.unlink(&root, "ONE.TXT", when()).expect("unlink");
    let second = v.create_file(&root, "TWO.TXT", when()).expect("create");
    assert_eq!(second.slot, first.slot, "the freed record was taken");
}

/// A fixed root cannot grow. Its size is a boot-sector field and the data
/// area begins immediately after it, so a full one is `ENOSPC` while the
/// volume is nearly empty.
#[test]
fn a_full_fixed_root_is_enospc_not_a_larger_root() {
    let mut img = Builder::new();
    let root = img.root_offset();
    img.write_dir(root, &[]);
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let handle = root_of(&v);
    assert!(handle.cluster.is_none(), "the fixture really has a fixed root");
    let mut made = 0usize;
    loop {
        let name = ::alloc::format!("F{made:07}.TXT");
        match v.create_file(&handle, &name, when()) {
            Ok(_) => made += 1,
            Err(e) => { assert_eq!(e, Errno::Enospc); break; }
        }
        assert!(made <= ROOT_ENTRIES, "the root grew past its declared size");
    }
    assert_eq!(made, ROOT_ENTRIES, "every declared slot was usable");
}

/// A subdirectory that fills up GROWS, and the cluster it grows by is cleared
/// before anything is written into it.
#[test]
fn a_subdirectory_grows_when_it_fills() {
    let (mut img, _) = populated();
    img.scribble_free_clusters();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let handle = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    let per = (v.geometry().cluster_bytes() / ENTRY_BYTES as u64) as usize;
    for i in 0..per + 4 {
        let name = ::alloc::format!("G{i:07}.TXT");
        v.create_file(&handle, &name, when()).expect("create in a growing directory");
    }
    let bytes = v.directory_bytes(Some(sub.entry.cluster)).expect("read it");
    assert!(bytes.len() > per * ENTRY_BYTES, "the directory really did grow");
    // Every name is still findable, which it would not be if the growth had
    // left stale bytes reading as an end-of-directory marker part-way through.
    for i in 0..per + 4 {
        let name = ::alloc::format!("G{i:07}.TXT");
        assert!(v.find_entry(&handle, &name).is_ok(), "{name} survived the growth");
    }
}

/// A read-only volume refuses every one of these before touching anything.
#[test]
fn a_read_only_volume_refuses_every_change() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(false)).expect("mount");
    let root = root_of(&v);
    assert_eq!(v.create_file(&root, "NEW.TXT", when()).err(), Some(Errno::Erofs));
    assert_eq!(v.create_dir(&root, "NEWDIR", when()).err(), Some(Errno::Erofs));
    assert_eq!(v.unlink(&root, "DATA.BIN", when()).err(), Some(Errno::Erofs));
    assert_eq!(v.rmdir(&root, "SUBDIR", when()).err(), Some(Errno::Erofs));
}

/// An 8.3-only mount never writes a long-name slot, and folds what it is
/// given into eleven bytes.
///
/// Under the default rule a name too long is CUT to fit rather than refused —
/// which is self-consistent, because a lookup of the same name folds to the
/// same eleven bytes. The strict rule is the one that refuses it, and a mount
/// that wants the refusal asks for `check=s`.
#[test]
fn a_short_only_mount_folds_a_name_into_eleven_bytes() {
    let (img, _) = populated();
    let mut v = Volume::mount_with(img.image(true), crate::opts::Options::msdos()).expect("mount");
    let root = root_of(&v);
    let made = v.create_file(&root, "ok.txt", when()).expect("this one fits");
    assert_eq!(made.nr_slots, 1, "it costs one record, never a slot run");
    assert_eq!(made.entry.raw_name, *b"OK      TXT");
    let cut = v.create_file(&root, "a-name-far-too-long.txt", when()).expect("cut to fit");
    assert_eq!(cut.entry.raw_name, *b"A-NAME-FTXT");
    assert!(v.find_entry(&root, "a-name-far-too-long.txt").is_ok(), "and it is found again");
}

/// Under `check=s` the same name is refused instead, and nothing is written.
#[test]
fn a_strict_short_only_mount_refuses_a_name_that_would_be_cut() {
    let (img, _) = populated();
    let mut opts = crate::opts::Options::msdos();
    opts.check = crate::name::msdos::NameCheck::Strict;
    let mut v = Volume::mount_with(img.image(true), opts).expect("mount");
    let root = root_of(&v);
    assert_eq!(v.create_file(&root, "a-name-far-too-long.txt", when()).err(),
               Some(Errno::Einval));
    assert_eq!(v.find_entry(&root, "a-name-far-too-long.txt").err(), Some(Errno::Enoent));
}
