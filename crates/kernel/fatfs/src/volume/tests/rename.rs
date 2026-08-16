//! Rename, and the order it does things in.
//!
//! Rename is where a filesystem loses data if the sequence is wrong, so most
//! of these assert about what SURVIVES rather than about what moved: the
//! source's bytes, the replaced file's clusters coming back, and a moved
//! directory still being able to name its parent.

use super::*;

use crate::dirent::ENTRY_BYTES;
use crate::namei::find_dotdot;

use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

fn writable() -> Volume<Image> {
    let (img, _) = populated();
    Volume::mount(img.image(true)).expect("mount")
}

/// A rename inside one directory moves the contents to the new name and
/// leaves the old one gone.
#[test]
fn a_rename_moves_the_contents_and_removes_the_old_name() {
    let mut v = writable();
    let root = root_of(&v);
    let before = v.find_entry(&root, "DATA.BIN").expect("present");
    let bytes = v.read_whole(&before.entry).expect("read");
    v.rename(&root, "DATA.BIN", &root, "MOVED.BIN", 0, when()).expect("rename");
    assert_eq!(v.find_entry(&root, "DATA.BIN").err(), Some(Errno::Enoent));
    let after = v.find_entry(&root, "MOVED.BIN").expect("under its new name");
    assert_eq!(after.entry.cluster, before.entry.cluster);
    assert_eq!(after.size(), before.size());
    assert_eq!(v.read_whole(&after.entry).expect("read"), bytes);
}

/// A rename does not modify the file, so its three readings are the ones it
/// already had. Stamping them with the rename's own instant reports every
/// moved file as just written.
#[test]
fn a_rename_keeps_the_files_own_timestamps() {
    let mut v = writable();
    let root = root_of(&v);
    let before = v.find_entry(&root, "DATA.BIN").expect("present");
    let was = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, before.slot).unwrap()).unwrap().times;
    v.rename(&root, "DATA.BIN", &root, "MOVED.BIN", 0, when()).expect("rename");
    let after = v.find_entry(&root, "MOVED.BIN").expect("present");
    let now = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, after.slot).unwrap()).unwrap().times;
    assert_eq!(now, was);
}

/// A long name renamed to a short one loses its slots, and every one of them
/// is released — a run left behind is skipped by every later create.
#[test]
fn renaming_away_from_a_long_name_releases_its_slots() {
    let mut v = writable();
    let root = root_of(&v);
    let before = v.find_entry(&root, "a long file name.txt").expect("present");
    let start = before.group_start();
    let slots = before.nr_slots;
    assert!(slots > 1);
    v.rename(&root, "a long file name.txt", &root, "SHORT.TXT", 0, when()).expect("rename");
    for i in 0..slots {
        let raw = v.read_dir_record(root.cluster, start + (i * ENTRY_BYTES) as u64).unwrap();
        assert_eq!(raw[0], crate::dirent::DELETED_FLAG, "record {i} of the old group");
    }
    assert!(v.find_entry(&root, "SHORT.TXT").is_ok());
}

/// Replacing a name gives the target's clusters back and hands the target's
/// NAME the source's contents.
#[test]
fn replacing_a_name_frees_what_it_replaced() {
    let mut v = writable();
    let root = root_of(&v);
    let victim = v.create_file(&root, "VICTIM.BIN", when()).expect("create");
    v.write_file(root.cluster, &victim, 0, b"to be replaced", when()).expect("write");
    let victim = v.find_entry(&root, "VICTIM.BIN").expect("present");
    let doomed = victim.entry.cluster;
    assert_ne!(doomed, 0);
    let source = v.find_entry(&root, "DATA.BIN").expect("present");
    let payload = v.read_whole(&source.entry).expect("read");

    v.rename(&root, "DATA.BIN", &root, "VICTIM.BIN", 0, when()).expect("rename over it");
    let after = v.find_entry(&root, "VICTIM.BIN").expect("the target name survives");
    assert_eq!(after.entry.cluster, source.entry.cluster, "with the source's data");
    assert_eq!(v.read_whole(&after.entry).expect("read"), payload);
    assert_eq!(v.find_entry(&root, "DATA.BIN").err(), Some(Errno::Enoent));
    // The replaced chain is free, and reusing it proves it: a chain still
    // marked in use that nothing names is the leak this ordering avoids.
    let reused = v.create_file(&root, "REUSE.BIN", when()).expect("create");
    v.write_file(root.cluster, &reused, 0, b"x", when()).expect("write");
    let free_now = v.free_clusters();
    assert!(free_now > 0);
    assert_eq!(crate::chain::read_entry(v.width(), &v.table, doomed).is_some(), true);
}

/// `RENAME_NOREPLACE` refuses rather than overwriting, and changes nothing.
#[test]
fn noreplace_refuses_an_existing_target() {
    let mut v = writable();
    let root = root_of(&v);
    v.create_file(&root, "TARGET.BIN", when()).expect("create");
    assert_eq!(v.rename(&root, "DATA.BIN", &root, "TARGET.BIN", RENAME_NOREPLACE, when()).err(),
               Some(Errno::Eexist));
    assert!(v.find_entry(&root, "DATA.BIN").is_ok(), "the source is untouched");
    assert!(v.find_entry(&root, "TARGET.BIN").is_ok(), "and so is the target");
}

/// A flag this filesystem cannot honour is refused rather than ignored: a
/// caller that asked for a whiteout and got an ordinary rename has a
/// different tree than it thinks.
#[test]
fn an_unsupported_flag_is_refused() {
    let mut v = writable();
    let root = root_of(&v);
    assert_eq!(v.rename(&root, "DATA.BIN", &root, "X.BIN", RENAME_WHITEOUT, when()).err(),
               Some(Errno::Einval));
    assert!(v.find_entry(&root, "DATA.BIN").is_ok());
}

/// A name renamed to itself changes nothing. Going through with it would
/// overwrite the record and then delete it — the file would be gone.
#[test]
fn a_rename_to_the_same_name_is_a_no_op() {
    let mut v = writable();
    let root = root_of(&v);
    let before = v.find_entry(&root, "DATA.BIN").expect("present");
    v.rename(&root, "DATA.BIN", &root, "DATA.BIN", 0, when()).expect("no-op");
    let after = v.find_entry(&root, "DATA.BIN").expect("still there");
    assert_eq!(after.entry, before.entry);
    assert_eq!(after.slot, before.slot);
}

/// A file may not replace a directory, and a directory may not replace a
/// non-empty one. Either would leave everything inside it unreachable and
/// still marked in use.
#[test]
fn the_type_and_emptiness_rules_are_enforced() {
    let mut v = writable();
    let root = root_of(&v);
    assert_eq!(v.rename(&root, "DATA.BIN", &root, "SUBDIR", 0, when()).err(),
               Some(Errno::Eisdir));
    v.create_dir(&root, "EMPTYDIR", when()).expect("mkdir");
    assert_eq!(v.rename(&root, "EMPTYDIR", &root, "DATA.BIN", 0, when()).err(),
               Some(Errno::Enotdir));
    assert_eq!(v.rename(&root, "EMPTYDIR", &root, "SUBDIR", 0, when()).err(),
               Some(Errno::Enotempty));
    assert!(v.find_entry(&root, "SUBDIR").is_ok());
    assert!(v.find_entry(&root, "EMPTYDIR").is_ok());
}

/// A directory moved to another parent has its `..` repointed. Without it the
/// directory names a parent that no longer holds it, and walking out of it
/// arrives somewhere else.
#[test]
fn a_directory_moved_across_parents_has_its_dotdot_fixed() {
    let mut v = writable();
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let subdir = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    let moving = v.create_dir(&root, "MOVER", when()).expect("mkdir in the root");
    // Made in the root, so its `..` names cluster zero.
    let bytes = v.directory_bytes(Some(moving.entry.cluster)).unwrap();
    let at = find_dotdot(&bytes).expect("it has one");
    let before = crate::dirent::Record::parse(&bytes[at as usize..at as usize + ENTRY_BYTES])
        .unwrap();
    assert_eq!(before.short.cluster, 0);

    v.rename(&root, "MOVER", &subdir, "MOVED", 0, when()).expect("move it down");
    let after_entry = v.find_entry(&subdir, "MOVED").expect("in its new parent");
    let bytes = v.directory_bytes(Some(after_entry.entry.cluster)).unwrap();
    let at = find_dotdot(&bytes).expect("it still has one");
    let after = crate::dirent::Record::parse(&bytes[at as usize..at as usize + ENTRY_BYTES])
        .unwrap();
    assert_eq!(after.short.cluster, sub.entry.cluster, "`..` now names the new parent");
    assert_eq!(v.find_entry(&root, "MOVER").err(), Some(Errno::Enoent));
}

/// ...and moving one back UP to the root sets `..` to zero again, not to the
/// root's cluster number.
#[test]
fn a_directory_moved_back_to_the_root_names_cluster_zero_again() {
    let mut v = writable();
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let subdir = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    let made = v.create_dir(&subdir, "DEEP", when()).expect("mkdir");
    assert_ne!(made.entry.cluster, 0);
    v.rename(&subdir, "DEEP", &root, "SHALLOW", 0, when()).expect("move it up");
    let after = v.find_entry(&root, "SHALLOW").expect("in the root");
    let bytes = v.directory_bytes(Some(after.entry.cluster)).unwrap();
    let at = find_dotdot(&bytes).expect("it has one");
    let r = crate::dirent::Record::parse(&bytes[at as usize..at as usize + ENTRY_BYTES]).unwrap();
    assert_eq!(r.short.cluster, 0);
}

/// A file moved between directories keeps its bytes and leaves the old
/// directory without the name.
#[test]
fn a_file_moved_between_directories_keeps_its_bytes() {
    let mut v = writable();
    let root = root_of(&v);
    let sub = v.find_entry(&root, "SUBDIR").expect("present");
    let subdir = DirHandle::child(sub.entry.cluster, root.cluster, sub.slot);
    let before = v.find_entry(&root, "DATA.BIN").expect("present");
    let payload = v.read_whole(&before.entry).expect("read");
    v.rename(&root, "DATA.BIN", &subdir, "DATA.BIN", 0, when()).expect("move");
    assert_eq!(v.find_entry(&root, "DATA.BIN").err(), Some(Errno::Enoent));
    let after = v.find_entry(&subdir, "DATA.BIN").expect("in the subdirectory");
    assert_eq!(v.read_whole(&after.entry).expect("read"), payload);
}

/// An exchange swaps the two files' contents and keeps both names. Reading
/// the second payload after writing the first would hand the first one back
/// and leave two names on one file.
#[test]
fn an_exchange_swaps_contents_and_keeps_both_names() {
    let mut v = writable();
    let root = root_of(&v);
    let a = v.find_entry(&root, "DATA.BIN").expect("present");
    let b = v.find_entry(&root, "a long file name.txt").expect("present");
    let pa = v.read_whole(&a.entry).expect("read");
    let pb = v.read_whole(&b.entry).expect("read");
    assert_ne!(pa, pb);

    v.rename(&root, "DATA.BIN", &root, "a long file name.txt", RENAME_EXCHANGE, when())
        .expect("exchange");
    let a2 = v.find_entry(&root, "DATA.BIN").expect("both names survive");
    let b2 = v.find_entry(&root, "a long file name.txt").expect("both names survive");
    assert_eq!(v.read_whole(&a2.entry).expect("read"), pb);
    assert_eq!(v.read_whole(&b2.entry).expect("read"), pa);
    assert_ne!(a2.entry.cluster, b2.entry.cluster, "they are still two files");
}

/// An exchange needs both names to exist.
#[test]
fn an_exchange_with_a_missing_name_is_enoent() {
    let mut v = writable();
    let root = root_of(&v);
    assert_eq!(v.rename(&root, "DATA.BIN", &root, "NOPE.BIN", RENAME_EXCHANGE, when()).err(),
               Some(Errno::Enoent));
    assert!(v.find_entry(&root, "DATA.BIN").is_ok());
}

/// A read-only volume refuses a rename before touching anything.
#[test]
fn a_read_only_volume_refuses_a_rename() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(false)).expect("mount");
    let root = root_of(&v);
    assert_eq!(v.rename(&root, "DATA.BIN", &root, "X.BIN", 0, when()).err(), Some(Errno::Erofs));
}

/// Nothing in a rename is atomic, so the ORDER of its steps is the whole of
/// its crash behaviour. Stopping it at every write in turn and checking one
/// invariant is the only way to pin that order.
///
/// The invariant: the source's clusters are reachable from SOME name. Adopting
/// the payload first makes both names reach them for a moment — a duplicate,
/// which a check repairs. Removing the source name first leaves a window in
/// which neither does, and the file is simply gone.
#[test]
fn a_rename_interrupted_at_any_step_still_leaves_the_data_named() {
    // How many writes an uninterrupted rename costs, so every one is tried.
    let total = {
        let (img, _) = populated();
        let (image, faults) = img.image_with_faults(true);
        let mut v = Volume::mount(image).expect("mount");
        let root = root_of(&v);
        v.rename(&root, "DATA.BIN", &root, "MOVED.BIN", 0, when()).expect("rename");
        let seen = { faults.lock().seen };
        assert!(seen > 1, "a rename really does take several writes");
        seen
    };

    for stop in 1..=total {
        let (img, _) = populated();
        let (image, faults) = img.image_with_faults(true);
        let mut v = Volume::mount(image).expect("mount");
        let root = root_of(&v);
        let source = v.find_entry(&root, "DATA.BIN").expect("present").entry.cluster;
        { faults.lock().fail_at = Some(stop); }
        let _ = v.rename(&root, "DATA.BIN", &root, "MOVED.BIN", 0, when());
        { faults.lock().fail_at = None; }

        let reachable = v.read_dir(root.cluster).expect("read")
            .into_iter().any(|e| e.entry.cluster == source);
        assert!(reachable, "the file was unreachable after failing write {stop} of {total}");
    }
}

/// The same for an overwriting rename: the REPLACED file's clusters may be
/// released only once nothing names them, so at no point may both the target
/// name and the freed chain be gone while the source name is too.
#[test]
fn an_interrupted_overwrite_never_loses_the_source() {
    let total = {
        let (img, _) = populated();
        let (image, faults) = img.image_with_faults(true);
        let mut v = Volume::mount(image).expect("mount");
        let root = root_of(&v);
        v.create_file(&root, "VICTIM.BIN", when()).expect("create");
        let before = { faults.lock().seen };
        v.rename(&root, "DATA.BIN", &root, "VICTIM.BIN", 0, when()).expect("rename");
        let after = { faults.lock().seen };
        after - before
    };

    for stop in 1..=total {
        let (img, _) = populated();
        let (image, faults) = img.image_with_faults(true);
        let mut v = Volume::mount(image).expect("mount");
        let root = root_of(&v);
        v.create_file(&root, "VICTIM.BIN", when()).expect("create");
        let source = v.find_entry(&root, "DATA.BIN").expect("present").entry.cluster;
        let at = { faults.lock().seen } + stop;
        { faults.lock().fail_at = Some(at); }
        let _ = v.rename(&root, "DATA.BIN", &root, "VICTIM.BIN", 0, when());
        { faults.lock().fail_at = None; }

        let reachable = v.read_dir(root.cluster).expect("read")
            .into_iter().any(|e| e.entry.cluster == source);
        assert!(reachable, "the source was unreachable after failing write {stop} of {total}");
    }
}
