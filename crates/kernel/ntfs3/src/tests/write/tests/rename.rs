use super::*;
use crate::volume::dirops::{RENAME_EXCHANGE, RENAME_NOREPLACE};

#[test]
fn a_rename_keeps_the_files_bytes_and_its_record() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "before.txt", now()).unwrap();
    v.write_file(made.reference.number, 0, b"contents survive", now()).unwrap();
    v.rename(MFT_REC_ROOT, "before.txt", MFT_REC_ROOT, "after.txt", 0, now()).unwrap();
    assert_eq!(names(&v), alloc::vec!["after.txt"]);
    let hit = v.find_entry(MFT_REC_ROOT, "after.txt").unwrap();
    assert_eq!(hit.reference.number, made.reference.number);
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"contents survive");
}

#[test]
fn a_rename_updates_the_records_own_idea_of_its_name() {
    // A rename that changes only the index leaves a record a checker repairs
    // by renaming the file back.
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "before.txt", now()).unwrap();
    v.rename(MFT_REC_ROOT, "before.txt", MFT_REC_ROOT, "after.txt", 0, now()).unwrap();
    let (bytes, attrs) = v.read_record(made.reference.number).unwrap();
    let recorded: alloc::vec::Vec<_> = v.names_of(&bytes, &attrs)
        .into_iter().map(|f| f.name()).collect();
    assert_eq!(recorded, alloc::vec!["after.txt"]);
}

#[test]
fn a_rename_across_directories_moves_the_name() {
    let mut v = test_image::empty();
    let sub = v.create_dir(MFT_REC_ROOT, "sub", now()).unwrap();
    let file = v.create_file(MFT_REC_ROOT, "moving.txt", now()).unwrap();
    v.write_file(file.reference.number, 0, b"moved", now()).unwrap();
    v.rename(MFT_REC_ROOT, "moving.txt", sub.reference.number, "moved.txt", 0, now()).unwrap();
    assert_eq!(names(&v), alloc::vec!["sub"]);
    let hit = v.lookup("/sub/moved.txt").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"moved");
    // The record's own name record follows it to the new parent.
    let (bytes, attrs) = v.read_record(hit.reference.number).unwrap();
    assert_eq!(v.names_of(&bytes, &attrs)[0].parent.number, sub.reference.number);
}

#[test]
fn a_rename_over_an_existing_name_replaces_it() {
    let mut v = test_image::empty();
    let a = v.create_file(MFT_REC_ROOT, "a", now()).unwrap();
    v.write_file(a.reference.number, 0, b"keep", now()).unwrap();
    let b = v.create_file(MFT_REC_ROOT, "b", now()).unwrap();
    v.write_file(b.reference.number, 0, &alloc::vec![0u8; CLUSTER * 2], now()).unwrap();
    let used = v.used_clusters();
    v.rename(MFT_REC_ROOT, "a", MFT_REC_ROOT, "b", 0, now()).unwrap();
    assert_eq!(names(&v), alloc::vec!["b"]);
    assert_eq!(v.used_clusters(), used - 2, "the replaced file's clusters must go");
    let hit = v.find_entry(MFT_REC_ROOT, "b").unwrap();
    assert_eq!(hit.reference.number, a.reference.number);
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"keep");
}

#[test]
fn noreplace_refuses_rather_than_replacing() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "a", now()).unwrap();
    v.create_file(MFT_REC_ROOT, "b", now()).unwrap();
    assert_eq!(v.rename(MFT_REC_ROOT, "a", MFT_REC_ROOT, "b", RENAME_NOREPLACE, now()).unwrap_err(),
               Errno::Eexist);
    assert_eq!(names(&v).len(), 2);
}

#[test]
fn an_exchange_swaps_two_names_and_keeps_both_records() {
    let mut v = test_image::empty();
    let a = v.create_file(MFT_REC_ROOT, "a", now()).unwrap();
    v.write_file(a.reference.number, 0, b"AAAA", now()).unwrap();
    let b = v.create_file(MFT_REC_ROOT, "b", now()).unwrap();
    v.write_file(b.reference.number, 0, b"BB", now()).unwrap();
    v.rename(MFT_REC_ROOT, "a", MFT_REC_ROOT, "b", RENAME_EXCHANGE, now()).unwrap();
    assert_eq!(names(&v), alloc::vec!["a", "b"]);
    let got_a = v.find_entry(MFT_REC_ROOT, "a").unwrap();
    let got_b = v.find_entry(MFT_REC_ROOT, "b").unwrap();
    assert_eq!(got_a.reference.number, b.reference.number);
    assert_eq!(got_b.reference.number, a.reference.number);
    assert_eq!(v.read_whole(got_a.reference.number).unwrap(), b"BB");
    assert_eq!(v.read_whole(got_b.reference.number).unwrap(), b"AAAA");
}

#[test]
fn renaming_a_name_onto_itself_does_not_remove_it() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "same", now()).unwrap();
    v.rename(MFT_REC_ROOT, "same", MFT_REC_ROOT, "same", 0, now()).unwrap();
    assert_eq!(names(&v), alloc::vec!["same"]);
}

#[test]
fn a_rename_may_not_replace_a_directory_with_a_file() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "f", now()).unwrap();
    v.create_dir(MFT_REC_ROOT, "d", now()).unwrap();
    assert_eq!(v.rename(MFT_REC_ROOT, "f", MFT_REC_ROOT, "d", 0, now()).unwrap_err(),
               Errno::Eisdir);
    assert_eq!(v.rename(MFT_REC_ROOT, "d", MFT_REC_ROOT, "f", 0, now()).unwrap_err(),
               Errno::Enotdir);
}

#[test]
fn a_written_record_still_verifies_its_update_sequence() {
    // A record written without a fresh sequence reads back torn, or worse
    // reads back whole when it was torn.
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "sealed.txt", now()).unwrap();
    v.write_file(made.reference.number, 0, b"payload", now()).unwrap();
    // Reading it back exercises the sequence; a stale one is `Torn`.
    assert!(v.read_record_raw(made.reference.number).is_ok());
}
