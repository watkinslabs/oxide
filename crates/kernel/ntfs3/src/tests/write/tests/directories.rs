use super::*;

#[test]
fn a_deleted_name_releases_its_record_and_its_clusters() {
    let mut v = test_image::empty();
    let before_clusters = v.used_clusters();
    let before_records = v.space().records_free;
    let made = v.create_file(MFT_REC_ROOT, "temp.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![9u8; CLUSTER * 3], now()).unwrap();
    assert!(v.used_clusters() > before_clusters);
    v.unlink(MFT_REC_ROOT, "temp.bin", now()).unwrap();
    assert_eq!(v.used_clusters(), before_clusters);
    assert_eq!(v.space().records_free, before_records);
    assert!(names(&v).is_empty());
    // A freed record's bytes are still a plausible record; every path that
    // reaches one must refuse it, or a deletion resurrects the file.
    assert_eq!(v.stat(made.reference.number).unwrap_err(), Errno::Enoent);
    assert_eq!(v.read_whole(made.reference.number).unwrap_err(), Errno::Enoent);
    assert_eq!(v.read_file(made.reference.number, 0, &mut [0u8; 8]).unwrap_err(), Errno::Enoent);
    let dir = v.create_dir(MFT_REC_ROOT, "gone", now()).unwrap();
    v.rmdir(MFT_REC_ROOT, "gone", now()).unwrap();
    assert_eq!(v.read_dir(dir.reference.number).unwrap_err(), Errno::Enoent);
    assert!(v.open_index(dir.reference.number).is_err());
}

#[test]
fn a_reused_record_takes_a_new_sequence() {
    // Restarting the sequence is how a stale reference silently names the
    // wrong file.
    let mut v = test_image::empty();
    let first = v.create_file(MFT_REC_ROOT, "one", now()).unwrap();
    v.unlink(MFT_REC_ROOT, "one", now()).unwrap();
    // The allocator walks forward and only comes back to a freed record once
    // it has wrapped; the hint is reset so the reuse happens here.
    v.set_record_hint(MFT_REC_USER);
    let reused = v.create_file(MFT_REC_ROOT, "two", now()).unwrap();
    assert_eq!(reused.reference.number, first.reference.number);
    assert_ne!(reused.reference.sequence, first.reference.sequence);
    assert!(!crate::ident::reference_is_current(&first.reference, reused.reference.sequence));
}

#[test]
fn a_directory_can_be_made_and_holds_names_of_its_own() {
    let mut v = test_image::empty();
    let made = v.create_dir(MFT_REC_ROOT, "sub", now()).unwrap();
    v.create_file(made.reference.number, "inside.txt", now()).unwrap();
    assert_eq!(v.lookup("/sub/inside.txt").unwrap().name, "inside.txt");
    assert_eq!(v.read_dir(made.reference.number).unwrap().len(), 1);
}

#[test]
fn a_directory_with_anything_in_it_will_not_be_removed() {
    let mut v = test_image::empty();
    let made = v.create_dir(MFT_REC_ROOT, "full", now()).unwrap();
    v.create_file(made.reference.number, "child", now()).unwrap();
    assert_eq!(v.rmdir(MFT_REC_ROOT, "full", now()).unwrap_err(), Errno::Enotempty);
    v.unlink(made.reference.number, "child", now()).unwrap();
    v.rmdir(MFT_REC_ROOT, "full", now()).unwrap();
    assert!(names(&v).is_empty());
}

#[test]
fn the_two_removals_refuse_each_others_kind() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "f", now()).unwrap();
    v.create_dir(MFT_REC_ROOT, "d", now()).unwrap();
    assert_eq!(v.unlink(MFT_REC_ROOT, "d", now()).unwrap_err(), Errno::Eisdir);
    assert_eq!(v.rmdir(MFT_REC_ROOT, "f", now()).unwrap_err(), Errno::Enotdir);
}
