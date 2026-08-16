//! The write paths, driven end to end against an image in memory.

use crate::test_image::{self, Builder, CLUSTER};
use crate::uapi::*;
use crate::volume::dirops::{RENAME_EXCHANGE, RENAME_NOREPLACE};
use crate::volume::Volume;
use sectors::MemImage;
use syscall::errno::Errno;

/// A timestamp every test writes with, so nothing depends on a clock.
fn now() -> i64 { crate::time::from_unix(vfs::timespec::Timespec64::from_secs(1_800_000_000)) }

fn names(v: &Volume<MemImage>) -> alloc::vec::Vec<alloc::string::String> {
    v.read_dir(MFT_REC_ROOT).unwrap().into_iter().map(|e| e.name).collect()
}

#[test]
fn a_created_file_is_found_by_the_name_it_was_given() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "new.txt", now()).unwrap();
    assert_eq!(made.name, "new.txt");
    assert_eq!(names(&v), alloc::vec!["new.txt"]);
    let hit = v.find_entry(MFT_REC_ROOT, "new.txt").unwrap();
    assert_eq!(hit.reference, made.reference);
}

#[test]
fn a_created_files_record_says_what_it_is() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "f", now()).unwrap();
    let info = v.stat(made.reference.number).unwrap();
    assert!(!info.is_dir);
    assert_eq!(info.size, 0);
    assert_eq!(info.hard_links, 1);
    assert_eq!(info.create_time, now());
    let dir = v.create_dir(MFT_REC_ROOT, "d", now()).unwrap();
    assert!(v.stat(dir.reference.number).unwrap().is_dir);
}

#[test]
fn creating_a_name_that_exists_is_refused() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "dup", now()).unwrap();
    assert_eq!(v.create_file(MFT_REC_ROOT, "dup", now()).unwrap_err(), Errno::Eexist);
    // Case-insensitively, through the volume's own table.
    assert_eq!(v.create_file(MFT_REC_ROOT, "DUP", now()).unwrap_err(), Errno::Eexist);
}

#[test]
fn names_are_created_in_key_order_whatever_order_they_arrive_in() {
    // An appended entry produces a node a descent cannot search.
    let mut v = test_image::empty();
    for name in ["zulu", "alpha", "mike", "bravo"] {
        v.create_file(MFT_REC_ROOT, name, now()).unwrap();
    }
    assert_eq!(names(&v), alloc::vec!["alpha", "bravo", "mike", "zulu"]);
    for name in ["zulu", "alpha", "mike", "bravo"] {
        assert!(v.find_entry(MFT_REC_ROOT, name).is_ok(), "{name} became unfindable");
    }
}

#[test]
fn a_small_written_file_stays_resident_and_reads_back() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "small.txt", now()).unwrap();
    let payload = b"resident payload";
    v.write_file(made.reference.number, 0, payload, now()).unwrap();
    assert_eq!(v.read_whole(made.reference.number).unwrap(), payload);
    let (bytes, attrs) = v.read_record(made.reference.number).unwrap();
    let attr = crate::attrib::find(&attrs, ATTR_DATA, &[]).unwrap();
    assert!(!attr.non_resident, "a small file must stay in its record");
    let _ = bytes;
}

#[test]
fn a_file_grown_past_its_record_moves_out_into_clusters() {
    // The transition is the point: a write that only ever grows the resident
    // form fails at the record's edge and calls the volume full.
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "big.bin", now()).unwrap();
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 2 + 5).map(|i| (i % 251) as u8).collect();
    let size = v.write_file(made.reference.number, 0, &payload, now()).unwrap();
    assert_eq!(size, payload.len() as u64);
    let (_, attrs) = v.read_record(made.reference.number).unwrap();
    assert!(crate::attrib::find(&attrs, ATTR_DATA, &[]).unwrap().non_resident);
    assert_eq!(v.read_whole(made.reference.number).unwrap(), payload);
}

#[test]
fn a_resident_file_that_grows_keeps_the_bytes_it_had() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "grow.txt", now()).unwrap();
    v.write_file(made.reference.number, 0, b"first", now()).unwrap();
    let tail: alloc::vec::Vec<u8> = alloc::vec![b'x'; CLUSTER];
    v.write_file(made.reference.number, 5, &tail, now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(&got[..5], b"first");
    assert_eq!(&got[5..], &tail[..]);
}

#[test]
fn a_write_into_the_middle_keeps_the_bytes_either_side() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "patch.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![1u8; CLUSTER * 2], now()).unwrap();
    v.write_file(made.reference.number, 100, &[2u8; 8], now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(&got[..100], &alloc::vec![1u8; 100][..]);
    assert_eq!(&got[100..108], &[2u8; 8]);
    assert_eq!(&got[108..], &alloc::vec![1u8; CLUSTER * 2 - 108][..]);
}

#[test]
fn a_write_past_the_end_leaves_zeros_not_the_previous_owners_bytes() {
    let mut v = test_image::empty();
    let scratch = v.create_file(MFT_REC_ROOT, "scratch", now()).unwrap();
    v.write_file(scratch.reference.number, 0, &alloc::vec![0xAB; CLUSTER * 2], now()).unwrap();
    v.unlink(MFT_REC_ROOT, "scratch", now()).unwrap();

    let made = v.create_file(MFT_REC_ROOT, "sparse", now()).unwrap();
    v.write_file(made.reference.number, CLUSTER as u64, b"tail", now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(got.len(), CLUSTER + 4);
    assert!(got[..CLUSTER].iter().all(|b| *b == 0), "the gap kept old bytes");
    assert_eq!(&got[CLUSTER..], b"tail");
}

#[test]
fn shortening_a_file_releases_the_clusters_it_no_longer_needs() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "shrink.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![3u8; CLUSTER * 4], now()).unwrap();
    let used = v.used_clusters();
    v.truncate_file(made.reference.number, CLUSTER as u64, now()).unwrap();
    assert_eq!(v.used_clusters(), used - 3);
    assert_eq!(v.read_whole(made.reference.number).unwrap(), alloc::vec![3u8; CLUSTER]);
}

#[test]
fn lengthening_a_file_allocates_and_zeroes() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "extend.bin", now()).unwrap();
    v.write_file(made.reference.number, 0, &alloc::vec![7u8; CLUSTER], now()).unwrap();
    v.truncate_file(made.reference.number, CLUSTER as u64 * 3, now()).unwrap();
    let got = v.read_whole(made.reference.number).unwrap();
    assert_eq!(got.len(), CLUSTER * 3);
    assert_eq!(&got[..CLUSTER], &alloc::vec![7u8; CLUSTER][..]);
    assert!(got[CLUSTER..].iter().all(|b| *b == 0));
}

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

#[test]
fn a_volume_survives_a_remount_after_a_write() {
    // The real test of a write path: read the image back through a fresh
    // mount, which trusts nothing the writing mount held in memory.
    let image = {
        let mut v = test_image::empty();
        let made = v.create_file(MFT_REC_ROOT, "persist.txt", now()).unwrap();
        v.write_file(made.reference.number, 0, b"still here after a remount", now()).unwrap();
        v.create_dir(MFT_REC_ROOT, "sub", now()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    assert_eq!(names(&v), alloc::vec!["persist.txt", "sub"]);
    let hit = v.find_entry(MFT_REC_ROOT, "persist.txt").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"still here after a remount");
}

#[test]
fn a_large_file_survives_a_remount() {
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 4 + 11).map(|i| (i % 241) as u8).collect();
    let image = {
        let mut v = test_image::empty();
        let made = v.create_file(MFT_REC_ROOT, "big.bin", now()).unwrap();
        v.write_file(made.reference.number, 0, &payload, now()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let hit = v.find_entry(MFT_REC_ROOT, "big.bin").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), payload);
}

#[test]
fn a_volume_can_be_filled_and_emptied_without_losing_clusters() {
    let mut v = test_image::empty();
    let before = v.free_clusters();
    for i in 0..8 {
        let name = alloc::format!("f{i}");
        let made = v.create_file(MFT_REC_ROOT, &name, now()).unwrap();
        v.write_file(made.reference.number, 0, &alloc::vec![i as u8; CLUSTER * 2], now()).unwrap();
    }
    for i in 0..8 { v.unlink(MFT_REC_ROOT, &alloc::format!("f{i}"), now()).unwrap(); }
    assert_eq!(v.free_clusters(), before);
    assert!(names(&v).is_empty());
}

#[test]
fn the_dirty_flag_round_trips() {
    let mut v = test_image::empty();
    assert!(!v.was_dirty());
    v.set_dirty(true).unwrap();
    let image = v.into_source();
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let mut v = Volume::mount_with(image, opts).unwrap();
    assert!(v.was_dirty());
    v.set_dirty(false).unwrap();
    let image = v.into_source();
    let v = Volume::mount_with(image, opts).unwrap();
    assert!(!v.was_dirty());
}

#[test]
fn a_name_past_the_length_ceiling_is_refused_before_anything_is_written() {
    let mut v = test_image::empty();
    let long: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert_eq!(v.create_file(MFT_REC_ROOT, &long, now()).unwrap_err(), Errno::Enametoolong);
    assert!(names(&v).is_empty());
}

#[test]
fn a_directory_fills_when_its_index_root_is_full() {
    // The tree does not yet grow into `$INDEX_ALLOCATION`, so a directory
    // holds what its resident root holds and then refuses. The refusal is
    // ENOSPC and nothing is left half-created: the record the failed create
    // claimed is released.
    let mut v = test_image::empty();
    let mut made = 0usize;
    loop {
        let name = alloc::format!("f{made:03}");
        match v.create_file(MFT_REC_ROOT, &name, now()) {
            Ok(_) => made += 1,
            Err(Errno::Enospc) => break,
            Err(other) => panic!("unexpected {other:?}"),
        }
        assert!(made < 1000, "the root never filled");
    }
    assert!(made > 0, "the root took no names at all");
    assert_eq!(names(&v).len(), made);
    // Every name that WAS taken is still findable, and the volume is
    // consistent: nothing was left behind by the refusal.
    for i in 0..made {
        assert!(v.find_entry(MFT_REC_ROOT, &alloc::format!("f{i:03}")).is_ok());
    }
    let free_before = v.space().records_free;
    assert_eq!(v.create_file(MFT_REC_ROOT, "one-more", now()).unwrap_err(), Errno::Enospc);
    assert_eq!(v.space().records_free, free_before, "the failed create leaked a record");
}
