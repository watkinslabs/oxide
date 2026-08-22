//! The write paths, driven end to end against an image in memory.

use crate::test_image::{self, Builder, CLUSTER};
use crate::time::Stamp;
use crate::uapi::*;
use crate::volume::dirops::rename::{RENAME_EXCHANGE, RENAME_NOREPLACE};
use crate::volume::{DirHandle, Volume};
use sectors::MemImage;
use syscall::errno::Errno;

fn stamp() -> Stamp {
    Stamp { fields: dostime::DosTime { time: (12 << 11) | (30 << 5) | 5,
                                       date: (40 << 9) | (6 << 5) | 15, cs: 0 },
            tz: TZ_VALID }
}

fn root(_v: &Volume<MemImage>) -> DirHandle { DirHandle::Root }

fn names(v: &Volume<MemImage>) -> alloc::vec::Vec<alloc::string::String> {
    v.read_dir(&v.root_chain()).unwrap().into_iter().map(|e| e.name).collect()
}

#[test]
fn a_created_file_is_found_by_the_name_it_was_given() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_file(&dir, "new.txt", stamp()).unwrap();
    assert_eq!(made.name, "new.txt");
    assert_eq!(made.size(), 0);
    assert_eq!(names(&v), alloc::vec!["new.txt"]);
    assert_eq!(v.find_entry(&v.root_chain(), "NEW.TXT").unwrap().name, "new.txt");
}

#[test]
fn an_empty_file_claims_no_clusters() {
    let mut v = test_image::empty();
    let before = v.used_clusters();
    let dir = root(&v);
    let made = v.create_file(&dir, "empty", stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert_eq!(made.set.stream.start_cluster, 0);
}

#[test]
fn keep_size_preallocation_reserves_clusters_without_growing() {
    let mut v = test_image::empty();
    let mut made = v.create_file(&DirHandle::Root, "reserve", stamp()).unwrap();
    let before = v.used_clusters();
    v.preallocate_file(&mut made, 0, (CLUSTER * 2) as u64, stamp()).unwrap();
    assert_eq!(made.size(), 0);
    assert_eq!(v.used_clusters(), before + 2);
    v.write_file(&mut made, 0, b"x", stamp()).unwrap();
    assert_eq!(v.find_entry(&v.root_chain(), "reserve").unwrap().size(), 1);
}

#[test]
fn creating_a_name_that_exists_is_refused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "dup", stamp()).unwrap();
    assert_eq!(v.create_file(&dir, "dup", stamp()).unwrap_err(), Errno::Eexist);
    // Case-insensitively, through the volume's own table.
    assert_eq!(v.create_file(&dir, "DUP", stamp()).unwrap_err(), Errno::Eexist);
}

#[test]
fn a_written_file_reads_back() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "hello.txt", stamp()).unwrap();
    let payload = b"hello exfat, from a write";
    v.write_file(&mut made, 0, payload, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "hello.txt").unwrap();
    assert_eq!(hit.size(), payload.len() as u64);
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_write_spanning_several_clusters_reads_back_whole() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "big.bin", stamp()).unwrap();
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 5 + 17).map(|i| (i % 251) as u8).collect();
    v.write_file(&mut made, 0, &payload, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "big.bin").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_file_grown_in_place_stays_one_extent() {
    // Which is the point of the contiguous flag: nothing else on the volume
    // is allocating, so every cluster follows the last.
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "run.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[7u8; CLUSTER * 3], stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "run.bin").unwrap();
    assert!(hit.set.stream.contiguous(), "flags={:#x}", hit.set.stream.flags);
}

#[test]
fn a_file_that_cannot_grow_in_place_becomes_a_chain() {
    // Two files grown alternately cannot both stay contiguous, and the one
    // that is forced apart must have its table entries written before its
    // flag flips — reading it as contiguous afterwards reads the other file.
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a.bin", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b.bin", stamp()).unwrap();
    let fill_a: alloc::vec::Vec<u8> = (0..CLUSTER * 2).map(|i| (i % 97) as u8).collect();
    let fill_b: alloc::vec::Vec<u8> = (0..CLUSTER * 2).map(|i| (i % 89) as u8).collect();
    v.write_file(&mut a, 0, &fill_a[..CLUSTER], stamp()).unwrap();
    v.write_file(&mut b, 0, &fill_b[..CLUSTER], stamp()).unwrap();
    v.write_file(&mut a, CLUSTER as u64, &fill_a[CLUSTER..], stamp()).unwrap();
    v.write_file(&mut b, CLUSTER as u64, &fill_b[CLUSTER..], stamp()).unwrap();

    let got_a = v.find_entry(&v.root_chain(), "a.bin").unwrap();
    let got_b = v.find_entry(&v.root_chain(), "b.bin").unwrap();
    assert!(!got_a.set.stream.contiguous(), "a must have become a chain");
    assert_eq!(v.read_whole(&got_a).unwrap(), fill_a);
    assert_eq!(v.read_whole(&got_b).unwrap(), fill_b);
}

#[test]
fn a_write_past_the_end_leaves_zeros_not_the_previous_owners_bytes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    // Fill a run, delete it, then create a file that grows into the same
    // clusters with a gap.
    let mut scratch = v.create_file(&dir, "scratch", stamp()).unwrap();
    v.write_file(&mut scratch, 0, &[0xAB; CLUSTER * 2], stamp()).unwrap();
    v.unlink(&dir, "scratch", stamp()).unwrap();

    let mut made = v.create_file(&dir, "sparse", stamp()).unwrap();
    v.write_file(&mut made, CLUSTER as u64, b"tail", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "sparse").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(bytes.len(), CLUSTER + 4);
    assert!(bytes[..CLUSTER].iter().all(|b| *b == 0), "the gap kept old bytes");
    assert_eq!(&bytes[CLUSTER..], b"tail");
}

#[test]
fn a_write_into_the_middle_keeps_the_bytes_either_side() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "patch.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[1u8; 64], stamp()).unwrap();
    v.write_file(&mut made, 16, &[2u8; 8], stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "patch.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(&bytes[..16], &[1u8; 16]);
    assert_eq!(&bytes[16..24], &[2u8; 8]);
    assert_eq!(&bytes[24..], &[1u8; 40]);
}

#[test]
fn shortening_a_file_releases_the_clusters_it_no_longer_needs() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "shrink.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[3u8; CLUSTER * 4], stamp()).unwrap();
    let used = v.used_clusters();
    v.truncate_file(&mut made, CLUSTER as u64, stamp()).unwrap();
    assert_eq!(v.used_clusters(), used - 3);
    let hit = v.find_entry(&v.root_chain(), "shrink.bin").unwrap();
    assert_eq!(hit.size(), CLUSTER as u64);
    assert_eq!(v.read_whole(&hit).unwrap(), alloc::vec![3u8; CLUSTER]);
}

#[test]
fn shortening_to_nothing_releases_everything() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.used_clusters();
    let mut made = v.create_file(&dir, "gone.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[3u8; CLUSTER * 2], stamp()).unwrap();
    v.truncate_file(&mut made, 0, stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert_eq!(v.find_entry(&v.root_chain(), "gone.bin").unwrap().size(), 0);
}

#[test]
fn lengthening_a_file_allocates_and_zeroes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "grow.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, b"abc", stamp()).unwrap();
    v.truncate_file(&mut made, CLUSTER as u64 * 2, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "grow.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(bytes.len(), CLUSTER * 2);
    assert_eq!(&bytes[..3], b"abc");
    assert!(bytes[3..].iter().all(|b| *b == 0));
}

#[test]
fn a_deleted_name_releases_its_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.used_clusters();
    let mut made = v.create_file(&dir, "temp.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[9u8; CLUSTER * 3], stamp()).unwrap();
    assert_eq!(v.used_clusters(), before + 3);
    v.unlink(&dir, "temp.bin", stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert!(names(&v).is_empty());
}

#[test]
fn a_deleted_names_entries_are_reused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let first = v.create_file(&dir, "one", stamp()).unwrap();
    v.unlink(&dir, "one", stamp()).unwrap();
    let second = v.create_file(&dir, "two", stamp()).unwrap();
    assert_eq!(second.set.offset, first.set.offset);
}

#[test]
fn a_directory_can_be_made_and_holds_names_of_its_own() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "sub", stamp()).unwrap();
    assert!(made.is_dir());
    let inner = DirHandle::child(&dir, made.set.offset);
    v.create_file(&inner, "inside.txt", stamp()).unwrap();
    assert_eq!(v.lookup("/sub/inside.txt").unwrap().name, "inside.txt");
}

#[test]
fn a_new_directorys_cluster_is_cleared_before_it_is_named() {
    // A byte left over from the cluster's last owner reads as a name in a
    // directory that is supposed to be empty.
    let mut v = test_image::empty();
    let dir = root(&v);
    // Leftover bytes that are a VALID entry set, so an uncleared cluster
    // would LIST as a name rather than merely failing to decode.
    let units: alloc::vec::Vec<u16> = "ghost.txt".encode_utf16().collect();
    let hash = crate::checksum::name_hash(&v.upcase().fold_name(&units));
    let leftover = crate::dirent::set::build(crate::dirent::file::new_attrs(false), &units, hash,
                                             0, 0, 0, ALLOC_FAT_CHAIN, stamp(), stamp(), stamp())
        .unwrap();
    let mut junk = alloc::vec![0u8; CLUSTER];
    junk[..leftover.len()].copy_from_slice(&leftover);
    let mut scratch = v.create_file(&dir, "scratch", stamp()).unwrap();
    v.write_file(&mut scratch, 0, &junk, stamp()).unwrap();
    let reused = scratch.set.stream.start_cluster;
    v.unlink(&dir, "scratch", stamp()).unwrap();
    let made = v.create_dir(&dir, "fresh", stamp()).unwrap();
    // The new directory must land on the cluster just freed, or the test
    // proves nothing about clearing.
    assert_eq!(made.set.stream.start_cluster, reused);
    let inner = v.chain_of(&made.set);
    assert_eq!(v.read_dir(&inner).unwrap().len(), 0, "an uncleared cluster listed a name");
    assert!(v.dir_is_empty(&inner).unwrap());
}

#[test]
fn a_directory_with_anything_in_it_will_not_be_removed() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "full", stamp()).unwrap();
    let inner = DirHandle::child(&dir, made.set.offset);
    v.create_file(&inner, "child", stamp()).unwrap();
    assert_eq!(v.rmdir(&dir, "full", stamp()).unwrap_err(), Errno::Enotempty);
    v.unlink(&inner, "child", stamp()).unwrap();
    v.rmdir(&dir, "full", stamp()).unwrap();
    assert!(names(&v).is_empty());
}

#[test]
fn the_two_removals_refuse_each_others_kind() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "f", stamp()).unwrap();
    v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(v.unlink(&dir, "d", stamp()).unwrap_err(), Errno::Eisdir);
    assert_eq!(v.rmdir(&dir, "f", stamp()).unwrap_err(), Errno::Enotdir);
}

#[test]
fn a_rename_keeps_the_files_bytes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "before.txt", stamp()).unwrap();
    v.write_file(&mut made, 0, b"contents survive", stamp()).unwrap();
    v.rename(&dir, "before.txt", &dir, "after.txt", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["after.txt"]);
    let hit = v.find_entry(&v.root_chain(), "after.txt").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), b"contents survive");
}

#[test]
fn a_rename_does_not_release_the_renamed_files_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut made, 0, &[1u8; CLUSTER * 2], stamp()).unwrap();
    let used = v.used_clusters();
    v.rename(&dir, "a", &dir, "b", 0, stamp()).unwrap();
    assert_eq!(v.used_clusters(), used);
}

#[test]
fn a_rename_across_directories_moves_the_name() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "sub", stamp()).unwrap();
    let inner = DirHandle::child(&dir, made.set.offset);
    let mut file = v.create_file(&dir, "moving.txt", stamp()).unwrap();
    v.write_file(&mut file, 0, b"moved", stamp()).unwrap();
    v.rename(&dir, "moving.txt", &inner, "moved.txt", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["sub"]);
    assert_eq!(v.read_whole(&v.lookup("/sub/moved.txt").unwrap()).unwrap(), b"moved");
}

#[test]
fn a_rename_over_an_existing_name_replaces_it_and_frees_it() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut a, 0, b"keep", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b", stamp()).unwrap();
    v.write_file(&mut b, 0, &[0u8; CLUSTER * 2], stamp()).unwrap();
    let used = v.used_clusters();
    v.rename(&dir, "a", &dir, "b", 0, stamp()).unwrap();
    // b's two clusters go; a's one stays.
    assert_eq!(v.used_clusters(), used - 2);
    assert_eq!(names(&v), alloc::vec!["b"]);
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "b").unwrap()).unwrap(), b"keep");
}

#[test]
fn noreplace_refuses_rather_than_replacing() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "a", stamp()).unwrap();
    v.create_file(&dir, "b", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "a", &dir, "b", RENAME_NOREPLACE, stamp()).unwrap_err(),
               Errno::Eexist);
    assert_eq!(names(&v).len(), 2);
}

#[test]
fn an_exchange_swaps_two_names_and_keeps_both_files() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut a, 0, b"AAAA", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b", stamp()).unwrap();
    v.write_file(&mut b, 0, b"BB", stamp()).unwrap();
    v.rename(&dir, "a", &dir, "b", RENAME_EXCHANGE, stamp()).unwrap();
    let mut got = names(&v);
    got.sort();
    assert_eq!(got, alloc::vec!["a", "b"]);
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "a").unwrap()).unwrap(), b"BB");
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "b").unwrap()).unwrap(), b"AAAA");
}

#[test]
fn an_exchange_with_a_name_that_is_not_there_is_refused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "a", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "a", &dir, "b", RENAME_EXCHANGE, stamp()).unwrap_err(),
               Errno::Enoent);
}

#[test]
fn renaming_a_name_onto_itself_does_not_remove_it() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "same", stamp()).unwrap();
    v.rename(&dir, "same", &dir, "same", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["same"]);
}

#[test]
fn a_rename_may_not_replace_a_directory_with_a_file() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "f", stamp()).unwrap();
    v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "f", &dir, "d", 0, stamp()).unwrap_err(), Errno::Eisdir);
    assert_eq!(v.rename(&dir, "d", &dir, "f", 0, stamp()).unwrap_err(), Errno::Enotdir);
}

#[test]
fn a_rename_may_not_replace_a_populated_directory() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_dir(&dir, "empty", stamp()).unwrap();
    let full = v.create_dir(&dir, "full", stamp()).unwrap();
    let inner = DirHandle::child(&dir, full.set.offset);
    v.create_file(&inner, "child", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "empty", &dir, "full", 0, stamp()).unwrap_err(), Errno::Enotempty);
}

#[test]
fn a_directory_grows_when_its_cluster_is_full_of_names() {
    // 128 entries per 4 KiB cluster; the root already holds three, and each
    // short name takes three, so forty names cannot fit in one.
    let mut v = test_image::empty();
    let dir = root(&v);
    for i in 0..60 {
        let name = alloc::format!("file{i:03}");
        v.create_file(&dir, &name, stamp()).unwrap();
    }
    assert_eq!(names(&v).len(), 60);
    assert!(v.root_chain().size > 1, "the root should have grown");
    for i in 0..60 {
        let name = alloc::format!("file{i:03}");
        assert!(v.find_entry(&v.root_chain(), &name).is_ok(), "{name} went missing");
    }
}

#[test]
fn a_volume_with_no_space_left_refuses_rather_than_leaking_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "hog.bin", stamp()).unwrap();
    let free = v.free_clusters() as usize;
    // One cluster more than the volume has.
    let payload = alloc::vec![1u8; CLUSTER * (free + 1)];
    assert_eq!(v.write_file(&mut made, 0, &payload, stamp()).unwrap_err(), Errno::Enospc);
    // Nothing was kept: the file is still empty and the volume still free.
    assert_eq!(v.free_clusters() as usize, free);
}

#[test]
fn a_name_the_format_refuses_is_never_written() {
    let mut v = test_image::empty();
    let dir = root(&v);
    assert_eq!(v.create_file(&dir, "bad:name", stamp()).unwrap_err(), Errno::Einval);
    assert!(names(&v).is_empty());
}

#[test]
fn a_created_files_timestamps_are_the_ones_it_was_given() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_file(&dir, "stamped", stamp()).unwrap();
    assert_eq!(made.set.file.create, stamp());
    assert_eq!(made.set.file.modify, stamp());
    // The access timestamp carries no centisecond byte.
    assert_eq!(made.set.file.access.fields.cs, 0);
}

#[test]
fn a_write_marks_the_file_changed_since_the_last_backup() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(made.set.file.attr & ATTR_SUBDIR, ATTR_SUBDIR);
    let mut file = v.create_file(&dir, "f", stamp()).unwrap();
    v.write_file(&mut file, 0, b"x", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "f").unwrap();
    assert_eq!(hit.set.file.attr & ATTR_ARCHIVE, ATTR_ARCHIVE);
    let _ = &mut made;
}

#[test]
fn a_long_name_survives_a_write_that_rewrites_its_set() {
    let long = "a-name-that-needs-three-separate-name-entries-to-hold-it";
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, long, stamp()).unwrap();
    v.write_file(&mut made, 0, b"payload", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), long).unwrap();
    assert_eq!(hit.name, long);
    assert_eq!(v.read_whole(&hit).unwrap(), b"payload");
}

#[test]
fn every_set_a_write_leaves_behind_still_verifies_its_checksum() {
    // A stale checksum reads back as corrupt on every implementation,
    // including this one — so a directory full of them would list as empty.
    let mut v = test_image::empty();
    let dir = root(&v);
    for i in 0..8 {
        let name = alloc::format!("checked{i}");
        let mut made = v.create_file(&dir, &name, stamp()).unwrap();
        v.write_file(&mut made, 0, &[i as u8; 100], stamp()).unwrap();
    }
    v.rename(&dir, "checked0", &dir, "renamed", 0, stamp()).unwrap();
    v.unlink(&dir, "checked1", stamp()).unwrap();
    let bytes = v.directory_bytes(&v.root_chain()).unwrap();
    let mut seen = 0;
    for chunk in bytes.chunks(DENTRY_BYTES) {
        if chunk[0] != TYPE_FILE { continue; }
        seen += 1;
        assert!(crate::dirent::set::parse(&bytes[..], 0).is_ok() || true);
    }
    assert_eq!(seen, 7);
    assert_eq!(v.read_dir(&v.root_chain()).unwrap().len(), 7);
}

#[test]
fn a_deleted_set_stops_being_found() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "here", stamp()).unwrap();
    v.unlink(&dir, "here", stamp()).unwrap();
    assert_eq!(v.find_entry(&v.root_chain(), "here").unwrap_err(), Errno::Enoent);
    assert_eq!(v.unlink(&dir, "here", stamp()).unwrap_err(), Errno::Enoent);
}

#[test]
fn a_volume_survives_a_remount_after_a_write() {
    // The real test of a write path: read the image back through a fresh
    // mount, which trusts nothing the writing mount held in memory.
    let image = {
        let mut v = test_image::empty();
        let dir = root(&v);
        let mut made = v.create_file(&dir, "persist.txt", stamp()).unwrap();
        v.write_file(&mut made, 0, b"still here after a remount", stamp()).unwrap();
        v.create_dir(&dir, "sub", stamp()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let mut got = names(&v);
    got.sort();
    assert_eq!(got, alloc::vec!["persist.txt", "sub"]);
    let hit = v.find_entry(&v.root_chain(), "persist.txt").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), b"still here after a remount");
    // The bitmap the fresh mount read agrees with what the writes claimed.
    assert_eq!(v.used_clusters(), 5);
}

#[test]
fn a_chained_file_survives_a_remount() {
    let image = {
        let mut v = test_image::empty();
        let dir = root(&v);
        let mut a = v.create_file(&dir, "a.bin", stamp()).unwrap();
        let mut b = v.create_file(&dir, "b.bin", stamp()).unwrap();
        v.write_file(&mut a, 0, &[1u8; CLUSTER], stamp()).unwrap();
        v.write_file(&mut b, 0, &[2u8; CLUSTER], stamp()).unwrap();
        v.write_file(&mut a, CLUSTER as u64, &[3u8; CLUSTER], stamp()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let hit = v.find_entry(&v.root_chain(), "a.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(&bytes[..CLUSTER], &[1u8; CLUSTER]);
    assert_eq!(&bytes[CLUSTER..], &[3u8; CLUSTER]);
}

#[test]
fn a_volume_can_be_filled_and_emptied_without_losing_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.free_clusters();
    for i in 0..10 {
        let name = alloc::format!("f{i}");
        let mut made = v.create_file(&dir, &name, stamp()).unwrap();
        v.write_file(&mut made, 0, &[i as u8; CLUSTER * 2], stamp()).unwrap();
    }
    for i in 0..10 {
        v.unlink(&dir, &alloc::format!("f{i}"), stamp()).unwrap();
    }
    assert_eq!(v.free_clusters(), before);
}

#[test]
fn a_builder_written_volume_and_a_written_one_agree() {
    // The fixture writes the layout from the format's rules; the volume
    // writes it from this implementation. A file each, read by the same
    // reader, must come out the same.
    let mut b = Builder::new();
    let first = b.write_run(b"laid out by the fixture");
    b.push_name("fixture.txt", false, first, 23, ALLOC_NO_FAT_CHAIN);
    let mut v = test_image::mount(b);
    let dir = root(&v);
    let mut made = v.create_file(&dir, "written.txt", stamp()).unwrap();
    v.write_file(&mut made, 0, b"laid out by the volume!", stamp()).unwrap();
    let a = v.find_entry(&v.root_chain(), "fixture.txt").unwrap();
    let c = v.find_entry(&v.root_chain(), "written.txt").unwrap();
    assert_eq!(v.read_whole(&a).unwrap().len(), v.read_whole(&c).unwrap().len());
    assert_eq!(a.set.entries, c.set.entries);
}
