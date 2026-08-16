use super::*;

/// A file's bytes reach the medium and read back — the point of the whole
/// write path.
#[test]
fn a_write_reaches_the_medium_and_reads_back() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    assert!(v.writable());
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let payload = alloc::vec![0x77u8; 100];
    let size = v.write_file(None, &hit, 0, &payload, when()).expect("write");
    assert_eq!(size, hit.size(), "an in-place write does not change the size");
    let again = v.lookup("DATA.BIN").expect("lookup");
    let mut buf = alloc::vec![0u8; 100];
    assert_eq!(v.read_file(&again.entry, 0, &mut buf), Ok(100));
    assert_eq!(buf, payload);
}

/// Writing past the end grows the file: the chain is extended, the record's
/// size is updated, and the new bytes read back.
#[test]
fn a_write_past_the_end_grows_the_file_and_its_record() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let tail = alloc::vec![0xEEu8; 1000];
    let grown = v.write_file(None, &hit, payload.len() as u64, &tail, when()).expect("write");
    assert_eq!(grown, payload.len() as u64 + 1000);

    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), grown, "the record carries the new size");
    let mut buf = alloc::vec![0u8; 1000];
    assert_eq!(v.read_file(&again.entry, payload.len() as u64, &mut buf), Ok(1000));
    assert_eq!(buf, tail);
    // ...and the bytes that were already there are untouched.
    let mut head = alloc::vec![0u8; payload.len()];
    v.read_file(&again.entry, 0, &mut head).expect("read");
    assert_eq!(head, payload);
}

/// A write that covers part of a cluster keeps the rest of that cluster.
/// Writing the whole cluster from a partial buffer destroys the bytes either
/// side of the range the caller asked for.
#[test]
fn a_partial_cluster_write_keeps_the_bytes_around_it() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.write_file(None, &hit, 700, &[0xAB, 0xCD], when()).expect("write");
    let again = v.lookup("DATA.BIN").expect("lookup");
    let mut buf = alloc::vec![0u8; 704];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(&buf[700..702], &[0xAB, 0xCD]);
    assert_eq!(&buf[..700], &payload[..700], "everything before survived");
    assert_eq!(&buf[702..704], &payload[702..704], "and everything after");
}

/// An empty file names no cluster; writing to it allocates one and records it.
#[test]
fn writing_to_an_empty_file_gives_it_a_chain() {
    let mut img = Builder::new();
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"EMPTY   TXT", ATTR_ARCH, 0, 0)]);
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("EMPTY.TXT").expect("lookup");
    assert_eq!(hit.entry.cluster, 0);
    assert_eq!(v.write_file(None, &hit, 0, b"first bytes", when()), Ok(11));
    let again = v.lookup("EMPTY.TXT").expect("lookup");
    assert_ne!(again.entry.cluster, 0, "it has a chain now");
    assert_eq!(v.read_whole(&again.entry).as_deref(), Ok(&b"first bytes"[..]));
}

/// EVERY copy of the table is updated. A volume left with two tables that
/// disagree is one every checker elsewhere reports.
#[test]
fn every_copy_of_the_table_is_written() {
    let (img, _) = populated();
    let image = img.image(true);
    let mut v = Volume::mount(image).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.write_file(None, &hit, 10_000, b"grow", when()).expect("write past the end allocates");
    let first = (RESERVED) * SECTOR;
    let second = (RESERVED + FAT_SECTORS) * SECTOR;
    for i in 0..FAT_SECTORS * SECTOR {
        assert_eq!(v.source_bytes(first + i), v.source_bytes(second + i),
                   "the two tables differ at byte {i}");
    }
}

/// A read-only medium refuses every write, at the write rather than halfway
/// through one.
#[test]
fn a_read_only_medium_refuses_writes() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(false)).expect("mount");
    assert!(!v.writable());
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(v.write_file(None, &hit, 0, b"nope", when()), Err(Errno::Erofs));
    assert_eq!(v.truncate_file(None, &hit, 0, when()), Err(Errno::Erofs));
}

/// A volume its last owner left dirty still mounts writable, exactly as the
/// reference does: it warns that a check is due and proceeds. Refusing would
/// leave a user unable to save anything to a stick that was pulled once.
#[test]
fn a_volume_left_dirty_still_mounts_writable() {
    let (mut img, _) = populated();
    crate::volstate::set_dirty(&mut img.bytes, FatWidth::Fat16, true).expect("mark");
    let mut v = Volume::mount(img.image(true)).expect("mount");
    assert!(v.was_dirty(), "the volume admits it, so a caller can warn");
    assert!(v.writable(), "and it is still writable");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert!(v.write_file(None, &hit, 0, b"ok", when()).is_ok());
}

/// ...and its flag is left exactly as its last owner set it. Clearing it at
/// this unmount would tell the next reader a check had happened when none has.
#[test]
fn an_already_dirty_flag_is_not_rewritten() {
    let (mut img, _) = populated();
    crate::volstate::set_dirty(&mut img.bytes, FatWidth::Fat16, true).expect("mark");
    let v = Volume::mount(img.image(true)).expect("mount");
    let at = crate::volstate::state_offset(FatWidth::Fat16);
    v.set_dirty(false).expect("unmount tries to clear it");
    assert_ne!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0,
               "the flag its last owner set survives");
}

/// The dirty flag round-trips through the medium, so a volume mounted
/// writable and pulled mid-write tells the next system that read it.
#[test]
fn the_dirty_flag_reaches_the_medium() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(true)).expect("mount");
    let at = crate::volstate::state_offset(FatWidth::Fat16);
    assert_eq!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
    v.set_dirty(true).expect("mark dirty");
    assert_ne!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
    v.set_dirty(false).expect("mark clean");
    assert_eq!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
}

/// Truncation releases the chain and zeroes the record, and the clusters come
/// back for the next file.
#[test]
fn truncation_releases_the_chain_and_zeroes_the_record() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let before = v.free_clusters();
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.truncate_file(None, &hit, 0, when()).expect("truncate");
    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), 0);
    assert_eq!(again.entry.cluster, 0);
    assert!(v.free_clusters() > before, "its clusters came back");
}

/// A full volume reports ENOSPC and changes nothing, rather than writing a
/// file it cannot hold.
#[test]
fn a_full_volume_reports_enospc_and_keeps_the_file_intact() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let huge = (u64::from(v.geometry().total_clusters) + 10) * v.geometry().cluster_bytes();
    assert_eq!(v.write_file(None, &hit, huge, b"x", when()).err(), Some(Errno::Enospc));
    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), payload.len() as u64, "the file is as it was");
    let mut buf = alloc::vec![0u8; payload.len()];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(buf, payload, "and its bytes are as they were");
}

/// A directory is not writable as a file.
#[test]
fn a_directory_refuses_a_write() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let dir = v.lookup("SUBDIR").expect("lookup");
    assert_eq!(v.write_file(None, &dir, 0, b"x", when()), Err(Errno::Eisdir));
    assert_eq!(v.truncate_file(None, &dir, 0, when()), Err(Errno::Eisdir));
}

/// A file in a SUBDIRECTORY updates its record where that record lives — in
/// the directory's cluster, not in the root.
#[test]
fn a_subdirectorys_file_updates_its_own_record() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let sub = v.lookup("SUBDIR").expect("subdir");
    let entries = v.read_dir(Some(sub.entry.cluster)).expect("read subdir");
    let nested = entries.into_iter().find(|e| e.name == "nested.txt").expect("nested");
    v.write_file(Some(sub.entry.cluster), &nested, 0, b"rewritten!", when()).expect("write");
    let entries = v.read_dir(Some(sub.entry.cluster)).expect("read subdir");
    let again = entries.into_iter().find(|e| e.name == "nested.txt").expect("nested");
    assert_eq!(again.size(), 14, "unchanged: the write fitted inside it");
    let mut buf = alloc::vec![0u8; 10];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(&buf, b"rewritten!");
}

/// A write rewrites the record's size and first cluster and NOTHING ELSE.
///
/// The record has ten more bytes than a short entry carries — the case bits
/// and three timestamps — and rebuilding it from the smaller view sets all of
/// them to zero. Every write to a file would then report it as created at the
/// start of 1980 under an all-uppercase name, and a mixed-case 8.3 name would
/// be permanently folded up.
#[test]
fn a_write_keeps_the_fields_it_does_not_change() {
    let (img, _) = populated();
    // The creation rule that STORES the case bits, so there is something in
    // that byte for the write to destroy.
    let mut v = Volume::mount_with(img.image(true), winnt()).expect("mount");
    let root = root_of(&v);
    // A record with every one of those fields set to something distinctive.
    let made = v.create_file(&root, "keep.txt", when()).expect("create");
    let before = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, made.slot).unwrap()).unwrap();
    assert_ne!(before.lcase, 0, "the fixture name really does carry case bits");
    assert_ne!(before.times.create, crate::time::FatTime::default());

    let hit = v.find_entry(&root, "keep.txt").expect("present");
    v.write_file(root.cluster, &hit, 0, b"payload", when()).expect("write");
    let after = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, hit.slot).unwrap()).unwrap();
    assert_eq!(after.lcase, before.lcase, "the case bits survived the write");
    assert_eq!(after.times.create, before.times.create, "and so did the creation time");
    assert_eq!(after.short.raw_name, before.short.raw_name);
    assert_eq!(after.short.size, 7, "while the size and the chain did change");
    assert_ne!(after.short.cluster, 0);
    // ...and the name still reads back in its own case, which is the only
    // record a mixed-case 8.3 name has.
    assert_eq!(v.find_entry(&root, "keep.txt").unwrap().name, "keep.txt");
}

/// A write stamps the modification time, which is the one field it MUST move.
#[test]
fn a_write_stamps_the_modification_time() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let root = root_of(&v);
    let early = crate::time::FatTime { time: 0x1111, date: 0x2222, cs: 0 };
    let made = v.create_file(&root, "STAMP.TXT", early).expect("create");
    let hit = v.find_entry(&root, "STAMP.TXT").expect("present");
    v.write_file(root.cluster, &hit, 0, b"x", when()).expect("write");
    let after = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, made.slot).unwrap()).unwrap();
    assert_eq!(after.times.modify,
               crate::time::FatTime { time: when().time, date: when().date, cs: 0 });
    assert_eq!(after.times.create, early, "the creation time is not a modification");
}

/// A truncation keeps them too, and stamps the modification time.
#[test]
fn a_truncation_keeps_the_fields_it_does_not_change() {
    let (img, _) = populated();
    let mut v = Volume::mount_with(img.image(true), winnt()).expect("mount");
    let root = root_of(&v);
    let early = crate::time::FatTime { time: 0x1111, date: 0x2222, cs: 71 };
    let made = v.create_file(&root, "cut.txt", early).expect("create");
    let hit = v.find_entry(&root, "cut.txt").expect("present");
    v.write_file(root.cluster, &hit, 0, b"some bytes", early).expect("write");
    let hit = v.find_entry(&root, "cut.txt").expect("present");
    v.truncate_file(root.cluster, &hit, 0, when()).expect("truncate");
    let after = crate::dirent::Record::parse(
        &v.read_dir_record(root.cluster, made.slot).unwrap()).unwrap();
    assert_eq!(after.times.create, early);
    assert_ne!(after.lcase, 0);
    assert_eq!(after.times.modify,
               crate::time::FatTime { time: when().time, date: when().date, cs: 0 });
    assert_eq!(after.short.size, 0);
    assert_eq!(after.short.cluster, 0);
}

/// A mount whose creation rule stores the case bits — the only rule under
/// which an all-lowercase 8.3 name needs no long-name slots at all.
fn winnt() -> crate::opts::Options {
    let mut o = crate::opts::Options::vfat();
    o.shortname = crate::name::flags::SFN_DISPLAY_WINNT | crate::name::flags::SFN_CREATE_WINNT;
    o.settle();
    o
}
