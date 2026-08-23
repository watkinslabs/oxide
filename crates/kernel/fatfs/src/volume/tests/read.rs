use super::*;

/// Mounting resolves the layout from the image's own boot sector.
#[test]
fn a_volume_mounts_and_reports_its_layout() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    assert_eq!(v.width(), FatWidth::Fat16, "the fixture must be the width it writes");
    assert!(v.geometry().total_clusters > crate::geometry::MAX_FAT12);
    assert_eq!(v.geometry().sector_size, SECTOR as u32);
    assert_eq!(v.geometry().data_start as usize,
               RESERVED + FATS * FAT_SECTORS + ROOT_ENTRIES * dirent::ENTRY_BYTES / SECTOR);
}

/// `dos1xfloppy` supplies the reference's geometry only after the normal BPB
/// has failed, and only when the source reports an exact floppy capacity.
#[test]
fn dos1xfloppy_mounts_a_bootstrap_only_floppy() {
    let image = sectors::MemImage::new(SECTOR as u32, 320);
    image.poke(0, &[0xeb, 0x00, 0x90]);
    let mut opts = crate::opts::Options::vfat();
    opts.dos1xfloppy = true;
    let v = Volume::mount_with(image, opts).expect("DOS 1.x fallback");
    assert_eq!(v.geometry().sector_size, 512);
    assert_eq!(v.geometry().sec_per_clus, 1);
    assert_eq!(v.geometry().dir_entries, 64);
    assert_eq!(v.geometry().fat_length, 1);
    assert_eq!(v.geometry().total_clusters, 313);
}

/// The root lists its files, hides the volume label, and carries long names
/// where the image wrote them.
#[test]
fn the_root_lists_its_files_and_hides_the_label() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let names: Vec<String> = v.read_root().expect("read root").into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["DATA.BIN", "a long file name.txt", "SUBDIR"]);
    assert!(!names.iter().any(|n| n.contains("MYVOLUME")), "a label is not a file");
}

/// The whole stack, end to end: a multi-cluster file read back byte for byte.
#[test]
fn a_multi_cluster_file_reads_back_exactly() {
    let (img, payload) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(hit.size(), payload.len() as u64);
    assert_eq!(v.read_whole(&hit.entry).expect("read"), payload);
    assert!(payload.len() > SEC_PER_CLUS * SECTOR, "the file really does span clusters");
}

/// A read stops at the declared size. The tail of the last cluster is not
/// part of the file, and returning it appends whatever the medium last held.
#[test]
fn a_read_stops_at_the_declared_size() {
    let (img, payload) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("data.bin").expect("lookup is case-insensitive");
    let mut buf = vec![0xAAu8; 4096];
    let got = v.read_file(&hit.entry, 0, &mut buf).expect("read");
    assert_eq!(got, payload.len(), "not the whole cluster");
    assert_eq!(buf[got], 0xAA, "and nothing past it was written");
    // Reading from the end yields nothing rather than the cluster's tail.
    assert_eq!(v.read_file(&hit.entry, payload.len() as u64, &mut buf), Ok(0));
    assert_eq!(v.read_file(&hit.entry, u64::MAX, &mut buf), Ok(0));
}

/// A read at an offset lands where it should, including across a cluster
/// boundary — the case a per-cluster reader gets wrong by a whole cluster.
#[test]
fn a_read_at_an_offset_crosses_cluster_boundaries_correctly() {
    let (img, payload) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let per = SEC_PER_CLUS * SECTOR;
    for offset in [0usize, 1, per - 1, per, per + 1, 2 * per - 5] {
        let mut buf = vec![0u8; 64];
        let got = v.read_file(&hit.entry, offset as u64, &mut buf).expect("read");
        assert_eq!(&buf[..got], &payload[offset..offset + got], "offset {offset}");
        assert!(got > 0);
    }
}

/// A path resolves through a subdirectory, and the file there reads back.
#[test]
fn a_path_resolves_through_a_subdirectory() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("SUBDIR/nested.txt").expect("nested lookup");
    assert_eq!(v.read_whole(&hit.entry).expect("read"), b"nested payload");
    assert_eq!(v.lookup("/SUBDIR/nested.txt").map(|e| e.name), Ok(String::from("nested.txt")),
               "a leading slash is not a component");
    assert_eq!(v.lookup("SUBDIR/./nested.txt").map(|e| e.name), Ok(String::from("nested.txt")));
}

/// A long name resolves by its long form and reads back.
#[test]
fn a_long_name_resolves_and_reads() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("a long file name.txt").expect("long lookup");
    assert_eq!(v.read_whole(&hit.entry).expect("read"), b"long name contents");
}

/// A missing name is `ENOENT`, and a directory is not readable as a file.
#[test]
fn the_refusals_are_the_ones_a_caller_expects() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    assert_eq!(v.lookup("nope.txt").err(), Some(Errno::Enoent));
    assert_eq!(v.lookup("SUBDIR/nope").err(), Some(Errno::Enoent));
    let dir = v.lookup("SUBDIR").expect("the directory itself resolves");
    assert!(dir.is_dir());
    let mut buf = vec![0u8; 16];
    assert_eq!(v.read_file(&dir.entry, 0, &mut buf), Err(Errno::Eisdir));
}

/// A deleted entry is not listed, and it breaks any long-name run in
/// progress: those slots belonged to the name that was removed.
#[test]
fn a_deleted_entry_is_hidden_and_ends_its_run() {
    let mut img = Builder::new();
    let cluster = img.write_chain(b"still here");
    let root = img.root_offset();
    img.write_dir(root, &[
        ("removed name.txt", *b"REMOVE~1TXT", ATTR_ARCH, 9, 5),
        ("", *b"KEPT    TXT", ATTR_ARCH, cluster, 10),
    ]);
    // Mark the short entry of the first file deleted, leaving its long slots.
    let deleted_at = root + 2 * dirent::ENTRY_BYTES; // two long slots precede it
    img.bytes[deleted_at] = DELETED_FLAG;
    let v = Volume::mount(img.image(false)).expect("mount");
    let entries = v.read_root().expect("read root");
    assert_eq!(entries.len(), 1, "only the surviving file");
    assert_eq!(entries[0].name, "KEPT.TXT",
               "and it did not inherit the removed file's long name");
}

/// A volume whose boot sector is not a FAT volume is refused at mount, not
/// discovered later as unreadable directories.
#[test]
fn a_volume_that_is_not_fat_is_refused_at_mount() {
    let mut img = Builder::new();
    img.bytes[0x15] = 0x00; // media descriptor no volume uses
    assert_eq!(Volume::mount(img.image(false)).err(), Some(Errno::Einval));
}

/// A truncated medium is an error rather than a short read treated as data.
#[test]
fn a_truncated_medium_is_an_error() {
    let mut img = Builder::new();
    img.bytes.truncate(SECTOR * 4);
    assert_eq!(Volume::mount(img.image(false)).err(), Some(Errno::Eio));
}

/// An entry whose size claims more than its chain holds is `EIO`: the entry
/// and the table disagree, and the table owns the data.
#[test]
fn a_size_longer_than_its_chain_is_refused() {
    let mut img = Builder::new();
    let cluster = img.write_chain(b"short");
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"LIAR    BIN", ATTR_ARCH, cluster, 100_000)]);
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("LIAR.BIN").expect("lookup");
    let mut buf = vec![0u8; 100_000];
    assert_eq!(v.read_file(&hit.entry, 0, &mut buf), Err(Errno::Eio));
}

/// An empty file names no cluster, so reading it must not walk a chain from
/// cluster zero — which is a reserved entry, not data.
#[test]
fn an_empty_file_reads_nothing_without_walking_a_chain() {
    let mut img = Builder::new();
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"EMPTY   TXT", ATTR_ARCH, 0, 0)]);
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("EMPTY.TXT").expect("lookup");
    assert_eq!(v.read_whole(&hit.entry), Ok(vec![]));
    let mut buf = vec![0u8; 16];
    assert_eq!(v.read_file(&hit.entry, 0, &mut buf), Ok(0));
}

/// The fixed root is a region, not a chain. Walking it as one reads table
/// entry zero — the media descriptor — and follows it somewhere arbitrary.
#[test]
fn the_fixed_root_is_read_as_a_region_not_a_chain() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
    assert!(v.geometry().has_fixed_root());
    assert!(v.read_root().is_ok(), "the root reads without consulting the table");
    // Entry 0 holds the media descriptor, which as a link would be an end
    // mark — a root read through it would come back empty.
    assert_eq!(crate::chain::read_entry(FatWidth::Fat16, &v.table, 0),
               Some(crate::chain::Link::End));
    assert!(!v.read_root().unwrap().is_empty());
}
