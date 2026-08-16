use super::*;
use crate::test_image::{self, Builder, CLUSTER};
use crate::uapi::*;

#[test]
fn a_formatted_volume_mounts_and_finds_its_own_files() {
    let v = test_image::empty();
    assert_eq!(v.geometry().cluster_size, CLUSTER as u32);
    assert_eq!(v.geometry().record_size, test_image::RECORD_SIZE);
    assert_eq!(v.geometry().index_size, test_image::INDEX_SIZE);
    assert_eq!(v.mft_records(), test_image::MFT_RECORDS);
    assert_eq!(v.label(), "OXIDE");
    assert_eq!(v.version(), (3, 1));
}

#[test]
fn a_file_a_formatter_wrote_reads_back() {
    let mut b = Builder::new();
    b.push_file("hello.txt", b"hello ntfs");
    let v = test_image::mount(b);
    let hit = v.find_entry(MFT_REC_ROOT, "hello.txt").unwrap();
    assert_eq!(hit.size(), 10);
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"hello ntfs");
}

#[test]
fn a_resident_and_a_nonresident_file_both_read() {
    let small = b"small enough to live in the record".to_vec();
    let large: alloc::vec::Vec<u8> = (0..CLUSTER * 2 + 7).map(|i| (i % 251) as u8).collect();
    let mut b = Builder::new();
    b.push_file("small.txt", &small);
    b.push_file("large.bin", &large);
    let v = test_image::mount(b);
    let a = v.find_entry(MFT_REC_ROOT, "small.txt").unwrap();
    let c = v.find_entry(MFT_REC_ROOT, "large.bin").unwrap();
    assert_eq!(v.read_whole(a.reference.number).unwrap(), small);
    assert_eq!(v.read_whole(c.reference.number).unwrap(), large);
}

#[test]
fn a_directory_lists_its_names_in_key_order() {
    let mut b = Builder::new();
    b.push_file("zebra.txt", b"z");
    b.push_file("apple.txt", b"a");
    b.push_dir("middle");
    let v = test_image::mount(b);
    let names: alloc::vec::Vec<_> = v.read_dir(MFT_REC_ROOT).unwrap()
        .into_iter().map(|e| e.name).collect();
    assert_eq!(names, alloc::vec!["apple.txt", "middle", "zebra.txt"]);
}

#[test]
fn a_lookup_is_case_insensitive_through_the_volumes_own_table() {
    let mut b = Builder::new();
    b.push_file("MixedCase.TXT", b"x");
    let v = test_image::mount(b);
    assert!(v.find_entry(MFT_REC_ROOT, "mixedcase.txt").is_ok());
    assert!(v.find_entry(MFT_REC_ROOT, "MIXEDCASE.TXT").is_ok());
    assert!(v.find_entry(MFT_REC_ROOT, "mixedcase.tx").is_err());
}

#[test]
fn a_fragmented_file_reads_in_order() {
    // Three runs the reader must follow rather than assuming contiguity.
    let mut b = Builder::new();
    let mut runs = crate::run::Runs::new();
    let mut payload = alloc::vec::Vec::new();
    for (i, lcn) in [200u64, 260, 220].into_iter().enumerate() {
        let at = b.cluster_at(lcn);
        let fill = alloc::vec![(i as u8 + 1); CLUSTER];
        b.bytes[at..at + CLUSTER].copy_from_slice(&fill);
        payload.extend_from_slice(&fill);
        runs.push(crate::run::Run { vcn: i as u64, lcn, len: 1 });
    }
    b.push_file_runs("frag.bin", &runs, payload.len() as u64, 0, 0);
    let v = test_image::mount(b);
    let hit = v.find_entry(MFT_REC_ROOT, "frag.bin").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), payload);
}

#[test]
fn a_hole_reads_as_zeros_not_as_cluster_zero() {
    // Cluster zero is the boot sector; reading a hole from it would put the
    // boot sector in the middle of a file.
    let mut b = Builder::new();
    let at = b.cluster_at(300);
    b.bytes[at..at + CLUSTER].copy_from_slice(&alloc::vec![0xEE; CLUSTER]);
    let mut runs = crate::run::Runs::new();
    runs.push(crate::run::Run { vcn: 0, lcn: SPARSE_LCN, len: 1 });
    runs.push(crate::run::Run { vcn: 1, lcn: 300, len: 1 });
    b.push_file_runs("sparse.bin", &runs, (CLUSTER * 2) as u64,
                     crate::uapi::ATTR_FLAG_SPARSED, 0);
    let v = test_image::mount(b);
    let hit = v.find_entry(MFT_REC_ROOT, "sparse.bin").unwrap();
    let bytes = v.read_whole(hit.reference.number).unwrap();
    assert!(bytes[..CLUSTER].iter().all(|x| *x == 0), "the hole read as data");
    assert!(bytes[CLUSTER..].iter().all(|x| *x == 0xEE));
}

#[test]
fn a_read_stops_at_the_valid_size() {
    let mut b = Builder::new();
    let at = b.cluster_at(310);
    b.bytes[at..at + CLUSTER].copy_from_slice(&alloc::vec![0xAA; CLUSTER]);
    let mut runs = crate::run::Runs::new();
    runs.push(crate::run::Run { vcn: 0, lcn: 310, len: 1 });
    b.push_file_runs("short.bin", &runs, 16, 0, 0);
    let v = test_image::mount(b);
    let hit = v.find_entry(MFT_REC_ROOT, "short.bin").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap().len(), 16);
}

#[test]
fn a_path_resolves_through_directories() {
    let mut b = Builder::new();
    b.push_dir("sub");
    let v = test_image::mount(b);
    assert!(v.lookup("/sub").is_ok());
    assert!(v.lookup("/sub/missing").is_err());
}

#[test]
fn statfs_reports_real_inode_counts() {
    let v = test_image::empty();
    let space = v.space();
    assert_eq!(space.cluster_bytes, CLUSTER as u64);
    assert_eq!(space.total, test_image::CLUSTERS);
    assert_eq!(space.records, test_image::MFT_RECORDS);
    assert!(space.records_free > 0 && space.records_free < space.records);
    assert_eq!(space.name_max, NTFS_NAME_LEN as u64);
}

#[test]
fn the_mirror_agrees_with_the_table_it_mirrors() {
    let v = test_image::empty();
    assert!(v.mirror_agrees().unwrap());
}

#[test]
fn a_record_the_bitmap_calls_free_is_not_read_as_a_file() {
    let v = test_image::empty();
    // A record past everything the fixture wrote was never formatted, so
    // reading it as a file resurrects nothing.
    assert!(v.stat(test_image::MFT_RECORDS - 1).is_err());
}

#[test]
fn a_read_only_volume_refuses_every_write() {
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let mut v = crate::volume::Volume::mount_with(Builder::new().finish().read_only(), opts)
        .unwrap();
    assert!(!v.writable());
    assert_eq!(v.create_file(MFT_REC_ROOT, "new.txt", 0), Err(syscall::errno::Errno::Erofs));
}

#[test]
fn a_volume_that_is_not_ntfs_is_refused() {
    let image = Builder::new().finish();
    image.poke(BOOT_OFF_SYSTEM_ID, b"FAT32   ");
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    assert!(crate::volume::Volume::mount_with(image, opts).is_err());
}

#[test]
fn a_records_data_across_a_sector_boundary_survives_the_update_sequence() {
    // Two bytes of every 512 in a record are the sequence value on the
    // medium. A reader that does not put back what they displaced returns a
    // record with those bytes wrong — and only data that CROSSES a boundary
    // shows it, which is why this fixture is sized to cross one.
    let payload: alloc::vec::Vec<u8> = (0..400u32).map(|i| (i % 251) as u8).collect();
    let mut b = Builder::new();
    b.push_file("crossing.bin", &payload);
    let v = test_image::mount(b);
    let hit = v.find_entry(MFT_REC_ROOT, "crossing.bin").unwrap();
    let (bytes, attrs) = v.read_record(hit.reference.number).unwrap();
    let attr = crate::attrib::find(&attrs, ATTR_DATA, &[]).unwrap();
    let (start, end) = attr.resident_span().unwrap();
    assert!(start < SECTOR_BYTES && end > SECTOR_BYTES,
            "the fixture must straddle a sector boundary: {start}..{end}");
    let _ = bytes;
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), payload);
}

#[test]
fn a_directory_index_in_a_block_is_read_through_its_own_sequence() {
    // An index block is fixed up like a record, and its header sits at 0x18
    // rather than 0x30 — a reader that assumes the record's layout puts the
    // array in the middle of the block's own header.
    let bytes = crate::index::format_block(test_image::INDEX_SIZE, 0);
    // The array sits after the node header, so the header's own lengths
    // survive being written.
    let fix_off = u16::from_le_bytes([bytes[REC_OFF_FIX_OFF], bytes[REC_OFF_FIX_OFF + 1]]);
    assert!(fix_off as usize >= IB_OFF_IHDR + SIZEOF_IHDR, "the array overwrites the header");
    assert!(crate::index::parse_block(&bytes, 0).is_some());

    let mut fixed = bytes.clone();
    crate::fixup::pre_write(&mut fixed, 0x2233).unwrap();
    for sector in 1..=(test_image::INDEX_SIZE as usize / SECTOR_BYTES) {
        let tail = sector * SECTOR_BYTES - 2;
        assert_eq!(&fixed[tail..tail + 2], &0x2233u16.to_le_bytes(), "sector {sector}");
    }
    crate::fixup::post_read(&mut fixed, false).unwrap();
    // Every sector's own last two bytes are back; the array keeps the copies,
    // which is what a reader would see on the medium too.
    for sector in 1..=(test_image::INDEX_SIZE as usize / SECTOR_BYTES) {
        let tail = sector * SECTOR_BYTES - 2;
        assert_eq!(fixed[tail..tail + 2], bytes[tail..tail + 2], "sector {sector}");
    }
    assert!(crate::index::parse_block(&fixed, 0).is_some());
}
