use super::*;
use alloc::vec;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Op { Read(u64), Write(u64), Flush, Commit(u64) }

struct MemDisk {
    stable: Vec<Page>,
    live: Vec<Page>,
    log: Vec<Op>,
    fail_at: Option<usize>,
    actions: usize,
    fail_commit_after_publish: bool,
}

impl MemDisk {
    fn new(pages: usize, header: usize) -> Self {
        let mut stable = vec![[0u8; format::PAGE_SIZE]; pages];
        stable[header][format::OFF_SIG..format::OFF_SIG + 10].copy_from_slice(&format::SWAP_SIG_NEW);
        Self { live: stable.clone(), stable, log: Vec::new(), fail_at: None, actions: 0,
            fail_commit_after_publish: false }
    }

    fn reopened(&self) -> Self {
        Self { live: self.stable.clone(), stable: self.stable.clone(), log: Vec::new(),
            fail_at: None, actions: 0, fail_commit_after_publish: false }
    }

    fn action(&mut self, op: Op) -> Result<(), ()> {
        self.log.push(op);
        let fail = self.fail_at == Some(self.actions);
        self.actions += 1;
        if fail { Err(()) } else { Ok(()) }
    }
}

impl Storage for MemDisk {
    type Error = ();
    fn page_count(&self) -> u64 { self.live.len() as u64 }
    fn read_page(&mut self, page: u64, out: &mut Page) -> Result<(), ()> {
        self.action(Op::Read(page))?;
        *out = *self.live.get(page as usize).ok_or(())?;
        Ok(())
    }
    fn write_page(&mut self, page: u64, data: &Page) -> Result<(), ()> {
        self.action(Op::Write(page))?;
        *self.live.get_mut(page as usize).ok_or(())? = *data;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        self.action(Op::Flush)?;
        self.stable.clone_from(&self.live);
        Ok(())
    }
    fn commit_page(&mut self, page: u64, data: &Page) -> Result<(), ()> {
        if self.fail_commit_after_publish {
            self.log.push(Op::Commit(page));
            self.actions += 1;
            self.stable.clone_from(&self.live);
            *self.live.get_mut(page as usize).ok_or(())? = *data;
            *self.stable.get_mut(page as usize).ok_or(())? = *data;
            self.fail_commit_after_publish = false;
            return Err(());
        }
        self.action(Op::Commit(page))?;
        self.stable.clone_from(&self.live);
        *self.live.get_mut(page as usize).ok_or(())? = *data;
        *self.stable.get_mut(page as usize).ok_or(())? = *data;
        Ok(())
    }
}

fn header() -> Header {
    Header {
        flags: format::FLAG_NOCOMPRESS | format::FLAG_CRC32, checksum: 0, first_map: 0,
        image_pages: 0, zero_pages: 0, stream_pages: 0, arch: 1, cpu_count: 2, hardware_sig: 3,
        build_id: [4; 32], topology_id: [5; 32], cpu_id: [6; 32], arch_data: [7; 128],
        original_sig: [0; 10],
    }
}

fn page(byte: u8) -> Page { [byte; format::PAGE_SIZE] }

#[test]
fn format_offsets_are_linux_swap_overlay_compatible() {
    assert_eq!(format::OFF_ORIG_SIG, format::PAGE_SIZE - 20);
    assert_eq!(format::OFF_SIG, format::PAGE_SIZE - 10);
    assert_eq!(format::MAP_ENTRIES, 511);
    let mut raw = [0xA5; format::PAGE_SIZE];
    raw[format::OFF_SIG..].copy_from_slice(&format::SWAP_SIG_OLD);
    let mut h = header(); h.first_map = 9; h.image_pages = 1;
    format::mark(&mut raw, &h).unwrap();
    assert_eq!(&raw[format::OFF_ORIG_SIG..format::OFF_SIG], b"SWAP-SPACE");
    assert_eq!(&raw[format::OFF_SIG..], b"S1SUSPEND\0");
}

#[test]
fn header_golden_bytes_pin_every_field_offset_and_little_endian_order() {
    let mut raw = [0xA5; format::PAGE_SIZE];
    raw[4086..4096].copy_from_slice(&format::SWAP_SIG_OLD);
    let h = Header {
        flags: format::FLAG_NOCOMPRESS | format::FLAG_CRC32, checksum: 0x5566_7788,
        first_map: 0x0102_0304_0506_0708,
        image_pages: 0x1112_1314_1516_1718,
        zero_pages: 0x2122_2324_2526_2728,
        stream_pages: 0x3132_3334_3536_3738,
        arch: 0x4142_4344, cpu_count: 0x5152_5354,
        hardware_sig: 0x6162_6364,
        build_id: core::array::from_fn(|i| i as u8),
        topology_id: core::array::from_fn(|i| 0x20 + i as u8),
        cpu_id: core::array::from_fn(|i| 0x40 + i as u8),
        arch_data: core::array::from_fn(|i| 0x80u8.wrapping_add(i as u8)),
        original_sig: [0; 10],
    };
    format::mark(&mut raw, &h).unwrap();

    let mut expected = [0xA5; format::PAGE_SIZE];
    expected[0..8].copy_from_slice(b"OXHIBIMG");
    expected[8..12].copy_from_slice(&1u32.to_le_bytes());
    expected[12..16].copy_from_slice(&4096u32.to_le_bytes());
    expected[16..24].copy_from_slice(&h.image_pages.to_le_bytes());
    expected[24..32].copy_from_slice(&h.zero_pages.to_le_bytes());
    expected[32..36].copy_from_slice(&h.arch.to_le_bytes());
    expected[36..40].copy_from_slice(&h.cpu_count.to_le_bytes());
    expected[40..72].copy_from_slice(&h.build_id);
    expected[72..104].copy_from_slice(&h.topology_id);
    expected[104..136].copy_from_slice(&h.cpu_id);
    expected[136..264].copy_from_slice(&h.arch_data);
    expected[264..272].copy_from_slice(&h.stream_pages.to_le_bytes());
    expected[4056..4060].copy_from_slice(&h.hardware_sig.to_le_bytes());
    expected[4060..4064].copy_from_slice(&h.checksum.to_le_bytes());
    expected[4064..4072].copy_from_slice(&h.first_map.to_le_bytes());
    expected[4072..4076].copy_from_slice(&h.flags.to_le_bytes());
    expected[4076..4086].copy_from_slice(&format::SWAP_SIG_OLD);
    expected[4086..4096].copy_from_slice(&format::HIBERNATE_SIG);
    assert_eq!(raw, expected);
    assert_eq!(format::decode(&raw).unwrap(), Header { original_sig: format::SWAP_SIG_OLD, ..h });
}

#[test]
fn map_golden_bytes_pin_all_locators_link_offset_and_endian_order() {
    let entries: Vec<u64> = (0..format::MAP_ENTRIES)
        .map(|i| 0x0102_0304_0000_0000 | i as u64).collect();
    let next = 0x8899_AABB_CCDD_EEFF;
    let encoded = format::encode_map(&entries, next).unwrap();
    let mut expected = [0u8; format::PAGE_SIZE];
    for (index, value) in entries.iter().enumerate() {
        expected[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    expected[4088..4096].copy_from_slice(&next.to_le_bytes());
    assert_eq!(encoded, expected);
    let (decoded, decoded_next) = format::decode_map(&encoded);
    assert_eq!(&decoded[..], entries.as_slice());
    assert_eq!(decoded_next, next);
}

#[test]
fn image_round_trips_after_storage_owner_reopens() {
    let mut disk = MemDisk::new(16, 0);
    let pages = [page(0x31), page(0x72)];
    write_image(&mut disk, &Plan { header_page: 0, map_pages: &[4], data_pages: &[8, 12] }, header(), &pages).unwrap();
    assert_eq!(disk.log, vec![Op::Read(0), Op::Write(8), Op::Write(12), Op::Write(4), Op::Flush, Op::Commit(0)]);
    let mut reopened = disk.reopened();
    let reader = ImageReader::open(&mut reopened, 0).unwrap();
    assert!(!format::is_marked(&reopened.stable[0]), "resume must consume marker before payload I/O");
    assert_eq!(reader.len(), 2);
    reader.verify_checksum(&mut reopened).unwrap();
    let mut out = [0; format::PAGE_SIZE];
    reader.read_page(&mut reopened, 1, &mut out).unwrap();
    assert_eq!(out, pages[1]);
    assert!(matches!(ImageReader::open(&mut reopened, 0), Err(Error::NoImage)));
}

#[test]
fn open_report_never_guesses_marker_consumption() {
    let mut empty = MemDisk::new(8, 0);
    let absent = match ImageReader::open_report(&mut empty, 0) {
        Err(failure) => failure,
        Ok(_) => panic!("unmarked swap header admitted"),
    };
    assert_eq!(absent, OpenFailure { error: Error::NoImage, marker_consumed: false });

    let mut disk = MemDisk::new(16, 0);
    write_image(&mut disk, &Plan { header_page: 0, map_pages: &[4], data_pages: &[8] },
        header(), &[page(0x31)]).unwrap();
    disk.stable[4][..8].copy_from_slice(&99u64.to_le_bytes());
    let mut corrupt = disk.reopened();
    let rejected = match ImageReader::open_report(&mut corrupt, 0) {
        Err(failure) => failure,
        Ok(_) => panic!("corrupt map admitted"),
    };
    assert_eq!(rejected, OpenFailure { error: Error::Bounds, marker_consumed: true });
    assert!(!format::is_marked(&corrupt.stable[0]));
}

#[test]
fn map_rollover_uses_a_forward_chain() {
    let count = format::MAP_ENTRIES + 1;
    let pages = vec![page(0x44); count];
    let data: Vec<u64> = (20..20 + count as u64).collect();
    let mut disk = MemDisk::new(600, 1);
    write_image(&mut disk, &Plan { header_page: 1, map_pages: &[9, 3], data_pages: &data }, header(), &pages).unwrap();
    let mut reopened = disk.reopened();
    let reader = ImageReader::open(&mut reopened, 1).unwrap();
    assert_eq!(reader.len(), count);
    reader.verify_checksum(&mut reopened).unwrap();
}

#[test]
fn every_write_or_flush_failure_leaves_no_durable_marker() {
    let plan = Plan { header_page: 1, map_pages: &[3], data_pages: &[7] };
    let pages = [page(0x55)];
    let mut probe = MemDisk::new(12, 1);
    write_image(&mut probe, &plan, header(), &pages).unwrap();
    let action_count = probe.actions;
    for fail_at in 0..action_count {
        let mut disk = MemDisk::new(12, 1);
        disk.fail_at = Some(fail_at);
        assert_eq!(write_image(&mut disk, &plan, header(), &pages), Err(Error::Io));
        let crashed = disk.reopened();
        assert!(!format::is_marked(&crashed.stable[1]), "failure published durable marker at action {fail_at}");
    }
}

#[test]
fn marker_first_positive_control_exposes_an_incomplete_image() {
    let mut disk = MemDisk::new(12, 1);
    let mut raw = disk.live[1];
    let mut h = header(); h.first_map = 3; h.image_pages = 1; h.stream_pages = 1;
    format::mark(&mut raw, &h).unwrap();
    disk.commit_page(1, &raw).unwrap();
    disk.write_page(7, &page(0xAA)).unwrap();
    let crashed = disk.reopened();
    assert!(format::is_marked(&crashed.stable[1]));
    assert_ne!(crashed.stable[7], page(0xAA), "RED control accidentally made payload durable");
}

fn marked_disk(entries: &[u64], next: u64, image_pages: u64) -> MemDisk {
    let mut disk = MemDisk::new(20, 1);
    let mut h = header(); h.first_map = 3; h.image_pages = image_pages;
    h.stream_pages = image_pages; h.checksum = 0;
    let mut raw = disk.live[1]; format::mark(&mut raw, &h).unwrap();
    disk.stable[1] = raw; disk.live[1] = raw;
    let map = format::encode_map(entries, next).unwrap();
    disk.stable[3] = map; disk.live[3] = map;
    disk
}

#[test]
fn hostile_maps_are_consumed_then_rejected() {
    let cases = [
        (marked_disk(&[0], 0, 1), Error::PrematureEnd),
        (marked_disk(&[1], 0, 1), Error::Bounds),
        (marked_disk(&[7, 7], 0, 2), Error::Duplicate),
        (marked_disk(&[7, 8], 0, 1), Error::TrailingEntry),
    ];
    for (mut disk, expected) in cases {
        let actual = ImageReader::open(&mut disk, 1).err().expect("hostile map was admitted");
        assert_eq!(actual, expected);
        assert!(!format::is_marked(&disk.stable[1]), "rejected image retained its marker");
    }
    let entries: Vec<u64> = (20..20 + format::MAP_ENTRIES as u64).collect();
    let mut cycle = MemDisk::new(600, 1);
    let mut h = header(); h.first_map = 3; h.image_pages = (format::MAP_ENTRIES + 1) as u64;
    h.stream_pages = h.image_pages;
    let mut raw = cycle.live[1]; format::mark(&mut raw, &h).unwrap();
    cycle.stable[1] = raw; cycle.live[1] = raw;
    let map = format::encode_map(&entries, 3).unwrap();
    cycle.stable[3] = map; cycle.live[3] = map;
    assert_eq!(ImageReader::open(&mut cycle, 1).err(), Some(Error::Cycle));
    assert!(!format::is_marked(&cycle.stable[1]));
}

#[test]
fn corrupt_payload_fails_checksum_after_admission() {
    let mut disk = MemDisk::new(12, 1);
    write_image(&mut disk, &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(9)]).unwrap();
    disk.stable[7][0] ^= 1; disk.live.clone_from(&disk.stable);
    let reader = ImageReader::open(&mut disk, 1).unwrap();
    assert_eq!(reader.verify_checksum(&mut disk), Err(Error::Checksum));
}

#[test]
fn both_compressed_chunk_modes_round_trip_exact_logical_pages() {
    let pages = [page(0x11), page(0x11), page(0x72), page(0x72), page(0x72)];
    for compression in [Compression::Lzo, Compression::Lz4] {
        let mut disk = MemDisk::new(20, 1);
        let data = [7, 8, 10, 11, 12, 13];
        write_image_with(&mut disk,
            &Plan { header_page: 1, map_pages: &[3], data_pages: &data }, header(), &pages,
            compression).unwrap();
        let mut reopened = disk.reopened();
        let reader = ImageReader::open(&mut reopened, 1).unwrap();
        assert_eq!(format::compression(reader.header.flags), Ok(compression));
        assert_eq!(reader.len(), pages.len());
        reader.verify_checksum(&mut reopened).unwrap();
        for (index, expected) in pages.iter().enumerate() {
            let mut actual = [0u8; format::PAGE_SIZE];
            reader.read_page(&mut reopened, index, &mut actual).unwrap();
            assert_eq!(&actual, expected);
        }
    }
}

#[test]
fn codec_capacity_covers_raw_full_and_tail_chunks_without_whole_image_storage() {
    assert_eq!(max_stored_pages(33, Compression::None), Ok(33));
    let full = (super::super::codec::worst_size(super::super::codec::CHUNK_BYTES)
        + super::super::codec::LENGTH_BYTES)
        .div_ceil(format::PAGE_SIZE);
    let tail = (super::super::codec::worst_size(format::PAGE_SIZE)
        + super::super::codec::LENGTH_BYTES)
        .div_ceil(format::PAGE_SIZE);
    assert_eq!(max_stored_pages(33, Compression::Lzo), Ok(full + tail));
    assert_eq!(max_stored_pages(33, Compression::Lz4), Ok(full + tail));
    assert_eq!(max_stored_pages(0, Compression::Lz4), Err(Error::Bounds));
    assert_eq!(max_stored_pages(usize::MAX, Compression::Lzo), Err(Error::Bounds));
}

#[test]
fn every_underreserved_compressed_payload_capacity_fails_before_marker_publication() {
    let logical_pages = super::super::codec::CHUNK_PAGES + 1;
    let capacity = max_stored_pages(logical_pages, Compression::Lz4).unwrap();
    let mut state = 0xD00D_F00Du32;
    let pages: Vec<Page> = (0..logical_pages).map(|_| {
        let mut page = [0u8; format::PAGE_SIZE];
        for byte in &mut page {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            *byte = state as u8;
        }
        page
    }).collect();
    let probe_data: Vec<u64> = (10..10 + capacity as u64).collect();
    let mut probe = MemDisk::new(10 + capacity, 1);
    assert!(stage_image(&mut probe,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &probe_data }, header(), &pages,
        Compression::Lz4).is_ok());
    let required = probe.log.iter().filter(|op| matches!(op, Op::Write(page) if *page >= 10)).count();
    assert!(required > logical_pages, "positive control must exercise compressed expansion");
    assert!(required <= capacity, "published worst-case bound must cover actual expansion");
    for available in 1..required {
        let data: Vec<u64> = (10..10 + available as u64).collect();
        let mut disk = MemDisk::new(10 + capacity, 1);
        let result = stage_image(&mut disk,
            &Plan { header_page: 1, map_pages: &[3], data_pages: &data }, header(), &pages,
            Compression::Lz4);
        assert!(matches!(result, Err(Error::Bounds)),
            "payload reservation {available}/{required} unexpectedly admitted");
        assert!(!format::is_marked(&disk.stable[1]));
    }
    let data: Vec<u64> = (10..10 + required as u64).collect();
    let mut disk = MemDisk::new(10 + capacity, 1);
    assert!(stage_image(&mut disk,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &data }, header(), &pages,
        Compression::Lz4).is_ok(), "exact observed reservation must be sufficient");
}

#[test]
fn malformed_and_physically_truncated_chunks_are_rejected_after_consumption() {
    for (encoded_len, expected) in [(1u64, Error::Format), (format::PAGE_SIZE as u64, Error::PrematureEnd)] {
        let mut disk = MemDisk::new(12, 1);
        write_image_with(&mut disk,
            &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(0x41)],
            Compression::Lz4).unwrap();
        disk.stable[7][..8].copy_from_slice(&encoded_len.to_le_bytes());
        disk.live.clone_from(&disk.stable);
        assert_eq!(ImageReader::open(&mut disk, 1).err(), Some(expected));
        assert!(!format::is_marked(&disk.stable[1]));
    }
}

#[test]
fn incompressible_lz4_chunks_roll_over_the_physical_map_chain() {
    let count = format::MAP_ENTRIES + 1;
    let mut state = 0x1234_5678u32;
    let mut pages = Vec::with_capacity(count);
    for _ in 0..count {
        let mut value = [0u8; format::PAGE_SIZE];
        for byte in &mut value {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            *byte = state as u8;
        }
        pages.push(value);
    }
    let data: Vec<u64> = (20..580).collect();
    let mut disk = MemDisk::new(600, 1);
    write_image_with(&mut disk,
        &Plan { header_page: 1, map_pages: &[9, 3], data_pages: &data }, header(), &pages,
        Compression::Lz4).unwrap();
    let mut reopened = disk.reopened();
    let reader = ImageReader::open(&mut reopened, 1).unwrap();
    assert!(reader.locators.len() > format::MAP_ENTRIES, "positive control did not cross a map page");
    assert_eq!(reader.len(), count);
    reader.verify_checksum(&mut reopened).unwrap();
    let mut last = [0u8; format::PAGE_SIZE];
    reader.read_page(&mut reopened, count - 1, &mut last).unwrap();
    assert_eq!(last, pages[count - 1]);
}

#[test]
fn staged_marker_is_invisible_until_commit_and_unmark_is_durable() {
    let mut disk = MemDisk::new(12, 1);
    let marker = stage_image(&mut disk,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(0x55)],
        Compression::None).unwrap();
    assert!(!format::is_marked(&disk.reopened().stable[1]));
    commit_image(&mut disk, marker).unwrap();
    assert!(format::is_marked(&disk.reopened().stable[1]));
    unmark_image(&mut disk, 1).unwrap();
    assert!(!format::is_marked(&disk.reopened().stable[1]));
}

#[test]
fn failed_unmark_commit_cannot_claim_the_marker_was_consumed() {
    let mut disk = MemDisk::new(12, 1);
    write_image(&mut disk,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(0x55)])
        .unwrap();
    disk.fail_at = Some(disk.actions + 1);
    assert_eq!(unmark_image(&mut disk, 1), Err(Error::Io));
    assert!(format::is_marked(&disk.reopened().stable[1]));
}

#[test]
fn post_publication_commit_error_is_recoverable_only_by_durable_unmark() {
    let mut disk = MemDisk::new(12, 1);
    let marker = stage_image(&mut disk,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(0x55)],
        Compression::None).unwrap();
    disk.fail_commit_after_publish = true;
    assert_eq!(commit_image(&mut disk, marker), Err(Error::Io));
    assert!(format::is_marked(&disk.reopened().stable[1]),
        "positive control must publish before reporting the injected error");
    unmark_image(&mut disk, 1).unwrap();
    assert!(!format::is_marked(&disk.reopened().stable[1]));
}

#[test]
fn pre_publication_commit_error_still_requires_a_durable_unmarked_commit() {
    let mut disk = MemDisk::new(12, 1);
    let marker = stage_image(&mut disk,
        &Plan { header_page: 1, map_pages: &[3], data_pages: &[7] }, header(), &[page(0x55)],
        Compression::None).unwrap();
    disk.fail_at = Some(disk.actions);
    assert_eq!(commit_image(&mut disk, marker), Err(Error::Io));
    let commits = disk.log.iter().filter(|op| matches!(op, Op::Commit(1))).count();
    unmark_image(&mut disk, 1).unwrap();
    assert_eq!(disk.log.iter().filter(|op| matches!(op, Op::Commit(1))).count(), commits + 1,
        "an already-unmarked header must still receive a durable FUA proof");
    assert!(!format::is_marked(&disk.reopened().stable[1]));
}
