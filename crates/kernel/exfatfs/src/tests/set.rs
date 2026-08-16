use super::*;
use crate::time::Stamp;
use crate::uapi::*;

fn stamp() -> Stamp {
    Stamp { fields: dostime::DosTime { time: (9 << 11) | (15 << 5) | 3, date: (30 << 9) | (4 << 5) | 8, cs: 40 },
            tz: TZ_VALID }
}

fn units(name: &str) -> alloc::vec::Vec<u16> { name.encode_utf16().collect() }

fn built(name: &str) -> alloc::vec::Vec<u8> {
    build(ATTR_ARCHIVE, &units(name), 0xBEEF, 7, 4096, 100, ALLOC_NO_FAT_CHAIN,
          stamp(), stamp(), stamp()).unwrap()
}

#[test]
fn a_set_round_trips_through_both_directions() {
    let bytes = built("readme.txt");
    let parsed = parse(&bytes, 64).unwrap();
    assert_eq!(parsed.name(), "readme.txt");
    assert_eq!(parsed.offset, 64);
    assert_eq!(parsed.entries, 3);
    assert_eq!(parsed.stream.start_cluster, 7);
    assert_eq!(parsed.stream.size, 4096);
    assert_eq!(parsed.stream.valid_size, 100);
    assert_eq!(parsed.stream.name_hash, 0xBEEF);
    assert_eq!(parsed.file.attr, ATTR_ARCHIVE);
    assert_eq!(parsed.file.create, stamp());
    assert!(!parsed.is_dir());
}

#[test]
fn the_entry_count_covers_the_whole_name() {
    // Sixteen units needs two name entries, and the file entry's count must
    // say so or the second entry is read as a separate record.
    let bytes = built("0123456789abcdef");
    let parsed = parse(&bytes, 0).unwrap();
    assert_eq!(parsed.entries, 4);
    assert_eq!(parsed.file.num_ext, 3);
    assert_eq!(bytes.len(), 4 * DENTRY_BYTES);
}

#[test]
fn a_set_a_single_byte_of_which_changed_fails_its_checksum() {
    // The checksum is what makes a set valid as a whole; a name entry
    // rewritten without resealing reads back as corrupt.
    let mut bytes = built("readme.txt");
    bytes[ES_IDX_FIRST_NAME * DENTRY_BYTES + NAME_OFF_CHARS] ^= 0xFF;
    assert_eq!(parse(&bytes, 0), Err(SetError::BadChecksum));
    reseal(&mut bytes);
    assert!(parse(&bytes, 0).is_ok());
}

#[test]
fn a_stream_entry_that_is_not_one_is_refused() {
    let mut bytes = built("readme.txt");
    bytes[ES_IDX_STREAM * DENTRY_BYTES] = TYPE_NAME;
    reseal(&mut bytes);
    assert_eq!(parse(&bytes, 0), Err(SetError::NoStream));
}

#[test]
fn a_set_the_bytes_end_before_is_refused() {
    let bytes = built("readme.txt");
    assert_eq!(parse(&bytes[..DENTRY_BYTES * 2], 0), Err(SetError::Truncated));
}

#[test]
fn a_count_too_small_to_be_a_set_is_refused() {
    let mut bytes = built("readme.txt");
    bytes[FILE_OFF_NUM_EXT] = 1;
    reseal(&mut bytes[..2 * DENTRY_BYTES]);
    assert_eq!(parse(&bytes, 0), Err(SetError::BadCount));
}

#[test]
fn a_declared_name_longer_than_its_entries_is_refused() {
    let mut bytes = built("short");
    bytes[ES_IDX_STREAM * DENTRY_BYTES + STREAM_OFF_NAME_LEN] = 200;
    reseal(&mut bytes);
    assert_eq!(parse(&bytes, 0), Err(SetError::ShortName));
}

#[test]
fn a_name_of_no_length_is_refused() {
    let mut bytes = built("short");
    bytes[ES_IDX_STREAM * DENTRY_BYTES + STREAM_OFF_NAME_LEN] = 0;
    reseal(&mut bytes);
    assert_eq!(parse(&bytes, 0), Err(SetError::ShortName));
}

#[test]
fn a_name_shorter_than_its_entry_ignores_the_padding() {
    // A name entry always carries fifteen units; the ones past the declared
    // length are padding, not characters.
    let parsed = parse(&built("ab"), 0).unwrap();
    assert_eq!(parsed.units.len(), 2);
    assert_eq!(parsed.name(), "ab");
}

#[test]
fn a_deleted_set_keeps_what_kind_of_entry_each_was() {
    let mut bytes = built("gone.txt");
    mark_deleted(&mut bytes);
    assert_eq!(bytes[0], TYPE_FILE & !IN_USE_BIT);
    assert_eq!(bytes[DENTRY_BYTES], TYPE_STREAM & !IN_USE_BIT);
    assert_eq!(bytes[2 * DENTRY_BYTES], TYPE_NAME & !IN_USE_BIT);
    for entry in bytes.chunks(DENTRY_BYTES) {
        assert!(crate::dirent::kind::is_deleted(entry[0]));
        assert!(!crate::dirent::kind::is_in_use(entry[0]));
    }
}

#[test]
fn a_directory_set_carries_the_subdirectory_attribute() {
    let bytes = build(ATTR_SUBDIR, &units("dir"), 1, 9, 4096, 4096, ALLOC_NO_FAT_CHAIN,
                      stamp(), stamp(), stamp()).unwrap();
    assert!(parse(&bytes, 0).unwrap().is_dir());
}

#[test]
fn the_stream_entrys_own_offset_is_where_a_size_update_lands() {
    let parsed = parse(&built("f"), 320).unwrap();
    assert_eq!(parsed.stream_offset(), 320 + DENTRY_BYTES as u64);
}

#[test]
fn a_benign_secondary_entry_past_the_name_is_kept() {
    // Rewriting a set without it silently discards another system's data.
    let mut bytes = built("f");
    let mut extra = alloc::vec![0u8; DENTRY_BYTES];
    extra[0] = TYPE_VENDOR_ALLOC;
    extra[SECONDARY_OFF_FLAGS] = ALLOC_POSSIBLE;
    extra[SECONDARY_OFF_START_CLU..SECONDARY_OFF_START_CLU + 4]
        .copy_from_slice(&40u32.to_le_bytes());
    extra[SECONDARY_OFF_SIZE..SECONDARY_OFF_SIZE + 8].copy_from_slice(&4096u64.to_le_bytes());
    bytes.extend_from_slice(&extra);
    bytes[FILE_OFF_NUM_EXT] += 1;
    reseal(&mut bytes);
    let parsed = parse(&bytes, 0).unwrap();
    assert_eq!(parsed.entries, 4);
    assert_eq!(parsed.name(), "f");
    assert_eq!(extra_entries(&bytes, parsed.units.len()), extra);
    assert_eq!(secondary_allocation(&extra), Some((40, 4096)));
}

#[test]
fn an_entry_with_no_allocation_reports_none() {
    let mut extra = alloc::vec![0u8; DENTRY_BYTES];
    extra[0] = TYPE_VENDOR_ALLOC;
    assert_eq!(secondary_allocation(&extra), None);
    // A name entry never carries clusters, whatever those bytes hold.
    let mut name = alloc::vec![0u8; DENTRY_BYTES];
    name[0] = TYPE_NAME;
    name[SECONDARY_OFF_START_CLU] = 5;
    name[SECONDARY_OFF_SIZE] = 1;
    assert_eq!(secondary_allocation(&name), None);
}

#[test]
fn a_name_at_the_length_ceiling_builds_the_widest_set() {
    let long: alloc::string::String = core::iter::repeat('x').take(MAX_NAME_LENGTH).collect();
    let bytes = build(ATTR_ARCHIVE, &units(&long), 1, 0, 0, 0, ALLOC_FAT_CHAIN,
                      stamp(), stamp(), stamp()).unwrap();
    assert_eq!(bytes.len(), 19 * DENTRY_BYTES);
    assert_eq!(parse(&bytes, 0).unwrap().name(), long);
}

#[test]
fn a_name_past_the_ceiling_is_refused_before_anything_is_written() {
    let long: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert_eq!(build(ATTR_ARCHIVE, &units(&long), 1, 0, 0, 0, ALLOC_FAT_CHAIN,
                     stamp(), stamp(), stamp()), Err(SetError::BadCount));
    assert_eq!(build(ATTR_ARCHIVE, &[], 1, 0, 0, 0, ALLOC_FAT_CHAIN,
                     stamp(), stamp(), stamp()), Err(SetError::BadCount));
}

#[test]
fn only_a_file_entry_starts_a_set() {
    assert!(is_name_set(TYPE_FILE));
    assert!(!is_name_set(TYPE_STREAM));
    assert!(!is_name_set(TYPE_BITMAP));
    assert!(!is_name_set(TYPE_FILE & !IN_USE_BIT));
}
