use super::*;
use crate::checksum;
use crate::uapi::{UPCASE_ENTRIES, UPCASE_SKIP_MARKER};

/// The compressed form of the built-in table, with the checksum it needs.
fn stored() -> (alloc::vec::Vec<u8>, u32) {
    let bytes = compress(&builtin());
    let sum = checksum::sum32(&bytes, 0);
    (bytes, sum)
}

#[test]
fn a_stored_table_round_trips_through_both_directions() {
    let (bytes, sum) = stored();
    let loaded = load(&bytes, sum).unwrap();
    assert_eq!(loaded.raw(), builtin().raw());
}

#[test]
fn a_table_whose_checksum_does_not_match_is_refused() {
    // A table that expands correctly but whose bytes were altered folds
    // differently from what the volume recorded — which changes which names
    // collide.
    let (bytes, sum) = stored();
    assert_eq!(load(&bytes, sum.wrapping_add(1)).err(), Some(UpCaseError::BadChecksum));
}

#[test]
fn a_table_that_stops_early_is_refused() {
    // Truncating leaves the characters it never reached folding to
    // themselves, which silently changes which names are the same name.
    let (bytes, _) = stored();
    let half = &bytes[..bytes.len() / 2];
    assert_eq!(load(half, checksum::sum32(half, 0)).err(), Some(UpCaseError::Incomplete));
}

#[test]
fn the_skip_marker_introduces_a_run_of_identity_entries() {
    // 0xFFFF then a count: the count's worth of characters fold to
    // themselves.
    let mut bytes = alloc::vec::Vec::new();
    bytes.extend_from_slice(&UPCASE_SKIP_MARKER.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
    bytes.extend_from_slice(&UPCASE_SKIP_MARKER.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    let table = load(&bytes, checksum::sum32(&bytes, 0)).unwrap();
    assert_eq!(table.fold(b'a' as u16), b'a' as u16);
}

#[test]
fn a_unit_equal_to_its_index_is_an_identity_entry() {
    let mut bytes = alloc::vec::Vec::new();
    for index in 0..UPCASE_ENTRIES {
        bytes.extend_from_slice(&(index as u16).to_le_bytes());
    }
    let table = load(&bytes, checksum::sum32(&bytes, 0)).unwrap();
    assert_eq!(table.fold(0x0061), 0x0061);
}

#[test]
fn the_builtin_table_folds_ascii() {
    let t = builtin();
    assert_eq!(t.fold(b'a' as u16), b'A' as u16);
    assert_eq!(t.fold(b'z' as u16), b'Z' as u16);
    assert_eq!(t.fold(b'A' as u16), b'A' as u16);
    assert_eq!(t.fold(b'0' as u16), b'0' as u16);
    assert_eq!(t.fold(b'_' as u16), b'_' as u16);
}

#[test]
fn the_builtin_table_folds_the_accented_latin_blocks() {
    let t = builtin();
    // Latin-1 either side of the division sign, which is not a letter.
    assert_eq!(t.fold(0x00E9), 0x00C9);
    assert_eq!(t.fold(0x00F8), 0x00D8);
    assert_eq!(t.fold(0x00F7), 0x00F7);
    // Latin Extended-A, laid out as upper/lower pairs one apart.
    assert_eq!(t.fold(0x0101), 0x0100);
    assert_eq!(t.fold(0x013A), 0x0139);
    // The three that fold nowhere near themselves.
    assert_eq!(t.fold(0x00FF), 0x0178);
    assert_eq!(t.fold(0x00B5), 0x039C);
    assert_eq!(t.fold(0x017F), 0x0053);
}

#[test]
fn the_builtin_table_folds_greek_and_cyrillic() {
    let t = builtin();
    assert_eq!(t.fold(0x03B1), 0x0391);
    // Both sigmas fold to the same capital, which is what makes two spellings
    // of one Greek word the same name.
    assert_eq!(t.fold(0x03C3), 0x03A3);
    assert_eq!(t.fold(0x03C2), 0x03A3);
    assert_eq!(t.fold(0x0430), 0x0410);
    assert_eq!(t.fold(0x0451), 0x0401);
}

#[test]
fn folding_a_name_folds_every_unit() {
    let t = builtin();
    let folded = t.fold_name(&[b'M' as u16, b'i' as u16, b'X' as u16]);
    assert_eq!(folded, alloc::vec![b'M' as u16, b'I' as u16, b'X' as u16]);
}

#[test]
fn two_names_differing_only_in_case_are_the_same_name() {
    let t = builtin();
    let lower: alloc::vec::Vec<u16> = "readme.txt".encode_utf16().collect();
    let upper: alloc::vec::Vec<u16> = "README.TXT".encode_utf16().collect();
    let other: alloc::vec::Vec<u16> = "readme.tx".encode_utf16().collect();
    assert!(t.eq(&lower, &upper));
    assert!(!t.eq(&lower, &other));
}

#[test]
fn a_volume_whose_table_folds_nothing_makes_two_cases_two_names() {
    // The fold is the VOLUME's answer, not a rule of the format: a volume
    // whose table is identity has case-sensitive names.
    let mut bytes = alloc::vec::Vec::new();
    bytes.extend_from_slice(&UPCASE_SKIP_MARKER.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
    bytes.extend_from_slice(&UPCASE_SKIP_MARKER.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    let t = load(&bytes, checksum::sum32(&bytes, 0)).unwrap();
    let lower: alloc::vec::Vec<u16> = "a".encode_utf16().collect();
    let upper: alloc::vec::Vec<u16> = "A".encode_utf16().collect();
    assert!(!t.eq(&lower, &upper));
}
