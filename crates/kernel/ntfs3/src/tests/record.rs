use super::*;

const SIZE: u32 = 1024;

#[test]
fn a_formatted_record_parses_back() {
    let bytes = format(SIZE, 42, 7);
    let h = parse(&bytes).unwrap();
    assert_eq!(h.sequence, 7);
    assert_eq!(h.hard_links, 1);
    assert_eq!(h.total, SIZE);
    assert_eq!(h.record_number, 42);
    assert!(h.in_use());
    assert!(!h.is_dir());
    assert!(h.is_base());
}

#[test]
fn a_formatted_records_fixup_array_covers_every_sector() {
    let bytes = format(SIZE, 0, 1);
    let fix_num = u16::from_le_bytes([bytes[REC_OFF_FIX_NUM], bytes[REC_OFF_FIX_NUM + 1]]);
    // One entry for the value plus one per sector: a shorter array leaves the
    // last sector's tail unprotected.
    assert_eq!(fix_num, (SIZE >> SECTOR_SHIFT) as u16 + 1);
}

#[test]
fn attributes_begin_after_the_fixup_array() {
    let bytes = format(SIZE, 0, 1);
    let h = parse(&bytes).unwrap();
    let fix_off = u16::from_le_bytes([bytes[REC_OFF_FIX_OFF], bytes[REC_OFF_FIX_OFF + 1]]);
    let fix_num = u16::from_le_bytes([bytes[REC_OFF_FIX_NUM], bytes[REC_OFF_FIX_NUM + 1]]);
    assert!(h.attr_off >= fix_off + fix_num * 2, "attributes overlap the array");
    assert_eq!(h.attr_off % 8, 0);
}

#[test]
fn an_empty_record_has_no_attributes_and_ends_at_its_marker() {
    let bytes = format(SIZE, 0, 1);
    let h = parse(&bytes).unwrap();
    assert!(attribute_offsets(&bytes, &h).is_empty());
    let at = h.attr_off as usize;
    assert_eq!(&bytes[at..at + 4], &ATTR_END.to_le_bytes());
}

#[test]
fn a_record_that_is_not_a_file_record_is_refused() {
    let mut bytes = format(SIZE, 0, 1);
    bytes[REC_OFF_SIGN..REC_OFF_SIGN + 4].copy_from_slice(SIG_INDX.as_slice());
    assert_eq!(parse(&bytes), Err(RecordError::NotFile));
}

#[test]
fn a_record_a_check_marked_damaged_is_refused_as_such() {
    let mut bytes = format(SIZE, 0, 1);
    bytes[REC_OFF_SIGN..REC_OFF_SIGN + 4].copy_from_slice(SIG_BAAD.as_slice());
    assert_eq!(parse(&bytes), Err(RecordError::Bad));
}

#[test]
fn a_used_length_past_the_record_is_refused() {
    let mut bytes = format(SIZE, 0, 1);
    set_used(&mut bytes, SIZE + 8);
    assert_eq!(parse(&bytes), Err(RecordError::Corrupt));
}

#[test]
fn an_attribute_offset_past_the_record_is_refused() {
    let mut bytes = format(SIZE, 0, 1);
    bytes[MFT_OFF_ATTR_OFF..MFT_OFF_ATTR_OFF + 2].copy_from_slice(&(SIZE as u16).to_le_bytes());
    assert_eq!(parse(&bytes), Err(RecordError::Corrupt));
}

#[test]
fn a_reference_round_trips_through_both_directions() {
    let mut bytes = alloc::vec![0u8; 8];
    let r = Reference { number: 0x1_2345_6789, sequence: 0xABCD };
    write_reference(&mut bytes, 0, &r);
    assert_eq!(reference(&bytes, 0), r);
}

#[test]
fn the_sequence_advances_and_never_lands_on_zero() {
    // Zero is what a reference uses to mean "no reference at all".
    assert_eq!(next_sequence(1), 2);
    assert_eq!(next_sequence(0xFFFF), 1);
}

#[test]
fn a_walk_stops_at_an_attribute_whose_size_is_zero() {
    // A size of zero would otherwise loop forever.
    let mut bytes = format(SIZE, 0, 1);
    let h = parse(&bytes).unwrap();
    let at = h.attr_off as usize;
    bytes[at..at + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
    set_used(&mut bytes, SIZE);
    let h = parse(&bytes).unwrap();
    assert!(attribute_offsets(&bytes, &h).is_empty());
}

#[test]
fn a_walk_stops_at_an_attribute_reaching_past_the_used_length() {
    let mut bytes = format(SIZE, 0, 1);
    let h = parse(&bytes).unwrap();
    let at = h.attr_off as usize;
    bytes[at..at + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&(SIZE * 2).to_le_bytes());
    set_used(&mut bytes, SIZE);
    let h = parse(&bytes).unwrap();
    assert!(attribute_offsets(&bytes, &h).is_empty());
}

#[test]
fn the_flags_say_what_a_record_is() {
    let mut bytes = format(SIZE, 0, 1);
    set_flags(&mut bytes, RECORD_FLAG_IN_USE | RECORD_FLAG_DIR);
    let h = parse(&bytes).unwrap();
    assert!(h.in_use());
    assert!(h.is_dir());
    set_flags(&mut bytes, 0);
    assert!(!parse(&bytes).unwrap().in_use());
}
