//! The field changes, against a real copy's bytes.
//!
//! Every case here is checked by RE-PARSING the copy rather than by reading
//! back the word that was written: the extension list's two sections share one
//! array and their boundary is a stored count, so a change that writes the
//! right bytes into the wrong slot passes any read-back of the field it set
//! and fails the moment the list is read as a list.

use alloc::vec;

use super::*;
use crate::sb::SuperBlock;
use crate::test_image;

/// A copy's bytes, as a formatter left them.
fn raw() -> RawSuper {
    let b = test_image::Builder::new();
    RawSuper::new(test_image::meta::super_bytes(&b), 0, false)
}

fn parsed(raw: &RawSuper) -> SuperBlock { raw.parse().expect("parses") }

/// The two sections of the extension list, as a reader sees them.
fn lists(raw: &RawSuper) -> (Vec<String>, Vec<String>) {
    let sb = parsed(raw);
    let cold = sb.extensions.clone();
    // The hot entries sit after the cold ones; the parsed view stops at the
    // cold count, so they are read out of the bytes directly.
    let mut hot = Vec::new();
    for i in 0..usize::from(sb.hot_ext_count) {
        let at = SB_EXTENSION_LIST + (sb.extension_count as usize + i) * EXTENSION_LEN;
        let e = &raw.bytes()[at..at + EXTENSION_LEN];
        let end = e.iter().position(|&c| c == 0).unwrap_or(EXTENSION_LEN);
        hot.push(String::from_utf8_lossy(&e[..end]).into_owned());
    }
    (cold, hot)
}

// ------------------------------------------------------------------- label

#[test]
fn a_shorter_label_does_not_leave_the_old_tail_behind() {
    let mut r = raw();
    set_volume_name(&mut r, "a-much-longer-label").expect("set");
    assert_eq!(parsed(&r).volume_name, "a-much-longer-label");
    set_volume_name(&mut r, "ox").expect("set");
    assert_eq!(parsed(&r).volume_name, "ox");
}

#[test]
fn a_label_longer_than_the_array_is_refused() {
    let mut r = raw();
    let long: String = core::iter::repeat('x').take(SB_VOLUME_NAME_UNITS + 1).collect();
    assert_eq!(set_volume_name(&mut r, &long), Err(Errno::Einval));
    assert_eq!(parsed(&r).volume_name, "oxide", "a refused label changes nothing");
}

#[test]
fn a_label_that_exactly_fills_the_array_is_accepted() {
    let mut r = raw();
    let full: String = core::iter::repeat('x').take(SB_VOLUME_NAME_UNITS).collect();
    set_volume_name(&mut r, &full).expect("set");
    assert_eq!(volume_name(&r).len(), SB_VOLUME_NAME_UNITS);
}

// --------------------------------------------------------- extension list

#[test]
fn a_cold_extension_is_appended_to_the_cold_section() {
    let mut r = raw();
    update_extension_list(&mut r, "iso", false, true).expect("add");
    assert_eq!(lists(&r), (vec!["jpg".into(), "mp4".into(), "iso".into()], vec![]));
    assert_eq!(parsed(&r).extension_count, 3);
}

#[test]
fn a_hot_extension_lands_after_the_cold_ones_and_does_not_join_them() {
    let mut r = raw();
    update_extension_list(&mut r, "db", true, true).expect("add");
    assert_eq!(lists(&r), (vec!["jpg".into(), "mp4".into()], vec!["db".into()]));
    assert_eq!(parsed(&r).extension_count, 2, "the cold count is not the total");
    assert_eq!(parsed(&r).hot_ext_count, 1);
}

#[test]
fn a_cold_extension_added_after_a_hot_one_moves_the_hot_section_up() {
    let mut r = raw();
    update_extension_list(&mut r, "db", true, true).expect("hot");
    update_extension_list(&mut r, "log", true, true).expect("hot");
    update_extension_list(&mut r, "iso", false, true).expect("cold");
    assert_eq!(lists(&r), (vec!["jpg".into(), "mp4".into(), "iso".into()],
                           vec!["db".into(), "log".into()]));
}

#[test]
fn removing_an_extension_closes_the_gap() {
    let mut r = raw();
    update_extension_list(&mut r, "db", true, true).expect("hot");
    update_extension_list(&mut r, "jpg", false, false).expect("remove");
    assert_eq!(lists(&r), (vec!["mp4".into()], vec!["db".into()]));
    assert_eq!(parsed(&r).extension_count, 1);
    assert_eq!(parsed(&r).hot_ext_count, 1);
}

#[test]
fn removing_the_only_hot_extension_empties_that_section() {
    let mut r = raw();
    update_extension_list(&mut r, "db", true, true).expect("hot");
    update_extension_list(&mut r, "db", true, false).expect("remove");
    assert_eq!(lists(&r), (vec!["jpg".into(), "mp4".into()], vec![]));
    assert_eq!(parsed(&r).hot_ext_count, 0);
}

#[test]
fn an_extension_already_in_the_other_section_is_refused() {
    let mut r = raw();
    assert_eq!(update_extension_list(&mut r, "jpg", true, true), Err(Errno::Einval));
    assert_eq!(lists(&r).1, Vec::<String>::new());
}

#[test]
fn an_extension_already_in_its_own_section_is_refused() {
    let mut r = raw();
    assert_eq!(update_extension_list(&mut r, "jpg", false, true), Err(Errno::Einval));
    assert_eq!(parsed(&r).extension_count, 2);
}

#[test]
fn removing_one_that_is_not_there_is_refused() {
    let mut r = raw();
    assert_eq!(update_extension_list(&mut r, "iso", false, false), Err(Errno::Einval));
}

#[test]
fn removing_from_an_empty_section_is_refused() {
    let mut r = raw();
    assert_eq!(update_extension_list(&mut r, "db", true, false), Err(Errno::Einval));
}

#[test]
fn a_full_list_takes_no_more() {
    let mut r = raw();
    let mut added = 2;
    while added < MAX_EXTENSION as usize {
        let name = alloc::format!("e{added}");
        update_extension_list(&mut r, &name, false, true).expect("add");
        added += 1;
    }
    assert_eq!(update_extension_list(&mut r, "last", false, true), Err(Errno::Einval));
    assert_eq!(update_extension_list(&mut r, "last", true, true), Err(Errno::Einval));
}

#[test]
fn a_name_the_slot_cannot_hold_is_refused() {
    let mut r = raw();
    assert_eq!(update_extension_list(&mut r, "", false, true), Err(Errno::Einval));
    assert_eq!(update_extension_list(&mut r, "12345678", false, true), Err(Errno::Einval));
    update_extension_list(&mut r, "1234567", false, true).expect("seven fits");
}

// ---------------------------------------------------------------- resize

#[test]
fn growing_by_a_section_moves_every_count_that_measures_the_volume() {
    let mut r = raw();
    let was = parsed(&r);
    resize(&mut r, 1).expect("grow");
    let now = parsed(&r);
    let per_sec = was.segs_per_sec;
    assert_eq!(now.section_count, was.section_count + 1);
    assert_eq!(now.segment_count, was.segment_count + per_sec);
    assert_eq!(now.segment_count_main, was.segment_count_main + per_sec);
    assert_eq!(now.block_count, was.block_count + u64::from(per_sec << was.log_blocks_per_seg));
}

#[test]
fn shrinking_is_the_same_change_the_other_way() {
    let mut r = raw();
    let was = parsed(&r);
    resize(&mut r, 1).expect("grow");
    resize(&mut r, -1).expect("shrink");
    assert_eq!(parsed(&r), was);
}

#[test]
fn a_shrink_past_the_start_is_refused_rather_than_wrapped() {
    let mut r = raw();
    let was = parsed(&r);
    assert_eq!(resize(&mut r, -1_000_000), Err(Errno::Einval));
    assert_eq!(parsed(&r), was, "a refused resize changes nothing");
}

// -------------------------------------------------------------- alignment

#[test]
fn a_main_area_short_of_the_volumes_end_corrects_the_segment_count() {
    let b = test_image::Builder::new();
    let mut bytes = test_image::meta::super_bytes(&b);
    // Two segments the areas do not account for, which is what a formatter
    // that rounded the main area down leaves behind.
    put32(&mut bytes, SB_SEGMENT_COUNT, test_image::SEGMENT_COUNT + 2);
    let crc = crate::checksum::crc32(&bytes[..SB_CRC]);
    put32(&mut bytes, SB_CRC, crc);
    let mut r = RawSuper::new(bytes, 0, false);
    realign(&mut r);
    assert!(r.realigned());
    assert_eq!(parsed(&r).segment_count, test_image::SEGMENT_COUNT);
}

#[test]
fn a_volume_whose_areas_add_up_is_left_alone() {
    let mut r = raw();
    let was = parsed(&r);
    realign(&mut r);
    assert!(!r.realigned());
    assert_eq!(parsed(&r), was);
}

// --------------------------------------------------------------- pw salt

#[test]
fn the_first_salt_written_is_the_one_that_stays() {
    let mut r = raw();
    assert_eq!(pw_salt(&r), [0u8; PW_SALT_LEN]);
    assert!(set_pw_salt(&mut r, &[7u8; PW_SALT_LEN]));
    assert!(!set_pw_salt(&mut r, &[9u8; PW_SALT_LEN]), "a second caller does not restart keys");
    assert_eq!(pw_salt(&r), [7u8; PW_SALT_LEN]);
}
