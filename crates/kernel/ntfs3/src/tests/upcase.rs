use super::*;
use core::cmp::Ordering;

fn units(s: &str) -> alloc::vec::Vec<u16> { s.encode_utf16().collect() }

#[test]
fn ascii_folds_by_arithmetic_before_the_table_is_consulted() {
    // A volume whose table disagrees about ASCII would otherwise sort its own
    // directories in an order Windows does not.
    let mut raw = pack(&builtin());
    raw[(b'a' as usize) * 2] = b'q';
    let t = load(&raw);
    assert_eq!(t.fold(b'a' as u16), b'A' as u16);
}

#[test]
fn the_volumes_table_decides_everything_above_ascii() {
    let mut raw = pack(&builtin());
    // Fold 0x00E9 to 0x1234 instead of 0x00C9.
    raw[0x00E9 * 2] = 0x34;
    raw[0x00E9 * 2 + 1] = 0x12;
    let t = load(&raw);
    assert_eq!(t.fold(0x00E9), 0x1234);
}

#[test]
fn a_table_shorter_than_the_range_folds_the_rest_by_the_builtin_rules() {
    let t = load(&[]);
    assert_eq!(t.fold(b'a' as u16), b'A' as u16);
    assert_eq!(t.fold(0x00E9), 0x00C9);
}

#[test]
fn the_builtin_table_folds_the_blocks_it_names() {
    let t = builtin();
    assert_eq!(t.fold(b'z' as u16), b'Z' as u16);
    assert_eq!(t.fold(0x00F8), 0x00D8);
    assert_eq!(t.fold(0x00F7), 0x00F7);
    assert_eq!(t.fold(0x0101), 0x0100);
    assert_eq!(t.fold(0x03B1), 0x0391);
    assert_eq!(t.fold(0x0430), 0x0410);
    assert_eq!(t.fold(0x00FF), 0x0178);
}

#[test]
fn two_names_differing_only_in_case_are_the_same_name() {
    let t = builtin();
    assert!(eq(&units("Readme.TXT"), &units("readme.txt"), &t));
    assert!(!eq(&units("readme.txt"), &units("readme.tx"), &t));
}

#[test]
fn comparison_orders_by_the_fold_not_by_the_raw_units() {
    // Raw, 'B' (0x42) sorts before 'a' (0x61); folded, 'a' sorts first.
    let t = builtin();
    assert_eq!(compare(&units("apple"), &units("Banana"), &t, false), Ordering::Less);
    assert_eq!(compare(&units("Banana"), &units("apple"), &t, false), Ordering::Greater);
}

#[test]
fn a_shorter_name_sorts_before_a_longer_one_that_starts_with_it() {
    let t = builtin();
    assert_eq!(compare(&units("file"), &units("file2"), &t, false), Ordering::Less);
}

#[test]
fn the_both_cases_rule_breaks_a_fold_tie_by_the_exact_bytes() {
    // Two names the fold cannot separate sort stably rather than arbitrarily,
    // and a tree built under that rule is not searchable under any other.
    let t = builtin();
    assert_eq!(compare(&units("File"), &units("file"), &t, true), Ordering::Less);
    assert_eq!(compare(&units("file"), &units("File"), &t, true), Ordering::Greater);
    assert_eq!(compare(&units("file"), &units("file"), &t, true), Ordering::Equal);
    // Without it the two are equal.
    assert_eq!(compare(&units("File"), &units("file"), &t, false), Ordering::Equal);
}

#[test]
fn a_table_round_trips_through_both_directions() {
    let packed = pack(&builtin());
    assert_eq!(packed.len(), UPCASE_UNITS * 2);
    assert_eq!(load(&packed).raw(), builtin().raw());
}

#[test]
fn a_name_of_nothing_or_past_the_ceiling_does_not_fit() {
    assert!(!name_fits(&[]));
    assert!(name_fits(&alloc::vec![b'x' as u16; 255]));
    assert!(!name_fits(&alloc::vec![b'x' as u16; 256]));
}
