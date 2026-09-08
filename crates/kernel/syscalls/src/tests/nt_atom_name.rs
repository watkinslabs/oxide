//! The two rules an atom name obeys: when it is an integer, and when two
//! names are the same name.

use super::*;

fn units(text: &str) -> alloc::vec::Vec<u16> { text.encode_utf16().collect() }
fn bytes(text: &str) -> alloc::vec::Vec<u8> {
    units(text).iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

#[test]
fn a_name_argument_that_fits_in_sixteen_bits_is_the_atom_itself() {
    assert_eq!(classify_pointer(0x1234, 0), Ok(Name::Integer(0x1234)));
    assert_eq!(classify_pointer(1, 0), Ok(Name::Integer(1)));
}

#[test]
fn an_integer_name_outside_the_integer_range_is_refused() {
    assert!(classify_pointer(0, 0).is_err());
    assert!(classify_pointer(FIRST_STRING_ATOM as u64, 0).is_err());
    assert!(classify_pointer(0xffff, 0).is_err());
}

#[test]
fn a_string_pointer_is_a_table_name_and_carries_its_length_rules() {
    assert_eq!(classify_pointer(0x7fff_0000_1000, 10), Ok(Name::Table));
    // An empty name is not a name; an over-long or odd one is a bad argument.
    assert_eq!(classify_pointer(0x7fff_0000_1000, 0), Err(0xc000_0033));
    assert_eq!(classify_pointer(0x7fff_0000_1000, MAX_ATOM_CHARS * 2 + 2), Err(0xc000_000d));
    assert_eq!(classify_pointer(0x7fff_0000_1000, 9), Err(0xc000_000d));
    assert_eq!(classify_pointer(0x7fff_0000_1000, MAX_ATOM_CHARS * 2), Ok(Name::Table));
}

#[test]
fn a_hash_and_digits_name_the_integer_atom_they_spell() {
    assert_eq!(classify_text(&units("#1234")), Ok(Name::Integer(1234)));
    assert_eq!(classify_text(&units("#1")), Ok(Name::Integer(1)));
}

#[test]
fn a_hash_that_is_not_all_digits_is_an_ordinary_table_name() {
    assert_eq!(classify_text(&units("#12a4")), Ok(Name::Table));
    assert_eq!(classify_text(&units("#")), Ok(Name::Table));
    assert_eq!(classify_text(&units("Edit")), Ok(Name::Table));
}

#[test]
fn a_spelled_integer_outside_the_integer_range_is_refused() {
    assert_eq!(classify_text(&units("#0")), Err(0xc000_000d));
    assert_eq!(classify_text(&units("#49152")), Err(0xc000_000d));
    assert_eq!(classify_text(&units("#99999999999")), Err(0xc000_000d));
}

#[test]
fn atom_names_match_without_regard_to_case() {
    assert!(same_name(&bytes("Edit"), &bytes("EDIT")));
    assert!(same_name(&bytes("#32770"), &bytes("#32770")));
    assert!(!same_name(&bytes("Edit"), &bytes("Editor")));
    assert!(!same_name(&bytes("Edit"), &bytes("Exit")));
}
