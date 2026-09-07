//! Integral atom names and the buffer fit every atom-name answer applies.
use super::*;

fn name(atom: u16) -> Option<alloc::vec::Vec<u16>> {
    let mut out = [0u16; MAX_INTEGRAL_NAME];
    let units = integral_atom_name(atom, &mut out)?;
    Some(out[..units].to_vec())
}

fn text(units: &[u16]) -> alloc::string::String {
    units.iter().map(|unit| char::from_u32(*unit as u32).unwrap()).collect()
}

#[test]
fn an_integral_atom_is_named_by_its_decimal_value_behind_a_hash() {
    assert_eq!(name(1).as_deref().map(text), Some("#1".into()));
    assert_eq!(name(49152 - 1).as_deref().map(text), Some("#49151".into()));
    assert_eq!(name(u16::MAX).as_deref().map(text), Some("#65535".into()));
}

#[test]
fn the_longest_integral_name_fits_the_buffer_the_formatter_is_given() {
    assert_eq!(name(u16::MAX).map(|units| units.len()), Some(MAX_INTEGRAL_NAME));
}

#[test]
fn atom_zero_has_no_name() {
    assert_eq!(name(0), None);
}

#[test]
fn a_buffer_with_no_room_for_the_terminator_cannot_be_written() {
    assert_eq!(name_fit(4, 0), None);
    assert_eq!(name_fit(4, 1), Some(0));
}

#[test]
fn a_name_longer_than_the_buffer_is_truncated_to_leave_room_for_the_terminator() {
    assert_eq!(name_fit(10, 4), Some(3));
    assert_eq!(name_fit(2, 10), Some(2));
    assert_eq!(name_fit(9, 10), Some(9));
}

#[test]
fn the_integral_boundary_matches_the_first_string_atom() {
    assert_eq!(MAXINTATOM, 0xc000);
}
