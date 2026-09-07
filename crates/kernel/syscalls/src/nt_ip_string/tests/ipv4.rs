//! IPv4 address text contracts: the shorthand forms, the strict rejections,
//! the overflow ceiling, the port suffix, and where the scan stops.

use super::ipv4::{string_to_address, Parsed};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

fn units(text: &str) -> alloc::vec::Vec<u16> { text.encode_utf16().collect() }
fn plain(text: &str) -> Parsed { string_to_address(&units(text), false, true, false) }
fn strict(text: &str) -> Parsed { string_to_address(&units(text), true, true, false) }
fn extended(text: &str) -> Parsed { string_to_address(&units(text), false, false, true) }

#[test]
fn a_dotted_quad_maps_octet_for_octet() {
    let parsed = plain("1.2.3.4");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.bytes, [1, 2, 3, 4]);
    assert_eq!(parsed.terminator, 7);
}

#[test]
fn the_short_forms_pack_the_trailing_value() {
    assert_eq!(plain("1.2.3").bytes, [1, 2, 0, 3]);
    assert_eq!(plain("1.2").bytes, [1, 0, 0, 2]);
    assert_eq!(plain("16909060").bytes, [1, 2, 3, 4]);
    assert_eq!(plain("1.2.771").bytes, [1, 2, 3, 3]);
    assert_eq!(plain("1.66051").bytes, [1, 1, 2, 3]);
}

#[test]
fn the_strict_form_demands_four_decimal_components() {
    assert_eq!(strict("1.2.3.4").status, STATUS_SUCCESS);
    assert_eq!(strict("1.2.3").status, STATUS_INVALID_PARAMETER);
    assert_eq!(strict("0x1.2.3.4").status, STATUS_INVALID_PARAMETER);
    assert_eq!(strict("010.2.3.4").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("0x1.0x2.0x3.0x4").bytes, [1, 2, 3, 4]);
    assert_eq!(plain("010.2.3.4").bytes, [8, 2, 3, 4]);
}

#[test]
fn an_octet_past_its_ceiling_is_rejected() {
    assert_eq!(plain("1.2.3.256").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("1.2.65536").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("1.16777216").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("4294967295").bytes, [255, 255, 255, 255]);
}

#[test]
fn five_components_and_an_empty_one_fail() {
    assert_eq!(plain("1.2.3.4.5").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain(".1.2.3").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("1..2.3").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn a_component_that_overflows_thirty_two_bits_fails() {
    assert_eq!(plain("4294967296").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain("0x100000000").status, STATUS_INVALID_PARAMETER);
    // Saturating at the ceiling is not a decrease, so the scan keeps going.
    assert_eq!(plain("0xffffffffff").bytes, [255, 255, 255, 255]);
}

#[test]
fn the_terminator_reports_where_the_scan_stopped() {
    assert_eq!(plain("1.2.3.4rest").terminator, 7);
    assert_eq!(plain("1.2.3.4rest").status, STATUS_SUCCESS);
    assert_eq!(plain("1.2.3.4:80").terminator, 7);
    let ex = extended("1.2.3.4:80");
    assert_eq!(ex.status, STATUS_SUCCESS);
    assert!(ex.has_port);
    assert_eq!(ex.port, 80u16.swap_bytes());
}

#[test]
fn trailing_text_fails_when_no_terminator_is_wanted() {
    assert_eq!(extended("1.2.3.4rest").status, STATUS_INVALID_PARAMETER);
    assert_eq!(extended("1.2.3.4").status, STATUS_SUCCESS);
    assert!(!extended("1.2.3.4").has_port);
}

#[test]
fn a_port_outside_its_range_fails_after_the_address_is_stored() {
    let parsed = extended("1.2.3.4:0");
    assert_eq!(parsed.status, STATUS_INVALID_PARAMETER);
    assert!(parsed.stored);
    assert_eq!(parsed.bytes, [1, 2, 3, 4]);
    assert_eq!(extended("1.2.3.4:65536").status, STATUS_INVALID_PARAMETER);
    assert_eq!(extended("1.2.3.4:80x").status, STATUS_INVALID_PARAMETER);
}
