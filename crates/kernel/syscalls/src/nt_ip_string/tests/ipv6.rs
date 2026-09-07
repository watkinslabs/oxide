//! IPv6 address text contracts: group parsing, the single zero-run elision,
//! the embedded dotted quad, and the bracketed scope and port forms.

use super::ipv6::string_to_address;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

fn units(text: &str) -> alloc::vec::Vec<u16> { text.encode_utf16().collect() }
fn plain(text: &str) -> super::ipv6::Parsed { string_to_address(&units(text), false, true) }
fn extended(text: &str) -> super::ipv6::Parsed { string_to_address(&units(text), true, false) }

fn bytes(groups: [u16; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, group) in groups.iter().enumerate() { out[index * 2..index * 2 + 2].copy_from_slice(&group.to_be_bytes()); }
    out
}

#[test]
fn eight_groups_map_group_for_group() {
    let parsed = plain("1:2:3:4:5:6:7:8");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.bytes, bytes([1, 2, 3, 4, 5, 6, 7, 8]));
}

#[test]
fn the_zero_run_elision_fills_the_gap() {
    assert_eq!(plain("1::8").bytes, bytes([1, 0, 0, 0, 0, 0, 0, 8]));
    assert_eq!(plain("::1").bytes, bytes([0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(plain("1::").bytes, bytes([1, 0, 0, 0, 0, 0, 0, 0]));
    assert_eq!(plain("::").bytes, bytes([0; 8]));
    assert_eq!(plain("1:2::7:8").bytes, bytes([1, 2, 0, 0, 0, 0, 7, 8]));
}

#[test]
fn a_second_elision_stops_the_scan_rather_than_failing() {
    // The plain form reports where it stopped and keeps what it parsed; the
    // extended form has no terminator, so the trailing text is a failure.
    let parsed = plain("1::2::3");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.bytes, bytes([1, 0, 0, 0, 0, 0, 0, 2]));
    assert_eq!(parsed.terminator, 4);
    assert_eq!(extended("1::2::3").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn a_lone_leading_colon_and_a_short_group_list_fail() {
    assert_eq!(plain(":1:2:3:4:5:6:7").status, STATUS_INVALID_PARAMETER);
    assert_eq!(plain(":1:2:3:4:5:6:7").terminator, 0);
    assert_eq!(plain("1:2:3:4:5:6:7").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn an_embedded_dotted_quad_lands_in_the_low_bytes() {
    assert_eq!(plain("::1.2.3.4").bytes, bytes([0, 0, 0, 0, 0, 0, 0x0102, 0x0304]));
    assert_eq!(plain("::ffff:1.2.3.4").bytes, bytes([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]));
    assert_eq!(plain("1:2:3:4:5:6:7.8.9.10").bytes, bytes([1, 2, 3, 4, 5, 6, 0x0708, 0x090a]));
    let overflowed = plain("::1.2.3.256");
    assert_eq!(overflowed.status, STATUS_INVALID_PARAMETER);
    assert_eq!(overflowed.bytes, bytes([0x0102, 0x0300, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn the_extended_form_takes_a_bracketed_port_and_a_scope() {
    let parsed = extended("[::1]:80");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.bytes, bytes([0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(parsed.port, 80u16.swap_bytes());
    let scoped = extended("::1%7");
    assert_eq!(scoped.status, STATUS_SUCCESS);
    assert_eq!(scoped.scope, 7);
    assert_eq!(extended("[::1]:0").status, STATUS_INVALID_PARAMETER);
    assert_eq!(extended("[::1").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn the_plain_form_refuses_the_bracketed_and_scoped_text() {
    assert_eq!(plain("[::1]:80").status, STATUS_INVALID_PARAMETER);
    let scoped = plain("::1%7");
    assert_eq!(scoped.status, STATUS_SUCCESS);
    assert_eq!(scoped.terminator, 3);
    assert_eq!(scoped.scope, 0);
}

#[test]
fn the_terminator_reports_where_the_scan_stopped() {
    let parsed = plain("::1 rest");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.terminator, 3);
    assert!(parsed.has_terminator);
    assert_eq!(extended("::1 rest").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn a_group_past_four_digits_is_rejected_without_a_terminator() {
    let parsed = plain("11111:2:3:4:5:6:7:8");
    assert_eq!(parsed.status, STATUS_INVALID_PARAMETER);
    assert!(!parsed.has_terminator);
    assert_eq!(plain("ffff:2:3:4:5:6:7:8").status, STATUS_SUCCESS);
}

#[test]
fn the_prefixed_trailing_group_stops_at_its_prefix_letter() {
    let parsed = plain("::0x1234");
    assert_eq!(parsed.status, STATUS_SUCCESS);
    assert_eq!(parsed.terminator, 3);
    assert_eq!(extended("::0x1234").status, STATUS_INVALID_PARAMETER);
}

#[test]
fn an_elision_at_the_last_group_boundary_stops_the_scan() {
    // Fourteen bytes already parsed leaves the elision nothing to fill, so
    // the group after it is never read.
    assert_eq!(plain("1:2:3:4:5:6:7::8").bytes, bytes([1, 2, 3, 4, 5, 6, 7, 0]));
    assert_eq!(plain("1:2:3:4:5:6::8").bytes, bytes([1, 2, 3, 4, 5, 6, 0, 8]));
    assert_eq!(plain("1:2:3:4:5::7:8").bytes, bytes([1, 2, 3, 4, 5, 0, 7, 8]));
    assert_eq!(plain("1:2:3:4:5:6:7::").bytes, bytes([1, 2, 3, 4, 5, 6, 7, 0]));
}

#[test]
fn an_embedded_quad_after_an_elision_takes_only_what_fits() {
    assert_eq!(plain("1:2:3:4:5::1.2.3.4").bytes, bytes([1, 2, 3, 4, 5, 0, 0x0102, 0x0304]));
    let crowded = plain("1:2:3:4:5:6::1.2.3.4");
    assert_eq!(crowded.status, STATUS_SUCCESS);
    assert_eq!(crowded.bytes, bytes([1, 2, 3, 4, 5, 6, 0, 1]));
    assert_eq!(crowded.terminator, 14);
}
