//! Update-region ordinal decode: flag composition per entry.
use super::*;

#[test]
fn validating_a_rectangle_subtracts_it_from_the_windows_update_region() {
    assert_eq!(decode(VALIDATE_RECT, [7, 0x1000, 0]),
        Some(Request::Redraw { hwnd: 7, rect: 0x1000, region: 0, flags: RDW_VALIDATE }));
}

#[test]
fn validating_with_no_window_repaints_the_whole_desktop_instead() {
    assert_eq!(decode(VALIDATE_RECT, [0, 0x1000, 0]),
        Some(Request::Redraw { hwnd: 0, rect: 0, region: 0, flags: DESKTOP_VALIDATE_FLAGS }));
}

#[test]
fn the_region_entries_refuse_an_absent_window() {
    assert_eq!(decode(VALIDATE_RGN, [0, 0x1000, 0]), Some(Request::NoWindow));
    assert_eq!(decode(INVALIDATE_RGN, [0, 0x1000, 1]), Some(Request::NoWindow));
}

#[test]
fn validating_a_region_carries_the_region_and_no_rectangle() {
    assert_eq!(decode(VALIDATE_RGN, [7, 0x2000, 0]),
        Some(Request::Redraw { hwnd: 7, rect: 0, region: 0x2000, flags: RDW_VALIDATE }));
}

#[test]
fn invalidating_a_region_adds_the_erase_flag_only_when_asked() {
    assert_eq!(decode(INVALIDATE_RGN, [7, 0x2000, 0]),
        Some(Request::Redraw { hwnd: 7, rect: 0, region: 0x2000, flags: RDW_INVALIDATE }));
    assert_eq!(decode(INVALIDATE_RGN, [7, 0x2000, 1]),
        Some(Request::Redraw { hwnd: 7, rect: 0, region: 0x2000, flags: RDW_INVALIDATE | RDW_ERASE }));
}

#[test]
fn the_update_queries_carry_their_output_and_erase_request() {
    assert_eq!(decode(GET_UPDATE_RECT, [7, 0x3000, 1]), Some(Request::ReadUpdateRect { hwnd: 7, rect: 0x3000, erase: true }));
    assert_eq!(decode(GET_UPDATE_RGN, [7, 0x4000, 0]), Some(Request::ReadUpdateRgn { hwnd: 7, region: 0x4000, erase: false }));
    assert_eq!(decode(EXCLUDE_UPDATE_RGN, [0x9, 7, 0]), Some(Request::ExcludeUpdate { dc: 0x9, hwnd: 7 }));
}

#[test]
fn an_unrelated_ordinal_is_not_claimed() { assert_eq!(decode(0x1234, [0; 3]), None); }
