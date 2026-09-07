use super::*;

#[test]
fn the_admitted_ordinal_table_is_sorted_so_lookup_is_exact() {
    for pair in COUNTS.windows(2) { assert!(pair[0].0 < pair[1].0, "{:#x} then {:#x}", pair[0].0, pair[1].0); }
}

#[test]
fn every_ordinal_reports_its_windows_parameter_count() {
    for (ordinal, count) in [(BEGIN_PATH, 1), (GET_PATH, 4), (SELECT_CLIP_PATH, 2), (CREATE_ROUND_RECT_RGN, 6),
        (EXCLUDE_CLIP_RECT, 5), (FRAME_RGN, 5), (EXT_CREATE_REGION, 3), (RECT_IN_REGION, 2), (SET_META_RGN, 1)] {
        assert_eq!(argument_count(ordinal), Some(count), "{ordinal:#x}");
    }
}

#[test]
fn an_unadmitted_ordinal_has_no_parameter_count() {
    assert_eq!(argument_count(0x1000), None);
    assert_eq!(argument_count(WIDEN_PATH + 1), None);
}

#[test]
fn the_family_admits_exactly_the_ordinals_it_owns() {
    assert_eq!(COUNTS.len(), 29);
}
