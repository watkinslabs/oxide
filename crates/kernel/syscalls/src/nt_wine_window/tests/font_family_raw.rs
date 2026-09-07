use super as raw;
use std::vec;
use ipc::win32_gdi::{Font, GdiManager};
use syscall::nt_native_gdi as abi;

fn font() -> Font { Font { height: -19, width: 7, weight: 700, italic: true } }

fn query(ordinal: u64, args: &[u64], fetched: Option<u64>) -> abi::QueryRequest {
    match raw::decode(ordinal, args, fetched).unwrap().unwrap() {
        raw::Request::Query(request) => request,
        other => panic!("expected a native query, got {other:?}"),
    }
}

fn routed(ordinal: u64, args: &[u64], fetched: Option<u64>) -> Option<abi::QueryRequest> {
    let mut seen = None;
    let result = raw::route(ordinal, args, |_| fetched, |_| Some(font()),
        |request| { seen = Some(request); 7 }, |_| panic!("immediate on a query ordinal"));
    assert_eq!(result, Some(seen.map(|_| 7).unwrap_or(abi::failure(query(ordinal, args, fetched).kind))));
    seen
}

#[test]
fn every_family_ordinal_is_admitted_with_its_windows_argument_count() {
    let expected = [(0x1087u64, 5usize), (0x1088, 6), (0x11be, 8), (0x11d6, 1), (0x11e8, 2), (0x11e9, 6),
        (0x11ff, 5), (0x1200, 5), (0x1202, 2), (0x1206, 8), (0x1207, 3), (0x121b, 2), (0x121c, 2),
        (0x1228, 4), (0x123b, 5), (0x125a, 1), (0x125b, 6), (0x128a, 3)];
    for (ordinal, count) in expected { assert_eq!(raw::argument_count(ordinal), Some(count), "{ordinal:#x}"); }
    assert_eq!(expected.len(), 18);
    for ordinal in [0x1086u64, 0x1089, 0x11bd, 0x1229, 0x128b, 0x4e54_0000_0000_1087] {
        assert_eq!(raw::argument_count(ordinal), None);
        assert!(raw::decode(ordinal, &[], None).is_none());
    }
}

#[test]
fn short_calls_stay_claimed_in_each_ordinal_failure_domain() {
    for (ordinal, failure) in [(raw::ADD_FONT_RESOURCE_W, 1), (raw::REMOVE_FONT_RESOURCE_W, 1),
        (raw::REMOVE_FONT_MEM_RESOURCE_EX, 1), (raw::ADD_FONT_MEM_RESOURCE_EX, 0),
        (raw::GET_GLYPH_OUTLINE, u32::MAX as u64), (raw::ENUM_FONTS, 0), (raw::GET_TEXT_FACE_W, 0)] {
        let count = raw::argument_count(ordinal).unwrap();
        for len in 0..count {
            assert_eq!(raw::decode(ordinal, &vec![1; len], Some(24)).unwrap().unwrap_err(), failure);
            assert_eq!(raw::route(ordinal, &vec![1; len], |_| Some(24), |_| Some(font()),
                |_| panic!("short callback"), |_| panic!("short immediate")), Some(failure));
        }
    }
}

#[test]
fn glyph_outline_places_every_windows_argument_and_refuses_a_missing_transform() {
    let request = query(raw::GET_GLYPH_OUTLINE, &[9, 0x1_0000 | 0x41, 6, 0x2000, 512, 0x3000, 0x4000, 1], None);
    assert_eq!((request.kind, request.dc, request.first, request.flags), (abi::QUERY_GLYPH_OUTLINE, 9, 0x41, 6));
    assert_eq!((request.aux, request.capacity, request.output, request.input), (0x2000, 512, 0x3000, 0x4000));
    assert_eq!((request.count, request.aux_bytes), (abi::MAT2_WORDS, abi::GLYPH_METRICS_BYTES));
    // No transform is the reference's outright refusal, not a device-context error.
    assert_eq!(raw::decode(raw::GET_GLYPH_OUTLINE, &[9, 0x41, 6, 0x2000, 512, 0x3000, 0, 1], None).unwrap().unwrap_err(),
        u32::MAX as u64);
    let metricless = query(raw::GET_GLYPH_OUTLINE, &[9, 0x41, 0, 0, 0, 0, 0x4000, 0], None);
    assert_eq!((metricless.aux_bytes, metricless.capacity, metricless.output), (0, 0, 0));
}

#[test]
fn char_width_count_follows_indices_and_explicit_characters_like_the_reference() {
    let ranged = query(raw::GET_CHAR_WIDTH_W, &[1, 65, 67, 0, 2, 0x1000], None);
    assert_eq!((ranged.first, ranged.count, ranged.input), (65, 3, 0));
    let explicit = query(raw::GET_CHAR_WIDTH_W, &[1, 65, 4, 0x2000, 2, 0x1000], None);
    assert_eq!((explicit.count, explicit.input), (4, 0x2000));
    let indices = query(raw::GET_CHAR_WIDTH_W, &[1, 65, 4, 0, raw::CHAR_WIDTH_INDICES as u64, 0x1000], None);
    assert_eq!((indices.count, indices.flags), (4, raw::CHAR_WIDTH_INDICES));
    assert!(!query(raw::GET_CHAR_WIDTH_W, &[1, 5, 4, 0, 2, 0x1000], None).valid());
}

#[test]
fn enum_fonts_reads_the_caller_byte_count_and_caps_the_face_name() {
    let request = query(raw::ENUM_FONTS, &[1, 0, 0, 5, 0x2000, 3, 0x3000, 0x4000], Some(904));
    assert_eq!((request.count, request.input, request.first), (5, 0x2000, 3));
    assert_eq!((request.aux, request.aux_bytes, request.capacity, request.output), (0x3000, 4, 904, 0x4000));
    assert!(request.valid());
    // A byte count that is not a whole number of records admits only whole records.
    let partial = query(raw::ENUM_FONTS, &[1, 0, 0, 0, 0, 1, 0x3000, 0x4000], Some(903));
    assert_eq!((partial.capacity, abi::capacity_limit(&partial)), (903, Some(452)));
    assert_eq!(query(raw::ENUM_FONTS, &[1, 0, 0, 0, 0x2000, 1, 0x3000, 0], Some(0)).input, 0);
    assert!(!query(raw::ENUM_FONTS, &[1, 0, 0, 33, 0x2000, 1, 0x3000, 0], Some(0)).valid());
    assert_eq!(raw::route(raw::ENUM_FONTS, &[1, 0, 0, 0, 0, 1, 0x3000, 0], |_| None, |_| Some(font()),
        |_| panic!("unread count"), |_| panic!("immediate")), Some(0));
}

#[test]
fn deviceless_ordinals_never_snapshot_a_device_context() {
    for (ordinal, args, fetched) in [
        (raw::GET_FONT_FILE_DATA, vec![11, 0, 0x1000, 0x2000, 64], Some(8)),
        (raw::GET_FONT_FILE_INFO, vec![11, 0, 0x2000, 64, 0x3000], None),
        (raw::MAKE_FONT_DIR, vec![1, 0x2000, 251, 0x3000, 20], None),
        (raw::ADD_FONT_RESOURCE_W, vec![0x3000, 10, 1, 0, 0, 0], None),
        (raw::REMOVE_FONT_RESOURCE_W, vec![0x3000, 10, 1, 0, 0, 0], None),
        (raw::ADD_FONT_MEM_RESOURCE_EX, vec![0x9000, 4096, 0, 0, 0x3000], None),
        (raw::REMOVE_FONT_MEM_RESOURCE_EX, vec![0x1234], None)] {
        let request = query(ordinal, &args, fetched);
        assert_eq!(request.dc, 0, "{ordinal:#x}");
        assert!(request.valid(), "{ordinal:#x}");
        let mut seen = None;
        assert_eq!(raw::route(ordinal, &args, |_| fetched, |_| panic!("device snapshot on {ordinal:#x}"),
            |request| { seen = Some(request); 3 }, |_| panic!("immediate")), Some(3));
        assert_eq!(seen.unwrap().kind, request.kind);
    }
}

#[test]
fn file_and_resource_arguments_land_in_their_declared_fields() {
    let data = query(raw::GET_FONT_FILE_DATA, &[11, 2, 0x1000, 0x2000, 64], Some(0x8000_0000_0000_0004));
    assert_eq!((data.first, data.offset, data.value, data.output, data.capacity), (11, 2, 0x8000_0000_0000_0004, 0x2000, 64));
    let info = query(raw::GET_FONT_FILE_INFO, &[11, 2, 0x2000, 64, 0x3000], None);
    assert_eq!((info.first, info.offset, info.output, info.capacity, info.aux, info.aux_bytes), (11, 2, 0x2000, 64, 0x3000, 8));
    let dir = query(raw::MAKE_FONT_DIR, &[1, 0x2000, 400, 0x3000, 20], None);
    assert_eq!((dir.flags, dir.output, dir.capacity, dir.input, dir.count), (1, 0x2000, 400, 0x3000, 10));
    let add = query(raw::ADD_FONT_RESOURCE_W, &[0x3000, 10, 1, 0x10, 0, 0], None);
    assert_eq!((add.input, add.count, add.flags), (0x3000, 10, 0x10));
    let mem = query(raw::ADD_FONT_MEM_RESOURCE_EX, &[0x9000, 4096, 0, 0, 0x3000], None);
    assert_eq!((mem.value, mem.capacity, mem.aux, mem.aux_bytes), (0x9000, 4096, 0x3000, 4));
    assert_eq!(query(raw::REMOVE_FONT_MEM_RESOURCE_EX, &[0x1234], None).value, 0x1234);
}

#[test]
fn refused_shapes_return_the_ordinals_own_failure_and_never_reach_the_backend() {
    for (ordinal, args, fetched, failure) in [
        // A destination with no pair count is the caller's error, not a size query.
        (raw::GET_KERNING_PAIRS, vec![1, 0, 0x2000], None, 0u64),
        (raw::MAKE_FONT_DIR, vec![1, 0x2000, 250, 0x3000, 20], None, 0),
        (raw::MAKE_FONT_DIR, vec![1, 0x2000, 251, 0x3000, 2], None, 0),
        (raw::MAKE_FONT_DIR, vec![1, 0x2000, 251, 0x3000, 21], None, 0),
        (raw::ADD_FONT_MEM_RESOURCE_EX, vec![0, 4096, 0, 0, 0x3000], None, 0),
        (raw::ADD_FONT_MEM_RESOURCE_EX, vec![0x9000, 0, 0, 0, 0x3000], None, 0),
        (raw::ADD_FONT_MEM_RESOURCE_EX, vec![0x9000, 4096, 0, 0, 0], None, 0),
        (raw::ADD_FONT_RESOURCE_W, vec![0, 10, 1, 0, 0, 0], None, 1),
        (raw::REMOVE_FONT_RESOURCE_W, vec![0x3000, 0, 1, 0, 0, 0], None, 1),
        (raw::GET_REALIZATION_INFO, vec![1, 0x2000], Some(20), 0),
        (raw::GET_CHAR_WIDTH_INFO, vec![1, 0], None, 0),
    ] {
        assert_eq!(raw::route(ordinal, &args, |_| fetched, |_| Some(font()),
            |_| panic!("refused shape reached the backend: {ordinal:#x}"), |_| panic!("immediate")), Some(failure));
    }
}

#[test]
fn realization_admits_only_the_two_published_record_sizes() {
    for size in [16u64, 24] { assert!(query(raw::GET_REALIZATION_INFO, &[1, 0x2000], Some(size)).valid()); }
    for size in [0u64, 8, 20, 28] {
        assert_eq!(raw::route(raw::GET_REALIZATION_INFO, &[1, 0x2000], |_| Some(size), |_| Some(font()),
            |_| panic!("bad realization size reached the backend"), |_| panic!("immediate")), Some(0));
    }
}

#[test]
fn selected_font_metrics_reach_every_device_bound_query() {
    let request = routed(raw::GET_CHAR_WIDTH_INFO, &[3, 0x2000], None).unwrap();
    assert_eq!((request.height, request.width, request.weight, request.italic), (-19, 7, 700, 1));
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(80, 40).unwrap();
    let seen = raw::route(raw::GET_FONT_UNICODE_RANGES, &[dc as u64, 0x2000],
        |_| None, |handle| owner.text_state(handle as u32).ok()?.font,
        |request| { assert_eq!((request.height, request.weight), (16, 700)); 40 }, |_| panic!("immediate"));
    assert_eq!(seen, Some(40));
    assert_eq!(raw::route(raw::GET_FONT_UNICODE_RANGES, &[0xdead_beef, 0x2000], |_| None,
        |handle| owner.text_state(handle as u32).ok()?.font, |_| panic!("dead DC callback"), |_| panic!("immediate")), Some(0));
}

#[test]
fn immediate_ordinals_bypass_the_backend_entirely() {
    for (ordinal, args) in [(raw::FONT_IS_LINKED, vec![1u64]), (raw::GET_RASTERIZER_CAPS, vec![0x2000, 6]),
        (raw::SET_TEXT_JUSTIFICATION, vec![1, 12, 3])] {
        let mut seen = None;
        assert_eq!(raw::route(ordinal, &args, |_| None, |_| panic!("snapshot"),
            |_| panic!("backend"), |request| { seen = Some(matches!(request, raw::Request::Query(_))); 5 }), Some(5));
        assert_eq!(seen, Some(false), "{ordinal:#x}");
    }
    assert!(matches!(raw::decode(raw::FONT_IS_LINKED, &[1], None).unwrap().unwrap(), raw::Request::FontIsLinked));
    assert!(matches!(raw::decode(raw::GET_RASTERIZER_CAPS, &[0x2000, 6], None).unwrap().unwrap(),
        raw::Request::RasterizerCaps { status: 0x2000 }));
    assert!(matches!(raw::decode(raw::SET_TEXT_JUSTIFICATION, &[1, u64::MAX, 3], None).unwrap().unwrap(),
        raw::Request::Justify { dc: 1, extra: -1, breaks: 3 }));
}

#[test]
fn rasterizer_status_reports_the_backend_that_actually_answers() {
    assert_eq!(raw::rasterizer_status(true), [6, 0, 3, 0, 0, 0]);
    assert_eq!(raw::rasterizer_status(false), [6, 0, 0, 0, 0, 0]);
    assert_eq!(raw::RASTERIZER_STATUS_BYTES, 6);
}

#[test]
fn justification_splits_the_magnitude_and_a_zero_amount_cancels_the_break_count() {
    assert_eq!(raw::justification(10, 3, 1, 1), Some((3, 1)));
    assert_eq!(raw::justification(-10, 3, 1, 1), Some((3, 1)));
    assert_eq!(raw::justification(9, 3, 1, 1), Some((3, 0)));
    assert_eq!(raw::justification(0, 3, 1, 1), Some((0, 0)));
    assert_eq!(raw::justification(10, 0, 1, 1), Some((0, 0)));
    // Extents scale the amount before the split, with the reference's rounding.
    assert_eq!(raw::justification(10, 1, 3, 2), Some((15, 0)));
    assert_eq!(raw::justification(1, 1, 0, 1), Some((0, 0)));
    assert_eq!(raw::justification(1, 1, 1, 0), None);
    // The reference computes the magnitude in the device unit type; a magnitude
    // that no longer fits that type has no split to store.
    assert_eq!(raw::justification(i32::MIN, 1, 1, 1), None);
}
