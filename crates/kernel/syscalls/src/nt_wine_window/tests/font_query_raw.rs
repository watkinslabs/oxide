use super as raw;
use std::vec;
use ipc::win32_gdi::{Font, GdiManager};
use syscall::nt_native_gdi as abi;

fn decode(ordinal: u64, args: &[u64]) -> abi::QueryRequest { raw::decode(ordinal, args).unwrap().unwrap() }
fn snapshot() -> Font { Font { height: -19, width: 7, weight: 700, italic: true } }

#[test]
fn exact_ordinals_signatures_and_short_calls_stay_claimed() {
    for (ordinal, count, failure) in [(0x1225, 3, 1), (0x11fe, 5, u32::MAX as u64),
        (0x1204, 5, u32::MAX as u64), (0x11e6, 6, 0), (0x1211, 4, 0)] {
        assert_eq!(raw::argument_count(ordinal), Some(count));
        for len in 0..count { assert_eq!(raw::decode(ordinal, &vec![1; len]).unwrap().unwrap_err(), failure); }
    }
    for ordinal in [0x1205, 0x1227, 0x11c9, 0x4e54_0000_0000_1225] {
        assert_eq!(raw::argument_count(ordinal), None);
        assert!(raw::decode(ordinal, &[]).is_none());
        assert_eq!(raw::route(ordinal, &[], |_| panic!("unclaimed snapshot"), |_| panic!("unclaimed callback")), None);
    }
}

#[test]
fn all_raw_argument_positions_preserve_pointers_and_truncate_only_scalars() {
    let high = 0xaabb_ccdd_0000_0000;
    let dc = 0x10000_0040;
    let output = 0x20000_0040;
    let input = 0x30000_0040;
    let req = decode(raw::GET_TEXT_CHARSET, &[dc, output, high | 9]);
    assert_eq!((req.dc, req.output, req.flags, req.kind), (dc, output, 9, abi::QUERY_CHARSET));
    let req = decode(raw::GET_FONT_DATA, &[dc, high | 0x64616568, high | 12, output, high | 4]);
    assert_eq!((req.dc, req.table, req.offset, req.output, req.capacity), (dc, 0x64616568, 12, output, 4));
    let req = decode(raw::GET_GLYPH_INDICES, &[dc, input, high | 3, output, high | 1]);
    assert_eq!((req.dc, req.input, req.count, req.output, req.flags), (dc, input, 3, output, 1));
    let req = decode(raw::GET_CHAR_ABC_WIDTHS, &[dc, high | 65, high | 3, input, high | 3, output]);
    assert_eq!((req.dc, req.first, req.count, req.input, req.flags, req.output), (dc, 65, 3, input, 3, output));
    let req = decode(raw::GET_OUTLINE_METRICS, &[dc, high | 232, output, high | 7]);
    assert_eq!((req.dc, req.capacity, req.output, req.flags), (dc, 232, output, 7));
    assert_eq!((req.version, req.size, req.reserved), (abi::VERSION, 80, 0));
}

#[test]
fn abc_count_depends_on_indices_bit_or_explicit_input_not_integer_bit() {
    for flags in [0, abi::ABC_INTEGER, 0x80000001] {
        let range = decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 65, 67, 0, flags as u64, 0x10000]);
        assert_eq!((range.first, range.count, range.input), (65, 3, 0));
        let explicit = decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 65000, 3, 0x20000, flags as u64, 0x10000]);
        assert_eq!((explicit.first, explicit.count, explicit.input), (65000, 3, 0x20000));
    }
    for flags in [abi::ABC_INDICES, abi::ABC_INDICES | abi::ABC_INTEGER] {
        let req = decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 65, 3, 0, flags as u64, 0x10000]);
        assert_eq!((req.first, req.count), (65, 3));
    }
    assert_eq!(decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 1, 0, 0, 1, 0x10000]).count, 0);
    assert_eq!(decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 0, u32::MAX as u64, 0, 1, 0x10000]).count, 0);
    assert_eq!(raw::decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 65, 63, 0, 1, 0x10000]).unwrap().unwrap_err(), 0);
    assert_eq!(raw::decode(raw::GET_CHAR_ABC_WIDTHS, &[1, 0, 0, 1, 1, 0]).unwrap().unwrap_err(), 0);
}

#[test]
fn null_queries_ignore_capacity_but_not_identity_or_font_selection() {
    for (ordinal, args) in [(raw::GET_FONT_DATA, vec![1, 0, u32::MAX as u64, 0, u64::MAX]),
        (raw::GET_OUTLINE_METRICS, vec![1, u64::MAX, 0, u64::MAX])] {
        let req = decode(ordinal, &args);
        assert_eq!(req.capacity, 0); assert_eq!(req.output, 0);
        assert_eq!(raw::route(ordinal, &args, |_| Some(snapshot()), |req| { assert!(req.valid()); 232 }), Some(232));
    }
    let req = decode(raw::GET_TEXT_CHARSET, &[1, 0, u64::MAX]);
    assert_eq!(req.flags, u32::MAX);
}

#[test]
fn canonical_selected_font_and_pending_deletion_cross_the_actual_route() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(80, 40).unwrap();
    let args = [dc as u64, 0, 0];
    let returned = raw::route(raw::GET_TEXT_CHARSET, &args,
        |handle| owner.text_state(handle as u32).ok()?.font,
        |req| { assert_eq!((req.height, req.width, req.weight, req.italic), (16, 7, 700, 0)); 0 });
    assert_eq!(returned, Some(0));
    let handle = owner.create_font(snapshot()).unwrap();
    let old = owner.select_font(dc, handle).unwrap();
    owner.delete_font(handle).unwrap();
    let returned = raw::route(raw::GET_OUTLINE_METRICS, &[dc as u64, 0, 0, 0],
        |handle| owner.text_state(handle as u32).ok()?.font,
        |req| { assert_eq!((req.height, req.width, req.weight, req.italic), (-19, 7, 700, 1)); 4096 });
    assert_eq!(returned, Some(4096));
    owner.select_font(dc, old).unwrap();
    assert!(owner.font_record(handle).is_err());
    owner.delete_object(dc).unwrap();
    assert_eq!(raw::route(raw::GET_TEXT_CHARSET, &args,
        |handle| owner.text_state(handle as u32).ok()?.font, |_| panic!("deleted DC callback")), Some(1));
}

#[test]
fn invalid_bounds_never_snapshot_or_enter_and_owner_failure_keeps_api_domain() {
    for (ordinal, args, failure) in [
        (raw::GET_GLYPH_INDICES, vec![1, 1, 0xffff_ffff, 2, 0], u32::MAX as u64),
        (raw::GET_GLYPH_INDICES, vec![1, 1, abi::MAX_UNITS as u64 + 1, 2, 0], u32::MAX as u64),
        (raw::GET_GLYPH_INDICES, vec![1, u64::MAX, 1, 2, 0], u32::MAX as u64),
        (raw::GET_FONT_DATA, vec![1, 0, 0, 2, abi::MAX_QUERY_BYTES as u64 + 1], u32::MAX as u64),
        (raw::GET_TEXT_CHARSET, vec![1, u64::MAX, 0], 1),
        (raw::GET_CHAR_ABC_WIDTHS, vec![1, 65535, 2, 0, 2, 2], 0),
        (raw::GET_OUTLINE_METRICS, vec![1, 232, u64::MAX, 0], 0),
    ] {
        assert_eq!(raw::route(ordinal, &args, |_| panic!("invalid snapshot"), |_| panic!("invalid callback")), Some(failure));
    }
    for (ordinal, args, failure) in [(raw::GET_TEXT_CHARSET, vec![1, 0, 0], 1),
        (raw::GET_FONT_DATA, vec![1, 0, 0, 0, 0], u32::MAX as u64),
        (raw::GET_GLYPH_INDICES, vec![1, 0, 0, 0, 0], u32::MAX as u64),
        (raw::GET_CHAR_ABC_WIDTHS, vec![1, 1, 0, 0, 1, 2], 0),
        (raw::GET_OUTLINE_METRICS, vec![1, 0, 0, 0], 0)] {
        assert_eq!(raw::route(ordinal, &args, |_| None, |_| panic!("missing font callback")), Some(failure));
        assert_eq!(raw::route(ordinal, &args, |_| Some(Font { width: i32::MIN, ..snapshot() }), |_| panic!("invalid font callback")), Some(failure));
        for result in [0, 1, 232, u32::MAX as u64, 0x1234_5678_9abc_def0] {
            assert_eq!(raw::route(ordinal, &args, |_| Some(snapshot()), |_| result), Some(result));
        }
    }
}
