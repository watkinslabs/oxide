use super::*;

const BOUNDS: Bounds = Bounds { left: 1, top: 2, right: 30, bottom: 40 };

#[test]
fn every_ordinal_this_family_owns_declares_its_windows_argument_count() {
    for (ordinal, count) in CALLS { assert_eq!(argument_count(*ordinal), Some(*count), "ordinal {ordinal:#x}"); }
    assert_eq!(argument_count(0x1234), None);
    assert!(CALLS.iter().all(|entry| entry.1 <= MAX_ARGUMENTS));
}

#[test]
fn the_arc_form_leads_the_argument_list_and_the_device_context_follows_it() {
    let args = [3, 7, 1, 2, 30, 40, 11, 12, 13, 14];
    assert_eq!(decode(ARC_INTERNAL, &args), Some(Call::ArcInternal { dc: 7, kind: 3, bounds: BOUNDS,
        start: (11, 12), end: (13, 14) }));
    // Reading the handle from the first slot would take the arc form as a handle.
    assert_ne!(decode(ARC_INTERNAL, &args).map(|call| matches!(call, Call::ArcInternal { dc: 3, .. })), Some(true));
}

#[test]
fn the_bounded_primitives_take_their_rectangle_in_signed_logical_units() {
    assert_eq!(decode(ELLIPSE, &[7, 1, 2, 30, 40]), Some(Call::Ellipse { dc: 7, bounds: BOUNDS }));
    assert_eq!(decode(ROUND_RECT, &[7, 1, 2, 30, 40, 8, 6]),
        Some(Call::RoundRect { dc: 7, bounds: BOUNDS, ellipse: (8, 6) }));
    assert_eq!(decode(ELLIPSE, &[7, 0xffff_ffff, 2, 30, 40]),
        Some(Call::Ellipse { dc: 7, bounds: Bounds { left: -1, ..BOUNDS } }));
}

#[test]
fn the_angle_arc_carries_two_raw_float_bit_patterns() {
    let (start, sweep) = (45.0f32.to_bits(), (-90.0f32).to_bits());
    assert_eq!(decode(ANGLE_ARC, &[7, 10, 20, 5, u64::from(start), u64::from(sweep)]),
        Some(Call::AngleArc { dc: 7, x: 10, y: 20, radius: 5, start_bits: start, sweep_bits: sweep }));
    // A negative radius survives decoding; the owner refuses it.
    assert_eq!(decode(ANGLE_ARC, &[7, 0, 0, 0xffff_ffff, 0, 0]).map(|call|
        matches!(call, Call::AngleArc { radius: -1, .. })), Some(true));
}

#[test]
fn a_point_or_run_count_is_bounded_before_any_user_memory_is_read() {
    assert_eq!(decode(POLY_DRAW, &[7, 0x1000, 0x2000, 4]),
        Some(Call::PolyDraw { dc: 7, points: 0x1000, types: 0x2000, count: 4 }));
    assert_eq!(decode(POLY_DRAW, &[7, 0x1000, 0x2000, MAX_POINTS + 1]), None);
    assert_eq!(decode(POLY_POLY_DRAW, &[7, 0x1000, 0x2000, 2, 1]),
        Some(Call::PolyPolyDraw { dc: 7, points: 0x1000, counts: 0x2000, runs: 2, function: 1 }));
    assert_eq!(decode(POLY_POLY_DRAW, &[7, 0x1000, 0x2000, MAX_POINTS + 1, 1]), None);
    assert_eq!(route(POLY_DRAW, &[7, 0x1000, 0x2000, MAX_POINTS + 1], |_| 1), Some(0));
}

#[test]
fn a_truncated_argument_list_decodes_nothing_rather_than_reading_past_its_end() {
    assert_eq!(decode(ARC_INTERNAL, &[3, 7, 1, 2]), None);
    assert_eq!(decode(ROUND_RECT, &[7, 1, 2, 30, 40]), None);
    assert_eq!(route(0x1234, &[7], |_| 1), None);
}
