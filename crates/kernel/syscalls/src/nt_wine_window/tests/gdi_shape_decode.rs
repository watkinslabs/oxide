use super::*;
use ipc::win32_gdi::Rect;

const DC: u64 = 0x0100_0042;

#[test]
fn every_single_handle_path_ordinal_decodes_to_its_own_operation() {
    for (ordinal, op) in [(BEGIN_PATH, PathOp::Begin), (END_PATH, PathOp::End), (ABORT_PATH, PathOp::Abort),
        (CLOSE_FIGURE, PathOp::CloseFigure), (FLATTEN_PATH, PathOp::Flatten), (WIDEN_PATH, PathOp::Widen),
        (FILL_PATH, PathOp::Fill), (STROKE_PATH, PathOp::Stroke), (STROKE_AND_FILL_PATH, PathOp::StrokeAndFill),
        (PATH_TO_REGION, PathOp::ToRegion)] {
        assert_eq!(decode(ordinal, &[DC]), Some(Operation::Path { dc: DC, op }), "{ordinal:#x}");
    }
}

#[test]
fn a_short_argument_slice_is_never_read_past() {
    assert_eq!(decode(GET_PATH, &[DC, 1, 2]), None);
    assert_eq!(decode(CREATE_ROUND_RECT_RGN, &[0, 0, 4, 4, 2]), None);
    assert_eq!(decode(FRAME_RGN, &[DC, 1, 2, 3]), None);
    assert_eq!(decode(BEGIN_PATH, &[]), None);
}

#[test]
fn an_unadmitted_ordinal_decodes_to_nothing() {
    assert_eq!(decode(0x1234, &[0, 0, 0, 0, 0, 0]), None);
}

#[test]
fn signed_coordinates_come_from_the_low_word_of_each_argument() {
    assert_eq!(decode(CREATE_ELLIPTIC_RGN, &[u64::from(-3i32 as u32), u64::from(-4i32 as u32), 5, 6]),
        Some(Operation::CreateEllipticRgn { rect: Rect { left: -3, top: -4, right: 5, bottom: 6 } }));
    assert_eq!(decode(OFFSET_RGN, &[7, u64::from(-1i32 as u32), 2]),
        Some(Operation::OffsetRgn { region: 7, x: -1, y: 2 }));
    assert_eq!(decode(PT_VISIBLE, &[DC, u64::from(-9i32 as u32), 0]),
        Some(Operation::PtVisible { dc: DC, x: -9, y: 0 }));
}

#[test]
fn the_rounded_rectangle_carries_its_two_stack_parameters() {
    assert_eq!(decode(CREATE_ROUND_RECT_RGN, &[1, 2, 30, 40, 8, 9]),
        Some(Operation::CreateRoundRectRgn { rect: Rect { left: 1, top: 2, right: 30, bottom: 40 },
            ellipse_width: 8, ellipse_height: 9 }));
}

#[test]
fn the_exclusion_rectangle_starts_after_the_device_context() {
    assert_eq!(decode(EXCLUDE_CLIP_RECT, &[DC, 1, 2, 3, 4]),
        Some(Operation::ExcludeClipRect { dc: DC, rect: Rect { left: 1, top: 2, right: 3, bottom: 4 } }));
}

#[test]
fn the_frame_carries_both_border_extents_after_the_brush() {
    assert_eq!(decode(FRAME_RGN, &[DC, 5, 6, 2, 3]),
        Some(Operation::FrameRgn { dc: DC, region: 5, brush: 6, width: 2, height: 3 }));
}

#[test]
fn buffer_lengths_are_unsigned_and_pointers_stay_full_width() {
    assert_eq!(decode(GET_REGION_DATA, &[9, 0xffff_ffff, 0x7fff_0000_1000]),
        Some(Operation::GetRegionData { region: 9, count: u32::MAX, data: 0x7fff_0000_1000 }));
    assert_eq!(decode(EXT_CREATE_REGION, &[0, 32, 0x7fff_0000_2000]),
        Some(Operation::ExtCreateRegion { xform: 0, count: 32, data: 0x7fff_0000_2000 }));
    assert_eq!(decode(GET_PATH, &[DC, 0x1000, 0x2000, u64::from(-1i32 as u32)]),
        Some(Operation::GetPath { dc: DC, points: 0x1000, types: 0x2000, size: -1 }));
}

#[test]
fn each_clip_selector_keeps_its_own_mode_and_code() {
    assert_eq!(decode(EXT_SELECT_CLIP_RGN, &[DC, 0, 5]), Some(Operation::ExtSelectClipRgn { dc: DC, region: 0, mode: 5 }));
    assert_eq!(decode(SELECT_CLIP_PATH, &[DC, 1]), Some(Operation::SelectClipPath { dc: DC, mode: 1 }));
    assert_eq!(decode(GET_RANDOM_RGN, &[DC, 4, u64::from(0x8000_0004u32)]),
        Some(Operation::GetRandomRgn { dc: DC, region: 4, code: 0x8000_0004u32 as i32 }));
    assert_eq!(decode(SET_META_RGN, &[DC]), Some(Operation::SetMetaRgn { dc: DC }));
}

#[test]
fn region_drawing_ordinals_keep_their_handle_order() {
    assert_eq!(decode(FILL_RGN, &[DC, 2, 3]), Some(Operation::FillRgn { dc: DC, region: 2, brush: 3 }));
    assert_eq!(decode(INVERT_RGN, &[DC, 2]), Some(Operation::InvertRgn { dc: DC, region: 2 }));
    assert_eq!(decode(EQUAL_RGN, &[7, 8]), Some(Operation::EqualRgn { first: 7, second: 8 }));
    assert_eq!(decode(PT_IN_REGION, &[7, 1, 2]), Some(Operation::PtInRegion { region: 7, x: 1, y: 2 }));
    assert_eq!(decode(RECT_IN_REGION, &[7, 0x3000]), Some(Operation::RectInRegion { region: 7, rect: 0x3000 }));
}
