use super::*;

#[test]
fn the_ordinal_and_argument_count_match_the_generated_win32u_table() {
    assert_eq!(DRAW_ICON_EX, 0x139a);
    assert_eq!(crate::nt_wine_raw_args_contract::argument_count(DRAW_ICON_EX), Some(9));
    assert_eq!([DI_MASK, DI_IMAGE, DI_DEFAULTSIZE], [0x0001, 0x0002, 0x0008]);
    assert_eq!([SM_CXICON, SM_CYICON], [11, 12]);
}

#[test]
fn a_mask_only_request_copies_the_mask_and_draws_no_image() {
    let plan = icon_plan(DI_MASK, false, true);
    assert_eq!(plan, IconPlan { alpha: false, mask: Some(ipc::win32_gdi::SRCCOPY), image: None });
}

#[test]
fn an_image_only_request_copies_the_colour_bitmap_and_draws_no_mask() {
    let plan = icon_plan(DI_IMAGE, false, true);
    assert_eq!(plan, IconPlan { alpha: false, mask: None,
        image: Some((ImageSource::Color, ipc::win32_gdi::SRCCOPY)) });
}

#[test]
fn a_normal_request_ands_the_mask_down_then_inverts_the_image_back_out() {
    let plan = icon_plan(DI_MASK | DI_IMAGE, false, true);
    assert_eq!(plan, IconPlan { alpha: false, mask: Some(ipc::win32_gdi::SRCAND),
        image: Some((ImageSource::Color, ipc::win32_gdi::SRCINVERT)) });
}

#[test]
fn a_frame_without_a_colour_bitmap_reads_its_image_from_the_lower_mask_half() {
    let plan = icon_plan(DI_MASK | DI_IMAGE, false, false);
    assert_eq!(plan.image, Some((ImageSource::MaskLowerHalf, ipc::win32_gdi::SRCINVERT)));
    assert_eq!(icon_plan(DI_IMAGE, false, false).image,
        Some((ImageSource::MaskLowerHalf, ipc::win32_gdi::SRCCOPY)));
}

#[test]
fn per_pixel_alpha_blends_only_when_the_request_asks_for_the_image() {
    assert!(icon_plan(DI_MASK | DI_IMAGE, true, true).alpha);
    assert!(icon_plan(DI_IMAGE, true, true).alpha);
    assert!(!icon_plan(DI_MASK, true, true).alpha);
    assert!(!icon_plan(DI_MASK | DI_IMAGE, false, true).alpha);
    // A blend that cannot run leaves the ordinary passes to do the work.
    let plan = icon_plan(DI_MASK | DI_IMAGE, true, true);
    assert_eq!(plan.mask, Some(ipc::win32_gdi::SRCAND));
    assert_eq!(plan.image, Some((ImageSource::Color, ipc::win32_gdi::SRCINVERT)));
}

#[test]
fn a_request_asking_for_neither_pass_draws_nothing() {
    assert_eq!(icon_plan(0, true, true), IconPlan { alpha: false, mask: None, image: None });
    assert_eq!(icon_plan(DI_DEFAULTSIZE, true, true), IconPlan { alpha: false, mask: None, image: None });
}

#[test]
fn an_omitted_extent_takes_the_default_metric_or_the_frames_own_extent() {
    assert_eq!(draw_extent(48, 0, 32, 64), 48);
    assert_eq!(draw_extent(48, DI_DEFAULTSIZE, 32, 64), 48);
    assert_eq!(draw_extent(0, 0, 32, 64), 32);
    assert_eq!(draw_extent(0, DI_DEFAULTSIZE, 32, 64), 64);
    assert_eq!(draw_extent(0, DI_MASK | DI_IMAGE, 32, 64), 32);
}

#[test]
fn an_offscreen_draw_starts_at_its_own_origin_and_a_direct_one_at_the_request() {
    assert_eq!(offscreen_origin(true, 40, 50), (0, 0));
    assert_eq!(offscreen_origin(false, 40, 50), (40, 50));
}

#[test]
fn only_a_brush_tagged_handle_selects_the_offscreen_path() {
    assert!(is_brush(ipc::win32_gdi::TYPE_BRUSH as u64 | 7));
    assert!(!is_brush(ipc::win32_gdi::TYPE_DC as u64 | 7));
    assert!(!is_brush(ipc::win32_gdi::TYPE_FONT as u64 | 7));
    assert!(!is_brush(0));
    assert!(!is_brush(u64::MAX));
}

#[test]
fn the_brush_fill_covers_a_square_of_the_destination_width() {
    assert_eq!(brush_fill_extent(32), (32, 32));
    assert_eq!(brush_fill_extent(48), (48, 48));
}

#[test]
fn every_icon_pass_runs_black_on_white_whatever_the_caller_selected() {
    let caller = ipc::win32_gdi::SharedDcColors { brush: 0x00123456, text: 0x00abcdef,
        background: 0x00fedcba, background_mode: 2 };
    let used = icon_colors(caller);
    assert_eq!(used.text, 0);
    assert_eq!(used.background, 0x00ff_ffff);
    assert_eq!(used.brush, caller.brush);
    assert_eq!(used.background_mode, caller.background_mode);
}

#[test]
fn an_alpha_frame_composites_source_over_at_full_constant_alpha() {
    let blend = icon_blend();
    assert_eq!(blend.op, ipc::win32_gdi::AC_SRC_OVER);
    assert_eq!(blend.flags, 0);
    assert_eq!(blend.source_constant_alpha, 255);
    assert_eq!(blend.alpha_format, ipc::win32_gdi::AC_SRC_ALPHA);
    // A fully transparent source leaves the destination; an opaque one replaces it.
    assert_eq!(blend.apply(0x0000_0000, 0x0012_3456), 0x0012_3456);
    assert_eq!(blend.apply(0xff11_2233, 0x00ab_cdef), 0x0011_2233);
}
