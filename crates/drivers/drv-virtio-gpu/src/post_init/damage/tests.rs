use super::*;

const W: u32 = 1280;
const H: u32 = 800;
const FB: usize = (W * H) as usize * BYTES_PER_PIXEL;

fn rect(x: u32, y: u32, w: u32, h: u32) -> FlushRect {
    FlushRect { x, y, w, h, stride_px: W }
}

#[test]
fn one_text_row_uploads_one_row_not_the_frame() {
    // A single 8x16 console line at text row 3.
    let p = plan_copy(rect(0, 48, W, 16), W, H, FB, FB).unwrap();
    assert_eq!((p.x, p.y, p.w, p.h), (0, 48, W, 16));
    assert_eq!(p.dst_off, 48 * W as u64 * 4);
    assert_eq!(p.src_off, 48 * W as usize * 4);
    assert_eq!(p.row_bytes, W as usize * 4);
    assert!(p.is_contiguous(), "full-width damage is one memcpy");
    assert_eq!(p.bytes(), 16 * W as usize * 4);
    // The whole point: 80 KiB, not 4 MiB — 1/50th of the frame.
    assert_eq!(p.bytes() * 50, FB, "one text row is 2% of the frame");
}

#[test]
fn full_frame_damage_still_covers_everything() {
    let p = plan_copy(rect(0, 0, W, H), W, H, FB, FB).unwrap();
    assert_eq!((p.x, p.y, p.w, p.h), (0, 0, W, H));
    assert_eq!(p.dst_off, 0);
    assert_eq!(p.bytes(), FB);
    assert!(p.is_contiguous());
}

#[test]
fn a_single_cursor_cell_is_a_narrow_non_contiguous_rect() {
    let p = plan_copy(rect(64, 32, 8, 16), W, H, FB, FB).unwrap();
    assert_eq!((p.x, p.y, p.w, p.h), (64, 32, 8, 16));
    assert_eq!(p.row_bytes, 32);
    assert_eq!(p.dst_off, (32 * W as u64 + 64) * 4);
    assert_eq!(p.src_off, (32 * W as usize + 64) * 4);
    assert!(!p.is_contiguous(), "a narrow rect walks per scanline");
    assert_eq!(p.bytes(), 16 * 32);
}

#[test]
fn transfer_offset_matches_row_pitch_plus_column() {
    for (x, y) in [(0u32, 0u32), (8, 16), (1272, 799), (640, 400)] {
        let p = plan_copy(rect(x, y, 8, 1), W, H, FB, FB).unwrap();
        assert_eq!(p.dst_off, (y as u64 * W as u64 + x as u64) * 4, "offset at {x},{y}");
    }
}

#[test]
fn rect_is_clamped_to_the_resource() {
    let p = plan_copy(rect(1200, 780, 400, 400), W, H, FB, FB).unwrap();
    assert_eq!((p.x, p.y, p.w, p.h), (1200, 780, 80, 20));
    // Last byte touched stays inside the backing.
    let last = p.dst_off as usize + (p.h as usize - 1) * p.dst_stride_b + p.row_bytes;
    assert_eq!(last, FB);
}

#[test]
fn origin_outside_the_resource_plans_nothing() {
    assert_eq!(plan_copy(rect(W, 0, 8, 16), W, H, FB, FB), None);
    assert_eq!(plan_copy(rect(0, H, 8, 16), W, H, FB, FB), None);
    assert_eq!(plan_copy(rect(0, 0, 0, 16), W, H, FB, FB), None);
    assert_eq!(plan_copy(rect(0, 0, 8, 0), W, H, FB, FB), None);
}

#[test]
fn degenerate_dimensions_plan_nothing() {
    assert_eq!(plan_copy(rect(0, 0, 8, 16), 0, H, FB, FB), None);
    assert_eq!(plan_copy(rect(0, 0, 8, 16), W, 0, FB, FB), None);
    let zero_stride = FlushRect { x: 0, y: 0, w: 8, h: 16, stride_px: 0 };
    assert_eq!(plan_copy(zero_stride, W, H, FB, FB), None);
}

#[test]
fn a_short_backing_trims_rows_instead_of_overrunning() {
    // Backing only holds 100 scanlines; damage asks for rows 90..110.
    let short = W as usize * 100 * 4;
    let p = plan_copy(rect(0, 90, W, 20), W, H, FB, short).unwrap();
    assert_eq!(p.h, 10);
    let last = p.dst_off as usize + (p.h as usize - 1) * p.dst_stride_b + p.row_bytes;
    assert!(last <= short);
}

#[test]
fn a_short_source_trims_rows_instead_of_overrunning() {
    let short = W as usize * 100 * 4;
    let p = plan_copy(rect(0, 90, W, 20), W, H, short, FB).unwrap();
    assert_eq!(p.h, 10);
    let last = p.src_off + (p.h as usize - 1) * p.src_stride_b + p.row_bytes;
    assert!(last <= short);
}

#[test]
fn a_backing_that_cannot_hold_even_one_row_plans_nothing() {
    assert_eq!(plan_copy(rect(0, 0, W, 16), W, H, FB, 16), None);
    assert_eq!(plan_copy(rect(0, 0, W, 16), W, H, 16, FB), None);
}

// The console grid can be narrower than the mode when the font width does
// not divide it (grid = floor(xres/cell_w) cells). The two strides then
// differ and a flat copy would shear the frame; the plan keeps them apart.
#[test]
fn a_narrower_console_surface_keeps_the_two_strides_apart() {
    let narrow = FlushRect { x: 0, y: 16, w: 1272, h: 16, stride_px: 1272 };
    let src_len = 1272 * H as usize * 4;
    let p = plan_copy(narrow, W, H, src_len, FB).unwrap();
    assert_eq!(p.src_stride_b, 1272 * 4);
    assert_eq!(p.dst_stride_b, W as usize * 4);
    assert_eq!(p.row_bytes, 1272 * 4);
    assert!(!p.is_contiguous(), "differing strides must not collapse to one memcpy");
    assert_eq!(p.src_off, 16 * 1272 * 4);
    assert_eq!(p.dst_off, 16 * W as u64 * 4);
}

// A surface WIDER than the resource is clamped to the resource width, never
// written past it.
#[test]
fn a_wider_console_surface_is_clamped_to_the_resource_width() {
    let wide = FlushRect { x: 0, y: 0, w: 2000, h: 4, stride_px: 2000 };
    let src_len = 2000 * H as usize * 4;
    let p = plan_copy(wide, W, H, src_len, FB).unwrap();
    assert_eq!(p.w, W);
    assert_eq!(p.row_bytes, W as usize * 4);
    assert_eq!(p.src_stride_b, 2000 * 4);
}

// A deep row on a large mode: the offset is the row pitch scaled by the
// resource width, not by the console surface's own width.
#[test]
fn deep_row_offset_on_a_large_mode() {
    let w4k = 3840u32;
    let h4k = 2160u32;
    let fb4k = (w4k * h4k) as usize * 4;
    let r = FlushRect { x: 0, y: 2000, w: w4k, h: 16, stride_px: w4k };
    let p = plan_copy(r, w4k, h4k, fb4k, fb4k).unwrap();
    assert_eq!(p.dst_off, 2000u64 * w4k as u64 * 4);
    assert_eq!(p.h, 16);
    assert!(p.is_contiguous());
}
