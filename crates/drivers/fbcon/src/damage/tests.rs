use super::*;

const STRIDE: u32 = 1280;
const HEIGHT: u32 = 800;

#[test]
fn fresh_damage_is_empty_and_takes_nothing() {
    let mut d = Damage::empty();
    assert!(d.is_empty());
    assert_eq!(d.take(STRIDE, HEIGHT), None);
    assert_eq!(Damage::default(), Damage::empty());
}

#[test]
fn zero_extent_regions_are_ignored() {
    let mut d = Damage::empty();
    d.add(10, 10, 0, 16);
    d.add(10, 10, 8, 0);
    assert!(d.is_empty());
    assert_eq!(d.take(STRIDE, HEIGHT), None);
}

#[test]
fn one_cell_damages_only_that_cell() {
    let mut d = Damage::empty();
    d.add(8, 16, 8, 16);
    let r = d.take(STRIDE, HEIGHT).unwrap();
    assert_eq!(r, FlushRect { x: 8, y: 16, w: 8, h: 16, stride_px: STRIDE });
    // Taking consumes the damage.
    assert_eq!(d.take(STRIDE, HEIGHT), None);
}

#[test]
fn adds_merge_into_the_bounding_box() {
    let mut d = Damage::empty();
    d.add(0, 16, 1280, 16); // a whole text row
    d.add(64, 48, 8, 16); // a cursor cell two rows lower
    let r = d.take(STRIDE, HEIGHT).unwrap();
    assert_eq!(r, FlushRect { x: 0, y: 16, w: 1280, h: 48, stride_px: STRIDE });
}

#[test]
fn clamps_to_the_surface() {
    let mut d = Damage::empty();
    d.add(0, 0, STRIDE + 64, HEIGHT + 64);
    let r = d.take(STRIDE, HEIGHT).unwrap();
    assert_eq!(r, FlushRect { x: 0, y: 0, w: STRIDE, h: HEIGHT, stride_px: STRIDE });
}

#[test]
fn a_box_entirely_off_surface_takes_nothing() {
    let mut d = Damage::empty();
    d.add(STRIDE + 8, HEIGHT + 8, 8, 16);
    assert_eq!(d.take(STRIDE, HEIGHT), None);
    // Still consumed, so a stale box cannot leak into the next flush.
    assert!(d.is_empty());
}

#[test]
fn add_saturates_instead_of_wrapping() {
    let mut d = Damage::empty();
    d.add(u32::MAX - 4, u32::MAX - 4, 64, 64);
    // Saturation keeps x1/y1 above x0/y0; the clamp then empties it.
    assert!(!d.is_empty());
    assert_eq!(d.take(STRIDE, HEIGHT), None);
}

#[test]
fn clear_drops_pending_damage() {
    let mut d = Damage::empty();
    d.add(0, 0, 8, 16);
    d.clear();
    assert!(d.is_empty());
}

#[test]
fn byte_offset_is_row_pitch_plus_column() {
    let r = FlushRect { x: 8, y: 16, w: 8, h: 16, stride_px: STRIDE };
    assert_eq!(r.byte_offset(), (16 * 1280 + 8) * 4);
    let full = FlushRect { x: 0, y: 0, w: STRIDE, h: HEIGHT, stride_px: STRIDE };
    assert_eq!(full.byte_offset(), 0);
}

#[test]
fn byte_offset_of_a_deep_row_does_not_overflow_u32_math() {
    // 4K-class surface: y*stride*4 exceeds u32 well before the last row.
    let r = FlushRect { x: 0, y: 2000, w: 3840, h: 16, stride_px: 3840 };
    assert_eq!(r.byte_offset(), 2000u64 * 3840 * 4);
}
