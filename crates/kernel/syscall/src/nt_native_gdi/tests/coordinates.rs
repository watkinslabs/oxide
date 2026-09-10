use super::*;
fn request() -> TextRequest {
    TextRequest { version: super::super::VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc: 1, x: -10, y: 20, flags: OPAQUE | CLIPPED, count: 1, text: 1, advances: 8,
        rect: [-10, 20, 30, 50], height: 16, width: 0, weight: 400, italic: 0,
        foreground: 0, background: 0xffffff, has_rect: 1, reserved: 0,
        background_mode: 2, alignment: 0, current_x: -17, current_y: 29, break_extra: 2, break_rem: 1 }
}
#[test]
fn device_translation_preserves_lengths_advances_and_logical_position() {
    let original = request(); let mapped = original.translated((56, -3)).unwrap();
    assert_eq!((mapped.x, mapped.y, mapped.rect), (46, 17, [46, 17, 86, 47]));
    assert_eq!((mapped.current_x, mapped.current_y), (-17, 29));
    assert_eq!((mapped.advances, mapped.height, mapped.width, mapped.break_extra, mapped.break_rem),
        (original.advances, 16, 0, 2, 1));
}
#[test]
fn overflow_rejects_active_coordinates_only_and_wide_origin_can_cancel() {
    assert!(request().translated((i32::MAX as i64, 0)).is_none());
    let empty = TextRequest { count: 0, flags: 0, ..request() };
    assert!(empty.translated((i32::MAX as i64, i32::MAX as i64)).is_some());
    let wide = TextRequest { x: i32::MIN, flags: 0, ..request() };
    assert_eq!(wide.translated((u32::MAX as i64, 0)).unwrap().x, i32::MAX);
    let empty_opaque = TextRequest { count: 0, ..request() };
    assert!(empty_opaque.translated((i32::MAX as i64, 0)).is_none());
}
