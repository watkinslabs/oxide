use super::*;
use ipc::win32_window::WindowRect;

#[test]
fn draw_callback_record_preserves_native_offsets_and_zero_tracking() {
    let bytes = draw_record(0x123456789, 0xabcdef123, Rect { left: -3, top: 4, right: 97, bottom: 104 },
        ScrollLayout { arrow_size: 17, thumb_pos: 35, thumb_size: 23 }, 2, true);
    assert_eq!(bytes.len(), 104);
    assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 0x123456789);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0xabcdef123);
    let words: alloc::vec::Vec<_> = bytes[16..].chunks_exact(4)
        .map(|chunk| i32::from_le_bytes(chunk.try_into().unwrap())).collect();
    assert_eq!(words, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, -3, 4, 97, 104, 2, 17, 35, 23, 1, 0]);
}

#[test]
fn creation_alignment_retains_opposite_edge_and_top_left_takes_precedence() {
    let rect = WindowRect { left: -20, top: 10, right: 80, bottom: 210 };
    assert_eq!(aligned_creation(rect, SBS_VERT, 18, 19), None);
    assert_eq!(aligned_creation(rect, SBS_VERT | SBS_BOTTOM_RIGHT, 18, 19),
        Some(WindowRect { left: 62, ..rect }));
    assert_eq!(aligned_creation(rect, SBS_TOP_LEFT | SBS_BOTTOM_RIGHT, 18, 19),
        Some(WindowRect { bottom: 29, ..rect }));
    for kind in [SBS_SIZEBOX, SBS_SIZEGRIP] {
        assert_eq!(aligned_creation(rect, kind | SBS_TOP_LEFT, 18, 19),
            Some(WindowRect { right: -2, bottom: 29, ..rect }));
        assert_eq!(aligned_creation(rect, kind | SBS_BOTTOM_RIGHT, 18, 19),
            Some(WindowRect { left: 62, top: 191, ..rect }));
    }
}
