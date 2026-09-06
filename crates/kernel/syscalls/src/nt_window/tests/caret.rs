use super::*;
use alloc::vec::Vec;

#[test]
fn caret_position_preserves_signed_wire_coordinates() {
    let position = CaretPos { x: -7, y: 19 };
    assert_eq!(CaretPos::decode(position.encode()), position);
    assert_eq!(CREATE_CARET_ORDINAL, 0x1360);
    assert_eq!(SET_CARET_POS_ORDINAL, 0x153c);
}

struct RenderLog(Vec<&'static str>);

impl super::CaretRenderSink for RenderLog {
    fn erase_caret_pixels(&mut self, _: u64, _: u64, _: (i32, i32, i32, i32), _: u64) -> bool {
        self.0.push("erase");
        true
    }

    fn paint_caret_pixels(&mut self, _: u64, _: u64, _: (i32, i32, i32, i32), _: u64) -> bool {
        self.0.push("paint");
        true
    }
}

#[test]
fn committed_visible_move_erases_before_painting_new_pixels() {
    let hwnd = ipc::win32_window::WindowId::from_raw(9);
    let transition = ipc::win32_window::CaretTransition {
        hwnd,
        old_hwnd: hwnd,
        old_visible: true,
        new_visible: true,
        old_rect: (1, 2, 3, 4),
        new_rect: (5, 6, 7, 8),
    };
    let mut log = RenderLog(Vec::new());
    assert!(publish_transition(&mut log, 44, transition, 17));
    assert_eq!(log.0, ["erase", "paint"]);
}

#[test]
fn failed_pixel_callback_is_reported() {
    struct Reject;
    impl super::CaretRenderSink for Reject {
        fn erase_caret_pixels(&mut self, _: u64, _: u64, _: (i32, i32, i32, i32), _: u64) -> bool { false }
        fn paint_caret_pixels(&mut self, _: u64, _: u64, _: (i32, i32, i32, i32), _: u64) -> bool { true }
    }
    let transition = ipc::win32_window::CaretTransition {
        hwnd: ipc::win32_window::WindowId::from_raw(9),
        old_hwnd: ipc::win32_window::WindowId::from_raw(9),
        old_visible: true,
        new_visible: false,
        old_rect: (0, 0, 1, 1),
        new_rect: (0, 0, 1, 1),
    };
    assert!(!publish_transition(&mut Reject, 44, transition, 1));
}
