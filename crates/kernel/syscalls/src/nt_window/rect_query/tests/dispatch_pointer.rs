//! Desktop input, default hit testing and retrieval must agree on coordinates.
use super::*;
use ipc::win32_window::{DefaultWindowResult, MessageFilter, WindowManager, WindowRect, WindowPosition,
    WS_VISIBLE, SWP_NOACTIVATE, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_NCHITTEST, HTCLIENT, HTNOWHERE};
use ipc::win32_window::styles::WS_CHILD;
use ipc::win32_window::hardware::{self, MouseContext, MouseOutcome};

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn child_click_survives_default_hit_test_and_retrieval_after_ancestor_moves() {
    let mut state = WindowManager::new();
    let dialog = state.create(7, None, 0).unwrap();
    let panel = state.create(7, Some(dialog), 0).unwrap();
    let button = state.create(7, Some(panel), 0).unwrap();
    for window in [panel, button] { state.set_style_bits(window, WS_CHILD | WS_VISIBLE, 0).unwrap(); }
    state.apply_position(7, WindowPosition { window: dialog, rect: rect(284, 224, 740, 534),
        client: Some(rect(290, 244, 734, 528)), order: None, visible: None,
        flags: SWP_NOACTIVATE, notify_geometry: false }).unwrap();
    state.set_rect(panel, rect(10, 20, 430, 280)).unwrap();
    state.set_rect(button, rect(306, 206, 436, 234)).unwrap();
    for origin in [(284, 224), (-400, -300), (500, 350)] {
        state.set_rect(dialog, rect(origin.0, origin.1, origin.0 + 456, origin.1 + 310)).unwrap();
        for (buttons, expected) in [(1, WM_LBUTTONDOWN), (0, WM_LBUTTONUP)] {
            state.post_compositor_pointer(button, 50, 10, buttons, 0, 0).unwrap();
            let filter = MessageFilter { hwnd: Some(button), first: expected, last: expected };
            let queued = state.peek_for_thread(7, filter, true).unwrap();
            let DefaultWindowResult::Return(hit) = default_proc_state(&state, button.raw(), WM_NCHITTEST, queued.lparam)
                else { panic!("hit test must return a code") };
            assert_eq!(hit, HTCLIENT as i64, "screen click must hit a child after ancestor movement");
            let context = MouseContext { hit_test: hit as i32, client_origin: state.client_origin(button).unwrap(),
                menu_mode: false, captured: false, modal: false, class_dbl_clks: false,
                double_click_ms: 500, double_click_width: 4, double_click_height: 4,
                time_ms: 1000, remove: true, filter };
            let prepared = hardware::prepare_mouse(queued, None, &context);
            assert_eq!(prepared.outcome, MouseOutcome::Ladder);
            assert_eq!(prepared.message.hwnd, Some(button));
            assert_eq!(prepared.message.message, expected);
            assert_eq!(prepared.message.lparam, (10 << 16) | 50);
        }
        let screen = query_state(&state, button, RectKind::Window, 0, 0).unwrap();
        for (x, y) in [(screen.right, screen.top), (screen.left, screen.bottom), (screen.left - 1, screen.top)] {
            let point = ((y as u16 as u32) << 16 | x as u16 as u32) as i64;
            assert_eq!(default_proc_state(&state, button.raw(), WM_NCHITTEST, point),
                DefaultWindowResult::Return(HTNOWHERE as i64));
        }
    }
}
