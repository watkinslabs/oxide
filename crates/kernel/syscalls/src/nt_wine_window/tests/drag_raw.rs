use super::*;
use ipc::win32_window::WindowRect;

#[test]
fn the_ordinals_and_argument_counts_match_the_generated_win32u_table() {
    assert_eq!([DRAG_DETECT, DRAG_OBJECT, WAIT_FOR_INPUT_IDLE], [0x1393, 0x1394, 0x15f8]);
    assert_eq!([crate::nt_wine_raw_args_contract::argument_count(DRAG_DETECT),
        crate::nt_wine_raw_args_contract::argument_count(DRAG_OBJECT),
        crate::nt_wine_raw_args_contract::argument_count(WAIT_FOR_INPUT_IDLE)],
        [Some(3), Some(5), Some(3)]);
}

#[test]
fn a_press_is_a_drag_candidate_only_while_the_button_is_held() {
    assert!(left_button_down(0x8000));
    assert!(left_button_down(0xffff));
    assert!(!left_button_down(0x0001));
    assert!(!left_button_down(0));
    assert_eq!(VK_LBUTTON, 0x01);
}

#[test]
fn the_drag_square_spans_twice_each_metric_around_the_press() {
    assert_eq!(drag_rect(100, 50, 4, 4), WindowRect { left: 96, top: 46, right: 104, bottom: 54 });
    assert_eq!(drag_rect(0, 0, 0, 0), WindowRect { left: 0, top: 0, right: 0, bottom: 0 });
    // The press coordinates are client relative, so a negative edge is normal.
    assert_eq!(drag_rect(2, 1, 4, 4), WindowRect { left: -2, top: -3, right: 6, bottom: 5 });
    // Neither extent may wrap at the ends of the coordinate range.
    assert_eq!(drag_rect(i32::MAX, i32::MIN, 4, 4).right, i32::MAX);
    assert_eq!(drag_rect(i32::MAX, i32::MIN, 4, 4).top, i32::MIN);
    assert_eq!([SM_CXDRAG, SM_CYDRAG], [68, 69]);
    assert_eq!([ipc::win32_gdi::system_metric_default(SM_CXDRAG), ipc::win32_gdi::system_metric_default(SM_CYDRAG)],
        [Some(4), Some(4)]);
}

#[test]
fn a_rectangle_holds_its_left_and_top_edges_and_excludes_the_others() {
    let rect = WindowRect { left: 10, top: 20, right: 30, bottom: 40 };
    assert!(pt_in_rect(rect, 10, 20));
    assert!(pt_in_rect(rect, 29, 39));
    assert!(!pt_in_rect(rect, 30, 39));
    assert!(!pt_in_rect(rect, 29, 40));
    assert!(!pt_in_rect(rect, 9, 20));
    assert!(!pt_in_rect(rect, 10, 19));
}

#[test]
fn a_mouse_position_is_two_signed_halves_of_the_low_lparam_word() {
    assert_eq!(mouse_point(0), (0, 0));
    assert_eq!(mouse_point(ipc::win32_window::mouse_lparam(7, 9)), (7, 9));
    assert_eq!(mouse_point(ipc::win32_window::mouse_lparam(-3, -4)), (-3, -4));
    // The high half of the sixty-four bit value never reaches the position.
    assert_eq!(mouse_point(0x1234_5678_0000_0000), (0, 0));
}

#[test]
fn the_button_release_ends_the_gesture_as_a_click_wherever_it_lands() {
    let rect = drag_rect(100, 100, 4, 4);
    assert_eq!(drag_step(ipc::win32_window::WM_LBUTTONUP, ipc::win32_window::mouse_lparam(100, 100), rect), DragStep::Released);
    assert_eq!(drag_step(ipc::win32_window::WM_LBUTTONUP, ipc::win32_window::mouse_lparam(900, 900), rect), DragStep::Released);
}

#[test]
fn a_move_out_of_the_square_is_a_drag_and_a_move_inside_it_is_not() {
    let rect = drag_rect(100, 100, 4, 4);
    assert_eq!(drag_step(ipc::win32_window::WM_MOUSEMOVE, ipc::win32_window::mouse_lparam(101, 101), rect), DragStep::Continue);
    assert_eq!(drag_step(ipc::win32_window::WM_MOUSEMOVE, ipc::win32_window::mouse_lparam(96, 96), rect), DragStep::Continue);
    assert_eq!(drag_step(ipc::win32_window::WM_MOUSEMOVE, ipc::win32_window::mouse_lparam(104, 100), rect), DragStep::Escaped);
    assert_eq!(drag_step(ipc::win32_window::WM_MOUSEMOVE, ipc::win32_window::mouse_lparam(100, 95), rect), DragStep::Escaped);
}

#[test]
fn every_other_mouse_message_leaves_the_gesture_running() {
    let rect = drag_rect(0, 0, 4, 4);
    for message in [ipc::win32_window::WM_LBUTTONDOWN, ipc::win32_window::WM_RBUTTONDOWN,
        ipc::win32_window::WM_RBUTTONUP, ipc::win32_window::WM_MBUTTONDOWN, ipc::win32_window::WM_MOUSEWHEEL] {
        assert_eq!(drag_step(message, ipc::win32_window::mouse_lparam(900, 900), rect), DragStep::Continue);
    }
}

#[test]
fn the_transfer_ordinal_accepts_no_object() {
    assert_eq!(DRAG_OBJECT_NONE, 0);
}

#[test]
fn both_an_ended_process_and_an_idle_one_report_success() {
    assert_eq!(idle_result(IdleWake::ProcessEnded), 0);
    assert_eq!(idle_result(IdleWake::Idle), 0);
    assert_eq!(idle_result(IdleWake::TimedOut), 0x0000_0102);
    assert_eq!(idle_result(IdleWake::Failed), 0xffff_ffff);
    assert_eq!([WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED], [0, 0x0000_0102, 0xffff_ffff]);
}

#[test]
fn an_infinite_wait_never_expires_and_a_bounded_one_expires_past_its_timeout() {
    assert!(!idle_expired(INFINITE, u64::MAX));
    assert!(!idle_expired(1000, 1000));
    assert!(idle_expired(1000, 1001));
    assert!(idle_expired(0, 1));
    assert!(!idle_expired(0, 0));
    assert_eq!(INFINITE, 0xffff_ffff);
}
