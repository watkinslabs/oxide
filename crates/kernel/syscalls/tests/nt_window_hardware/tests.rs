use super::*;
use ipc::win32_window::{HTCLIENT, HTTRANSPARENT, WM_NCHITTEST};

#[test]
fn nonremoving_hardware_peek_preserves_the_raw_screen_point() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    nt_window::GUI.lock()[0].state.post_compositor_pointer(button, 20, 10, 1, 0, 0).unwrap();
    let original = queued_button();
    let nt_window::hardware::Stage::Prepared { message, .. } = peek_mouse(false) else { panic!("missing prepared message"); };
    assert_eq!(ipc::win32_window::hardware::split_point(message.lparam), (20, 10));
    assert_eq!(queued_button(), original, "PM_NOREMOVE changed the canonical raw event");
    for _ in 0..3 {
        let nt_window::hardware::Stage::Prepared { message: again, .. } = peek_mouse(false) else { panic!("missing repeat view"); };
        assert_eq!(again, message);
        assert_eq!(queued_button(), original);
    }
}

#[test]
fn transparent_control_hit_tests_the_next_candidate_instead_of_delivering_to_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    let label = window(Some(parent), (30, 40, 130, 68), HTTRANSPARENT);
    nt_window::GUI.lock()[0].state.post_compositor_pointer(parent, 50, 50, 1, 0, 0).unwrap();
    let _ = peek_mouse(false);
    let hits: Vec<_> = CALLS.lock().unwrap().iter().filter(|call| call.message == WM_NCHITTEST).map(|call| call.hwnd).collect();
    assert_eq!(hits, [label.raw(), button.raw()]);
}

#[test]
fn suspended_transparent_walk_resumes_at_the_next_candidate() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    let label = window(Some(parent), (30, 40, 130, 68), HTTRANSPARENT);
    nt_window::GUI.lock()[0].state.post_compositor_pointer(parent, 50, 50, 1, 0, 0).unwrap();
    let original = queued_button();
    *SUSPEND.lock().unwrap() = true;
    assert_eq!(peek_mouse(false), nt_window::hardware::Stage::Pending(nt_window::STATUS_PENDING));
    assert_eq!(complete_callback(), nt_window::hardware::Stage::Pending(nt_window::STATUS_PENDING));
    let nt_window::hardware::Stage::Prepared { message, .. } = complete_callback() else { panic!("missing translated result"); };
    assert_eq!(message.hwnd, Some(button));
    assert_eq!(ipc::win32_window::hardware::split_point(message.lparam), (20, 10));
    assert_eq!(queued_button(), original);
    let hits: Vec<_> = CALLS.lock().unwrap().iter().filter(|call| call.message == WM_NCHITTEST).map(|call| call.hwnd).collect();
    assert_eq!(hits, [label.raw(), button.raw()]);
}

#[test]
fn retrieval_uses_capture_changed_after_the_event_was_queued() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    nt_window::GUI.lock()[0].state.post_compositor_pointer(parent, 50, 50, 1, 0, 0).unwrap();
    nt_window::GUI.lock()[0].state.set_capture_window(41, Some(button), 0).unwrap();
    let nt_window::hardware::Stage::Prepared { message, .. } = peek_mouse(false) else { panic!("missing captured result"); };
    assert_eq!(message.hwnd, Some(button));
    assert_eq!(ipc::win32_window::hardware::split_point(message.lparam), (20, 10));
    assert!(CALLS.lock().unwrap().is_empty());
}

#[test]
fn retired_selection_never_removes_an_identical_successor() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    nt_window::GUI.lock()[0].state.post_compositor_pointer(parent, 50, 50, 1, 0, 0).unwrap();
    let original = queued_button();
    let nt_window::hardware::Stage::Prepared { id, .. } = peek_mouse(false) else { panic!("missing selected result"); };
    let mut entries = nt_window::GUI.lock();
    let state = &mut entries[0].state;
    assert_eq!(state.read_selected_for_thread(41, id, true), Some(original));
    state.post_to_window(parent, original).unwrap();
    assert_eq!(state.read_selected_for_thread(41, id, true), None);
    assert_eq!(state.peek_for_thread(41, MessageFilter { hwnd: None, first: original.message, last: original.message }, false), Some(original));
}

#[test]
fn posted_mouse_number_does_not_enter_hardware_processing() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let message = WinMessage { hwnd: Some(parent), message: ipc::win32_window::WM_LBUTTONDOWN, wparam: 1, lparam: 0 };
    nt_window::GUI.lock()[0].state.post_to_window(parent, message).unwrap();
    assert_eq!(peek_mouse(false), nt_window::hardware::Stage::Ready);
    assert_eq!(queued_button(), message);
    assert!(CALLS.lock().unwrap().is_empty());
}

#[test]
fn repeated_nonclient_peeks_do_not_renumber_the_raw_event() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    const HTCAPTION: i32 = 2;
    const WM_NCLBUTTONDOWN: u32 = 0x00a1;
    let parent = window(None, (280, 200, 740, 540), HTCAPTION);
    raw_button(parent, 330, 250);
    let original = queued_button();
    for _ in 0..3 {
        let nt_window::hardware::Stage::Prepared { message, .. } = peek_range(false, WM_NCLBUTTONDOWN, original.message)
            else { panic!("missing nonclient view"); };
        assert_eq!(message.message, WM_NCLBUTTONDOWN);
        assert_eq!(message.wparam, HTCAPTION as u64);
        assert_eq!(message.lparam, original.lparam);
        assert_eq!(queued_button(), original);
    }
}

#[test]
fn disabled_scope_sets_error_cursor_without_calling_hit_test() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    nt_window::GUI.lock()[0].state.set_style_bits(parent,
        ipc::win32_window::styles::WS_VISIBLE | ipc::win32_window::styles::WS_DISABLED, 0).unwrap();
    raw_button(parent, 330, 250);
    assert_eq!(peek_range(false, 0, 0), nt_window::hardware::Stage::Again);
    let calls = CALLS.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].message, ipc::win32_window::WM_SETCURSOR);
    assert_eq!(calls[0].lparam as i16 as i32, ipc::win32_window::HTERROR);
}

#[test]
fn exhausted_transparent_scope_drops_the_event() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTTRANSPARENT);
    raw_button(parent, 330, 250);
    assert_eq!(peek_mouse(false), nt_window::hardware::Stage::Again);
    assert!(nt_window::GUI.lock()[0].state.peek_for_thread(41,
        MessageFilter { hwnd: None, first: ipc::win32_window::WM_LBUTTONDOWN, last: ipc::win32_window::WM_LBUTTONDOWN }, false).is_none());
    assert_eq!(CALLS.lock().unwrap().len(), 1);
}

#[test]
fn destroyed_next_candidate_is_skipped_after_callback_return() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    let label = window(Some(parent), (30, 40, 130, 68), HTTRANSPARENT);
    raw_button(parent, 330, 250);
    *SUSPEND.lock().unwrap() = true;
    assert_eq!(peek_mouse(false), nt_window::hardware::Stage::Pending(nt_window::STATUS_PENDING));
    nt_window::GUI.lock()[0].state.destroy(button).unwrap();
    assert_eq!(complete_callback(), nt_window::hardware::Stage::Pending(nt_window::STATUS_PENDING));
    let nt_window::hardware::Stage::Prepared { message, .. } = complete_callback() else { panic!("missing surviving target"); };
    assert_eq!(message.hwnd, Some(parent));
    let hits: Vec<_> = CALLS.lock().unwrap().iter().filter(|call| call.message == WM_NCHITTEST).map(|call| call.hwnd).collect();
    assert_eq!(hits, [label.raw(), parent.raw()]);
}

#[test]
fn target_destroyed_by_its_hit_test_is_not_delivered() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner()); setup();
    let parent = window(None, (280, 200, 740, 540), HTCLIENT);
    let button = window(Some(parent), (30, 40, 130, 68), HTCLIENT);
    raw_button(parent, 330, 250);
    *SUSPEND.lock().unwrap() = true;
    assert_eq!(peek_mouse(false), nt_window::hardware::Stage::Pending(nt_window::STATUS_PENDING));
    nt_window::GUI.lock()[0].state.destroy(button).unwrap();
    assert_eq!(complete_callback(), nt_window::hardware::Stage::Again);
    assert!(nt_window::GUI.lock()[0].state.peek_for_thread(41,
        MessageFilter { hwnd: None, first: ipc::win32_window::WM_LBUTTONDOWN, last: ipc::win32_window::WM_LBUTTONDOWN }, false).is_none());
}
