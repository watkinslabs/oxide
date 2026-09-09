//! The real dispatcher must consume the screen-coordinate rectangle query.
use super::*;
use ipc::win32_window::{WindowRect, WM_LBUTTONDOWN, WM_NCHITTEST, HTCLIENT};
use ipc::win32_window::styles::WS_CHILD;

#[test]
fn actual_default_dispatch_keeps_a_click_inside_a_displaced_dialog_button() {
    let _serial = SERIAL.lock().unwrap();
    setup();
    let (button, queued) = {
        let mut entries = nt_window::GUI.lock();
        let state = &mut entries[0].state;
        let dialog = state.siblings_top_first(None)[0];
        state.set_rect(dialog, WindowRect { left: 284, top: 224, right: 740, bottom: 534 }).unwrap();
        let button = state.create(41, Some(dialog), 0).unwrap();
        state.set_style_bits(button, WS_CHILD, 0).unwrap();
        state.set_rect(button, WindowRect { left: 306, top: 226, right: 436, bottom: 254 }).unwrap();
        state.post_compositor_pointer(button, 65, 13, 1, 0, 0).unwrap();
        let queued = state.peek_for_thread(41,
            MessageFilter { hwnd: Some(button), first: WM_LBUTTONDOWN, last: WM_LBUTTONDOWN }, true).unwrap();
        (button, queued)
    };
    let request = NtCall { service: nt::NtService::DefaultWindowProc,
        args: syscall::SyscallArgs { a0: button.raw() as u64, a1: WM_NCHITTEST as u64,
            a2: 0, a3: queued.lparam as u64, a4: 0, a5: 0 } };
    assert_eq!(nt_window::production::dispatch(request), Some(HTCLIENT as u64));
}
