//! Mapping replays disjoint retained areas without claiming their holes.
use super::*;
use crate::BridgeCommand;
const CW_BACK_PIXEL: u32 = 1 << 1;
const BACKGROUND: u32 = 0x0077_8899;

#[test]
fn show_replays_partial_frames_and_preserves_unpainted_background() {
    let mut f = Fixture::open(W, H);
    f.backend.handle_command(BridgeCommand::Hide { hwnd: 0xb1 }).unwrap();
    let first = Rect { left: 2, top: 3, right: 8, bottom: 9 };
    let second = Rect { left: 20, top: 15, right: 30, bottom: 22 };
    f.present(W, H, first, FIRST);
    f.present(W, H, second, SECOND);
    unsafe {
        ffi::xcb_change_window_attributes(f.conn, f.xid, CW_BACK_PIXEL, &BACKGROUND);
        crate::xvfb_harness::child_order(f.conn, f.xid);
    }
    f.backend.handle_command(BridgeCommand::Show { hwnd: 0xb1 })
        .expect("valid partial retained coverage must not refuse Show");
    let (displayed, _, held) = f.displayed_and_retained(W, H);
    assert_eq!(held, [first, second]);
    for y in 0..H as i32 { for x in 0..W as i32 {
        let inside = |r: Rect| x >= r.left && x < r.right && y >= r.top && y < r.bottom;
        let expected = if inside(first) { FIRST } else if inside(second) { SECOND } else { BACKGROUND };
        assert_eq!(displayed[(y as u32 * W + x as u32) as usize] & 0x00ff_ffff, expected, "pixel at {x},{y}");
    } }
}

#[test]
fn rejected_x11_frame_receives_failure_ack_on_the_bridge() {
    let mut f = Fixture::open(W, H);
    unsafe {
        let cookie = ffi::xcb_query_tree(f.conn, f.xid);
        let mut error = ptr::null_mut();
        let reply = ffi::xcb_query_tree_reply(f.conn, cookie, &mut error);
        assert!(!reply.is_null()); let root = (*reply).root; libc::free(reply.cast());
        ffi::xcb_destroy_window(f.conn, f.xid);
        crate::xvfb_harness::child_order(f.conn, root);
    }
    f.sequence += 1;
    send(&mut f.peer, Opcode::Frame, f.sequence, 0xb1,
        frame(W, H, Rect { left: 0, top: 0, right: W as i32, bottom: H as i32 }, FIRST));
    crate::xvfb_harness::ack_status(&mut f.peer, &mut f.backend, &mut f.transport, f.sequence, 1);
}

#[test]
fn earlier_batch_error_is_not_hidden_by_a_successful_last_request() {
    let f = Fixture::open(W, H);
    let cookies = unsafe {
        let absent = ffi::xcb_generate_id(f.conn);
        vec![ffi::xcb_configure_window_checked(f.conn, absent, 0, ptr::null()),
            ffi::xcb_configure_window_checked(f.conn, f.xid, 0, ptr::null())]
    };
    assert!(matches!(crate::x11::requests::finish(f.conn, 0xb1, cookies), Err(crate::BackendError::X11)));
}
