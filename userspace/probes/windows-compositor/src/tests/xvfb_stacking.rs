//! Actual server stacking and window-manager request boundary.
use std::ptr;
use crate::{Backend, BridgeCommand, Rect};
use crate::ffi;
use crate::xvfb_harness::{child_order, connect, xvfb};

const CONFIGURE_REQUEST: u8 = 23;

fn create(backend: &mut Backend, hwnd: u32, parent: u64) {
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(),
        rect: Rect { left: 0, top: 0, right: 60, bottom: 40 }, parent,
        style: if parent == 0 { 0 } else { 0x4000_0000 }, ex_style: 0 }).unwrap();
}

#[test]
fn preceding_sibling_projection_preserves_complete_top_to_bottom_order() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    create(&mut backend, 0xb0, 0);
    for hwnd in [0xb1, 0xb2, 0xb3] { create(&mut backend, hwnd, 0xb0); }
    backend.position(0xb1, Some(0), false).unwrap();
    backend.position(0xb2, Some(0xb1), false).unwrap();
    backend.position(0xb3, Some(0xb2), false).unwrap();
    let (conn, _) = unsafe { connect(&server.display) };
    let expected: Vec<_> = [0xb3, 0xb2, 0xb1].map(|hwnd| backend.xid_for(hwnd).unwrap()).into();
    assert_eq!(unsafe { child_order(conn, backend.xid_for(0xb0).unwrap()) }, expected);
    unsafe { ffi::xcb_disconnect(conn); }
}

#[test]
fn reparented_top_levels_send_original_sibling_request_to_window_manager() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    create(&mut backend, 0xb1, 0);
    create(&mut backend, 0xb2, 0);
    let first = backend.xid_for(0xb1).unwrap();
    let second = backend.xid_for(0xb2).unwrap();
    let (conn, root) = unsafe { connect(&server.display) };
    for xid in [first, second] {
        unsafe {
            let frame = ffi::xcb_generate_id(conn);
            ffi::xcb_create_window(conn, 0, frame, root, 0, 0, 80, 60, 0,
                ffi::WINDOW_CLASS_INPUT_OUTPUT, 0, 0, ptr::null());
            ffi::xcb_reparent_window(conn, xid, frame, 0, 0);
        }
    }
    unsafe {
        ffi::xcb_change_window_attributes(conn, root, ffi::CW_EVENT_MASK, &ffi::SUBSTRUCTURE_NOTIFY);
        child_order(conn, root); // Round trip orders reparenting and event selection before backend request.
    }
    backend.position(0xb2, Some(0xb1), false).expect("top-level sibling request must reach window manager after reparenting");
    unsafe { child_order(conn, root); }
    let mut request = None;
    loop {
        let event = unsafe { ffi::xcb_poll_for_event(conn) };
        if event.is_null() { break; }
        let bytes = unsafe { std::slice::from_raw_parts(event.cast::<u8>(), 32) };
        if bytes[0] & 0x7f == CONFIGURE_REQUEST { request = Some(<[u8; 32]>::try_from(bytes).unwrap()); }
        unsafe { libc::free(event.cast()); }
    }
    let event = request.expect("successful submission must emit a configure request, not silently ignore stacking");
    let word = |at: usize| u32::from_ne_bytes(event[at..at + 4].try_into().unwrap());
    assert_eq!(event[0], CONFIGURE_REQUEST | 0x80);
    assert_eq!(event[1], ffi::STACK_BELOW as u8);
    assert_eq!((word(4), word(8), word(12)), (root, second, first));
    assert_eq!(u16::from_ne_bytes(event[26..28].try_into().unwrap()), ffi::CONFIGURE_SIBLING | ffi::CONFIGURE_STACK_MODE);
    unsafe { ffi::xcb_disconnect(conn); }
}

#[test]
fn server_destroyed_top_level_is_an_error_not_a_window_manager_request() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    create(&mut backend, 0xb1, 0);
    create(&mut backend, 0xb2, 0);
    let (conn, root) = unsafe { connect(&server.display) };
    unsafe {
        ffi::xcb_destroy_window(conn, backend.xid_for(0xb2).unwrap());
        child_order(conn, root);
    }
    assert!(matches!(backend.position(0xb2, Some(0xb1), false), Err(crate::BackendError::X11)));
    unsafe { ffi::xcb_disconnect(conn); }
}
