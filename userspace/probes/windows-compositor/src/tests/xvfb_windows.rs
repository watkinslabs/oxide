//! Every window owns its own surface, its own drawable and its own input:
//! a top level, an owned dialog and a child control, proved against a real
//! server rather than against this backend's own bookkeeping.

use std::os::unix::net::UnixStream;
use std::ptr;
use std::time::Duration;

use syscall::nt_compositor::{self as wire, Opcode};
use crate::ffi;
use crate::xvfb_harness::{ack, connect, rect, send, xvfb};
use crate::{Backend, BridgeCommand, BridgeEvent, InputEvent, Rect, StreamTransport};

/// Styles the invariant tests below name by hand.
const WS_CHILD: u32 = 0x4000_0000;
const WS_POPUP: u32 = 0x8000_0000;

/// One frame payload of a single colour covering the whole surface.
fn solid_frame(width: u32, height: u32, colour: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&width.to_le_bytes()); payload.extend_from_slice(&height.to_le_bytes());
    payload.extend_from_slice(&(width * 4).to_le_bytes()); payload.extend_from_slice(&wire::PIXEL_BGRA8888.to_le_bytes());
    payload.extend_from_slice(&wire::Damage { left: 0, top: 0, right: width as i32, bottom: height as i32 }.encode());
    for _ in 0..width * height { payload.extend_from_slice(&colour.to_le_bytes()); }
    payload
}

/// One pixel the server holds for a drawable, as its four stored bytes.
unsafe fn server_pixel(conn: *mut ffi::Connection, drawable: ffi::Window, x: i16, y: i16) -> [u8; 4] {
    let cookie = ffi::xcb_get_image(conn, ffi::IMAGE_FORMAT_Z_PIXMAP, drawable, x, y, 1, 1, u32::MAX);
    let mut error = ptr::null_mut();
    let reply = ffi::xcb_get_image_reply(conn, cookie, &mut error);
    assert!(!reply.is_null(), "the server refused to read back drawable {drawable:#x} at ({x},{y})");
    let len = ffi::xcb_get_image_data_length(reply) as usize;
    assert!(len >= 4);
    let data = std::slice::from_raw_parts(ffi::xcb_get_image_data(reply), len);
    let pixel = [data[0], data[1], data[2], data[3]];
    libc::free(reply as *mut _);
    pixel
}

/// The four stored bytes one BGRA colour is put on the display as.
fn stored(colour: u32) -> [u8; 4] { colour.to_le_bytes() }

/// Every window owns its own surface and its own destination drawable: a top
/// level, an owned dialog and a child control are three X windows, three
/// retained surfaces and three sets of pixels, and presenting to one of them
/// leaves the other two exactly as they were. Read back from the server, so a
/// change that let one window's frame reach another window's drawable fails
/// here rather than on a screen someone is watching.
#[test]
fn a_top_level_an_owned_dialog_and_a_child_control_never_share_a_surface_or_a_drawable() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    backend.seed_test_ewmh();
    let (mut peer, bridge) = UnixStream::pair().unwrap();
    let mut transport = StreamTransport::from_stream(bridge).unwrap();
    let (top, dialog, control) = (0xa1u64, 0xa2u64, 0xa3u64);
    const TOP: u32 = 0x0011_2233;
    const DIALOG: u32 = 0x0044_5566;
    const CONTROL: u32 = 0x0077_8899;

    let create = |x: i32, y: i32, w: u32, h: u32, parent: u64, style: u32| {
        let mut payload = rect(x, y, w, h);
        payload.extend_from_slice(&parent.to_le_bytes());
        payload.extend_from_slice(&style.to_le_bytes()); payload.extend_from_slice(&0u32.to_le_bytes());
        payload
    };
    send(&mut peer, Opcode::Create, 1, top, create(0, 0, 64, 64, 0, 0)); ack(&mut peer, &mut backend, &mut transport, 1);
    // The dialog is owned by the top level and is a top-level X window of its
    // own, placed clear of it so a readback names its pixels and nobody else's.
    send(&mut peer, Opcode::Create, 2, dialog, create(120, 0, 60, 50, top, WS_POPUP)); ack(&mut peer, &mut backend, &mut transport, 2);
    // The control is a real X child inside the top level's own window.
    send(&mut peer, Opcode::Create, 3, control, create(4, 4, 24, 20, top, WS_CHILD)); ack(&mut peer, &mut backend, &mut transport, 3);
    for (sequence, hwnd) in [(4u64, top), (5, dialog), (6, control)] {
        send(&mut peer, Opcode::Visibility, sequence, hwnd, 1u32.to_le_bytes().to_vec());
        ack(&mut peer, &mut backend, &mut transport, sequence);
    }

    let (top_xid, dialog_xid, control_xid) = (backend.xid_for(top as u32).unwrap(), backend.xid_for(dialog as u32).unwrap(), backend.xid_for(control as u32).unwrap());
    assert_ne!(top_xid, dialog_xid); assert_ne!(top_xid, control_xid); assert_ne!(dialog_xid, control_xid);
    let (conn, root) = unsafe { connect(&server.display) };
    // The dialog is its own top-level surface naming its owner; the control is
    // a child of the window it belongs to. Neither draws through the top level.
    assert_eq!(backend.parent_xid_for(dialog as u32), Some(root));
    assert_eq!(backend.transient_xid_for(dialog as u32), Some(top_xid));
    assert_eq!(backend.parent_xid_for(control as u32), Some(top_xid));

    send(&mut peer, Opcode::Frame, 7, top, solid_frame(64, 64, TOP)); ack(&mut peer, &mut backend, &mut transport, 7);
    // A point of the top level no child covers.
    assert_eq!(unsafe { server_pixel(conn, top_xid, 40, 40) }, stored(TOP));

    send(&mut peer, Opcode::Frame, 8, control, solid_frame(24, 20, CONTROL)); ack(&mut peer, &mut backend, &mut transport, 8);
    assert_eq!(unsafe { server_pixel(conn, control_xid, 2, 2) }, stored(CONTROL));
    assert_eq!(unsafe { server_pixel(conn, top_xid, 40, 40) }, stored(TOP));

    send(&mut peer, Opcode::Frame, 9, dialog, solid_frame(60, 50, DIALOG)); ack(&mut peer, &mut backend, &mut transport, 9);
    assert_eq!(unsafe { server_pixel(conn, dialog_xid, 30, 25) }, stored(DIALOG));
    assert_eq!(unsafe { server_pixel(conn, control_xid, 2, 2) }, stored(CONTROL));
    assert_eq!(unsafe { server_pixel(conn, top_xid, 40, 40) }, stored(TOP));

    // Destroying the owner takes its child's record with it, because the
    // server destroys the child window along with its parent: a record left
    // behind names a window that no longer exists and refuses the next
    // creation that draws the same handle.
    send(&mut peer, Opcode::Destroy, 10, top, Vec::new()); ack(&mut peer, &mut backend, &mut transport, 10);
    assert!(backend.xid_for(top as u32).is_none());
    assert!(backend.xid_for(control as u32).is_none());
    assert_eq!(backend.xid_for(dialog as u32), Some(dialog_xid));
    unsafe { ffi::xcb_disconnect(conn); }
}

/// A press on a control is delivered by the server to the control's own X
/// window, and every layer above the bridge names windows by HWND: the bridge
/// answers with the control's handle and the point in the control's own
/// coordinates. A press that arrived as the dialog's handle, or that carried
/// the parent's coordinates, leaves every control dead.
#[test]
fn a_button_press_on_a_child_control_arrives_as_the_controls_hwnd_and_point() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    backend.seed_test_ewmh();
    let (parent, control) = (0xb1u32, 0xb2u32);
    backend.handle_command(BridgeCommand::Create { hwnd: parent, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 80, bottom: 60 }, parent: 0, style: 0, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: control, title: Vec::new(), rect: Rect { left: 5, top: 6, right: 45, bottom: 26 }, parent: parent as u64, style: WS_CHILD, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Show { hwnd: parent }).unwrap();
    backend.handle_command(BridgeCommand::Show { hwnd: control }).unwrap();
    let control_xid = backend.xid_for(control).unwrap();
    assert_ne!(Some(control_xid), backend.xid_for(parent));

    let (conn, root) = unsafe { connect(&server.display) };
    let mut event = [0u8; 32];
    event[0] = ffi::BUTTON_PRESS; event[1] = 1;
    event[8..12].copy_from_slice(&root.to_ne_bytes());
    event[12..16].copy_from_slice(&control_xid.to_ne_bytes());
    event[24..26].copy_from_slice(&3i16.to_ne_bytes()); event[26..28].copy_from_slice(&4i16.to_ne_bytes());
    unsafe { ffi::xcb_send_event(conn, 0, control_xid, ffi::EVENT_BUTTON_PRESS, event.as_ptr() as *const libc::c_char); ffi::xcb_flush(conn); }

    // Mapping the two windows produces its own notifications; the press is
    // what this test waits for, not whatever the server says first.
    let mut seen = None;
    for _ in 0..400 {
        match backend.poll_event() {
            Some(event @ BridgeEvent::Input(InputEvent::Pointer { .. })) => { seen = Some(event); break; }
            Some(_) => continue,
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    match seen {
        Some(BridgeEvent::Input(InputEvent::Pointer { hwnd, x, y, buttons, .. })) => {
            assert_eq!(hwnd, control);
            assert_eq!((x, y), (3, 4));
            assert_eq!(buttons, crate::pointer::MK_LBUTTON);
        }
        other => panic!("a press on the control's own window did not reach the control: {other:?}"),
    }
    unsafe { ffi::xcb_disconnect(conn); }
}
