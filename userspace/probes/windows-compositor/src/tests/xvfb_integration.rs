//! Non-GNOME acceptance: private Xvfb catches XCB ABI, protocol and blit errors.

use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::Duration;

use syscall::nt_compositor::{self as wire, Opcode, Record};
use crate::ffi;
use crate::{Backend, BridgeCommand, BridgeEvent, InputEvent, Rect, StreamTransport};

struct Xvfb { child: Child, display: String }
impl Drop for Xvfb { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }

fn xvfb() -> Xvfb {
    let mut child = Command::new("Xvfb").args(["-displayfd", "1", "-screen", "0", "320x240x24", "-nolisten", "tcp"])
        .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb is required for non-GNOME compositor integration");
    let mut line = String::new(); BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    Xvfb { child, display: format!(":{}", line.trim()) }
}

unsafe fn connect(display: &str) -> (*mut ffi::Connection, ffi::Window) {
    let name = CString::new(display).unwrap(); let mut screen = 0; let conn = ffi::xcb_connect(name.as_ptr(), &mut screen);
    assert!(!conn.is_null() && ffi::xcb_connection_has_error(conn) == 0);
    let mut it = ffi::xcb_setup_roots_iterator(ffi::xcb_get_setup(conn)); for _ in 0..screen { ffi::xcb_screen_next(&mut it); }
    (conn, (*it.data).root)
}

unsafe fn override_redirect(conn: *mut ffi::Connection, window: ffi::Window) -> bool {
    let cookie = ffi::xcb_get_window_attributes(conn, window); let mut err = ptr::null_mut();
    let reply = ffi::xcb_get_window_attributes_reply(conn, cookie, &mut err); assert!(!reply.is_null());
    let value = (*reply).override_redirect != 0; libc::free(reply as *mut _); value
}

unsafe fn child_order(conn: *mut ffi::Connection, parent: ffi::Window) -> Vec<ffi::Window> {
    let cookie = ffi::xcb_query_tree(conn, parent); let mut err = ptr::null_mut(); let reply = ffi::xcb_query_tree_reply(conn, cookie, &mut err); assert!(!reply.is_null());
    let count = ffi::xcb_query_tree_children_length(reply); let children = std::slice::from_raw_parts(ffi::xcb_query_tree_children(reply), count as usize).to_vec(); libc::free(reply as *mut _); children
}

fn send(peer: &mut UnixStream, opcode: Opcode, seq: u64, hwnd: u64, payload: Vec<u8>) { peer.write_all(&Record::new(opcode, seq, hwnd, payload).unwrap().encode().unwrap()).unwrap(); }
fn position(peer: &mut UnixStream, backend: &mut Backend, transport: &mut StreamTransport, seq: u64, hwnd: u64, after: u64, flags: u32) { let mut payload = Vec::new(); payload.extend_from_slice(&after.to_le_bytes()); payload.extend_from_slice(&flags.to_le_bytes()); payload.extend_from_slice(&0u32.to_le_bytes()); send(peer, Opcode::Position, seq, hwnd, payload); ack(peer, backend, transport, seq); }
fn rect(x: i32, y: i32, w: u32, h: u32) -> Vec<u8> { wire::Rect { x, y, width: w, height: h }.encode().unwrap().to_vec() }
fn ack(peer: &mut UnixStream, backend: &mut Backend, transport: &mut StreamTransport, seq: u64) {
    for _ in 0..100 {
        let _ = backend.run_once(transport);
        let mut header = [0u8; wire::HEADER_LEN]; if peer.set_read_timeout(Some(Duration::from_millis(5))).is_ok() && peer.read_exact(&mut header).is_ok() {
            let header = wire::Header::decode(&header).unwrap(); let mut payload = vec![0u8; header.length as usize]; peer.read_exact(&mut payload).unwrap();
            if header.opcode == Opcode::Ack && header.sequence == seq { assert_eq!(wire::u32_at(&payload, 0).unwrap(), 0); return; }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("protocol ACK timeout for sequence {seq}");
}

#[test]
fn xvfb_protocol_window_frame_and_server_pixels_non_gnome() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    backend.seed_test_ewmh();
    let snapshot = backend.monitor_snapshot().unwrap(); assert_eq!(snapshot.monitor.right, 320); assert_eq!(snapshot.monitor.bottom, 240); assert_eq!(snapshot.work_area.bottom, 220);
    let (mut peer, bridge) = UnixStream::pair().unwrap(); let mut transport = StreamTransport::from_stream(bridge).unwrap();
    // 128x128 is larger than the conservative 64 KiB XCB tile budget while
    // remaining below the local Unix socket's write-buffer threshold.
    const FRAME_EDGE: u32 = 128;
    let hwnd = 0x51u64; let mut create = rect(0, 0, FRAME_EDGE, FRAME_EDGE); create.extend_from_slice(&0u64.to_le_bytes()); create.extend_from_slice(&0u32.to_le_bytes()); create.extend_from_slice(&0u32.to_le_bytes()); send(&mut peer, Opcode::Create, 1, hwnd, create); ack(&mut peer, &mut backend, &mut transport, 1);
    send(&mut peer, Opcode::Title, 2, hwnd, b"Xvfb Notepad".to_vec()); ack(&mut peer, &mut backend, &mut transport, 2);
    let pixels = vec![0x00112233u32; (FRAME_EDGE * FRAME_EDGE) as usize]; let mut frame = Vec::new(); frame.extend_from_slice(&FRAME_EDGE.to_le_bytes()); frame.extend_from_slice(&FRAME_EDGE.to_le_bytes()); frame.extend_from_slice(&(FRAME_EDGE * 4).to_le_bytes()); frame.extend_from_slice(&wire::PIXEL_BGRA8888.to_le_bytes()); frame.extend_from_slice(&wire::Damage { left: 0, top: 0, right: FRAME_EDGE as i32, bottom: FRAME_EDGE as i32 }.encode()); for pixel in pixels { frame.extend_from_slice(&pixel.to_le_bytes()); } send(&mut peer, Opcode::Frame, 3, hwnd, frame); ack(&mut peer, &mut backend, &mut transport, 3);
    assert!(backend.xid_for(hwnd as u32).is_some()); send(&mut peer, Opcode::Visibility, 4, hwnd, 1u32.to_le_bytes().to_vec()); ack(&mut peer, &mut backend, &mut transport, 4);
    // Show's checked retained-frame replay completes before ACK; capture must
    // not depend on speculative nonblocking Expose polls.
    let xid = backend.xid_for(hwnd as u32).unwrap(); let (conn, _) = unsafe { connect(&server.display) }; let cookie = unsafe { ffi::xcb_get_image(conn, ffi::IMAGE_FORMAT_Z_PIXMAP, xid, 0, 0, 4, 4, u32::MAX) }; let mut err = ptr::null_mut(); let reply = unsafe { ffi::xcb_get_image_reply(conn, cookie, &mut err) }; assert!(!reply.is_null()); let len = unsafe { ffi::xcb_get_image_data_length(reply) }; let data = unsafe { std::slice::from_raw_parts(ffi::xcb_get_image_data(reply), len as usize) }; assert!(data.len() >= 4); assert_eq!(&data[..4], &[0x33, 0x22, 0x11, 0x00]); unsafe { libc::free(reply as *mut _); ffi::xcb_disconnect(conn); }
    let parent_xid = xid; backend.handle_command(BridgeCommand::Create { hwnd: 0x52, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 0, bottom: 0 }, parent: hwnd, style: 0x5000_0000, ex_style: 0 }).unwrap(); assert_eq!(backend.parent_xid_for(0x52), Some(parent_xid)); assert_eq!(backend.window_layout_for_test(0x52), Some((true, 0, 0))); backend.handle_command(BridgeCommand::Show { hwnd: 0x52 }).unwrap(); backend.handle_command(BridgeCommand::Configure { hwnd: 0x52, rect: Rect { left: 2, top: 3, right: 12, bottom: 13 } }).unwrap(); assert_eq!(backend.window_layout_for_test(0x52), Some((true, 10, 10)));
    backend.handle_command(BridgeCommand::Create { hwnd: 0x53, title: Vec::new(), rect: Rect { left: 15, top: 3, right: 25, bottom: 13 }, parent: hwnd, style: 0x4000_0000, ex_style: 0 }).unwrap(); backend.handle_command(BridgeCommand::Show { hwnd: 0x53 }).unwrap();
    let (order_conn, _) = unsafe { connect(&server.display) }; let child_a = backend.xid_for(0x52).unwrap(); let child_b = backend.xid_for(0x53).unwrap();
    position(&mut peer, &mut backend, &mut transport, 7, 0x52, 1, wire::POSITION_ORDER); let order = unsafe { child_order(order_conn, parent_xid) }; assert_eq!(order.last().copied(), Some(child_b)); assert_eq!(order.first().copied(), Some(child_a));
    position(&mut peer, &mut backend, &mut transport, 8, 0x52, 0, wire::POSITION_ORDER); let order = unsafe { child_order(order_conn, parent_xid) }; assert_eq!(order.last().copied(), Some(child_a));
    position(&mut peer, &mut backend, &mut transport, 9, 0x53, 0x52, wire::POSITION_ORDER); let order = unsafe { child_order(order_conn, parent_xid) }; assert_eq!(order, vec![child_a, child_b]);
    position(&mut peer, &mut backend, &mut transport, 10, hwnd, 0, wire::POSITION_ACTIVATE); unsafe { ffi::xcb_disconnect(order_conn); }
    send(&mut peer, Opcode::Geometry, 5, hwnd, rect(10, 12, 4, 4)); ack(&mut peer, &mut backend, &mut transport, 5); send(&mut peer, Opcode::Destroy, 6, hwnd, Vec::new()); ack(&mut peer, &mut backend, &mut transport, 6); assert!(backend.xid_for(hwnd as u32).is_none());
}

#[test]
fn popup_style_wins_over_child_and_retains_owner_transient() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    backend.seed_test_ewmh();
    let parent = 0x81;
    let popup = 0x82;
    backend.handle_command(BridgeCommand::Create { hwnd: parent, title: Vec::new(), rect: Rect { left: 20, top: 20, right: 100, bottom: 80 }, parent: 0, style: 0, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: popup, title: Vec::new(), rect: Rect { left: 4, top: 5, right: 44, bottom: 25 }, parent: parent as u64, style: 0xc000_0000, ex_style: 0 }).unwrap();

    let (conn, root) = unsafe { connect(&server.display) };
    assert_eq!(backend.parent_xid_for(popup), Some(root));
    assert_eq!(backend.transient_xid_for(popup), backend.xid_for(parent));
    unsafe { ffi::xcb_disconnect(conn); }
}

#[test]
fn xvfb_position_wire_controls_server_stack_order() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let (mut peer, bridge) = UnixStream::pair().unwrap(); let mut transport = StreamTransport::from_stream(bridge).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: 0x71, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 80, bottom: 80 }, parent: 0, style: 0, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: 0x72, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 10, bottom: 10 }, parent: 0x71, style: 0x4000_0000, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: 0x73, title: Vec::new(), rect: Rect { left: 10, top: 0, right: 20, bottom: 10 }, parent: 0x71, style: 0x4000_0000, ex_style: 0 }).unwrap();
    let (conn, _) = unsafe { connect(&server.display) }; let parent = backend.xid_for(0x71).unwrap(); let first = backend.xid_for(0x72).unwrap(); let second = backend.xid_for(0x73).unwrap();
    position(&mut peer, &mut backend, &mut transport, 1, 0x72, 1, wire::POSITION_ORDER); let order = unsafe { child_order(conn, parent) }; assert_eq!(order.first().copied(), Some(first)); assert_eq!(order.last().copied(), Some(second));
    position(&mut peer, &mut backend, &mut transport, 2, 0x72, 0, wire::POSITION_ORDER); let order = unsafe { child_order(conn, parent) }; assert_eq!(order.last().copied(), Some(first));
    unsafe { ffi::xcb_disconnect(conn); }
}

#[test]
fn xvfb_xkb_layout_modifiers_reach_vk_text_wire() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let hwnd = 0x61;
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 80, bottom: 40 }, parent: 0, style: 0, ex_style: 0 }).unwrap();
    let press_shift = backend.map_input_for_test(InputEvent::Key { hwnd, press: true, virtual_key: 0, scan_code: 50, modifiers: 0 }).unwrap();
    let shifted_one = backend.map_input_for_test(InputEvent::Key { hwnd, press: true, virtual_key: 0, scan_code: 10, modifiers: 0 }).unwrap();
    assert_eq!(backend.pending_event_for_test(), Some(BridgeEvent::Input(InputEvent::Text { hwnd, utf8: b"!".to_vec() })));
    if let BridgeEvent::Input(InputEvent::Key { virtual_key, .. }) = shifted_one { assert_eq!(virtual_key, 0x31); } else { panic!("shifted digit did not produce key event"); }
    assert!(crate::protocol::encode_event(&press_shift, 1).is_ok());
    let _ = backend.map_input_for_test(InputEvent::Key { hwnd, press: false, virtual_key: 0, scan_code: 10, modifiers: 0 });
    let _ = backend.map_input_for_test(InputEvent::Key { hwnd, press: false, virtual_key: 0, scan_code: 50, modifiers: 0 });
    let _ = backend.map_input_for_test(InputEvent::Key { hwnd, press: true, virtual_key: 0, scan_code: 37, modifiers: 0 });
    let ctrl_a = backend.map_input_for_test(InputEvent::Key { hwnd, press: true, virtual_key: 0, scan_code: 38, modifiers: 0 }).unwrap();
    assert_eq!(backend.pending_event_for_test(), Some(BridgeEvent::Input(InputEvent::Text { hwnd, utf8: vec![1] })));
    if let BridgeEvent::Input(InputEvent::Key { virtual_key, .. }) = ctrl_a { assert_eq!(virtual_key, 0x41); } else { panic!("Ctrl+A did not produce key event"); }
}

// 31gd desktop geometry: actual X11 properties, no WM identity or session-name prerequisite.
#[test]
fn xvfb_workarea_uses_generic_properties_without_window_manager_identity() {
    let server = xvfb();let backend = Backend::connect(Some(&server.display)).unwrap();
    // Measured on the target desktop: GNOME's XWayland publishes neither
    // property, and requiring them made the bridge time out with no diagnostic.
    // X's own answer with no window manager work area is the whole screen, and
    // a later property change replaces it with a real one.
    let bare=backend.monitor_snapshot().expect("a bare X11 screen still has geometry");
    assert_eq!(bare.work_area,Rect{left:0,top:0,right:320,bottom:240});
    assert_eq!(bare.monitor,bare.work_area);
    assert_eq!(bare.desktop,0);
    let (conn,root) = unsafe { connect(&server.display) };
    let atom = |name:&str| unsafe {
        let name=CString::new(name).unwrap();let cookie=ffi::xcb_intern_atom(conn,0,name.as_bytes().len() as u16,name.as_ptr());
        let mut error=ptr::null_mut();let reply=ffi::xcb_intern_atom_reply(conn,cookie,&mut error);assert!(error.is_null()&&!reply.is_null());
        let atom=(*reply).atom;libc::free(reply as *mut _);atom
    };
    let current=atom("_NET_CURRENT_DESKTOP");let workarea=atom("_NET_WORKAREA");
    let set = |property,values:&[u32]| unsafe {
        ffi::xcb_change_property(conn,ffi::PROP_MODE_REPLACE,root,property,ffi::ATOM_CARDINAL,32,values.len() as u32,values.as_ptr() as *const _);
        // A reply on the publishing connection establishes ordering before the backend reads.
        let cookie=ffi::xcb_get_property(conn,0,root,property,ffi::ATOM_CARDINAL,0,values.len() as u32);
        let mut error=ptr::null_mut();let reply=ffi::xcb_get_property_reply(conn,cookie,&mut error);assert!(error.is_null()&&!reply.is_null());libc::free(reply as *mut _);
    };
    set(current,&[0]);assert_eq!(backend.monitor_snapshot().unwrap().work_area,Rect{left:0,top:0,right:320,bottom:240});
    set(workarea,&[7,11,300,200]);
    let snapshot=backend.monitor_snapshot().unwrap();assert_eq!(snapshot.desktop,0);
    assert_eq!(snapshot.monitor,Rect{left:0,top:0,right:320,bottom:240});
    assert_eq!(snapshot.work_area,Rect{left:7,top:11,right:307,bottom:211});
    set(workarea,&[0,0,320]);assert_eq!(backend.monitor_snapshot(),None,"malformed workarea cannot fall back to screen geometry");
    set(workarea,&[0,0,320,230]);assert_eq!(backend.monitor_snapshot().unwrap().work_area.bottom,230);
    unsafe { ffi::xcb_disconnect(conn); }
}

// 31fn desktop input routing: an X event names an X window, and every layer
// above the bridge names an HWND. Feeding map_input an HWND directly, as the
// keyboard test does, cannot observe that translation; only a real event
// delivered by the server can.
#[test]
fn xvfb_desktop_input_events_carry_the_hwnd_not_the_x_window() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let hwnd = 0x91u32;
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 120, bottom: 90 }, parent: 0, style: 0x1000_0000, ex_style: 0 }).unwrap();
    let xid = backend.xid_for(hwnd).unwrap();
    assert_ne!(xid, hwnd, "the test is meaningless unless the X window id differs from the HWND");
    let (conn, _) = unsafe { connect(&server.display) };
    let send_raw = |bytes: &[u8; 32], mask: u32| unsafe { ffi::xcb_send_event(conn, 0, xid, mask, bytes.as_ptr() as *const _); ffi::xcb_flush(conn); };

    let mut button = [0u8; 32];
    button[0] = ffi::BUTTON_PRESS; button[1] = 1;
    button[8..12].copy_from_slice(&xid.to_ne_bytes()); button[12..16].copy_from_slice(&xid.to_ne_bytes());
    button[24..26].copy_from_slice(&30i16.to_ne_bytes()); button[26..28].copy_from_slice(&40i16.to_ne_bytes());
    send_raw(&button, ffi::EVENT_BUTTON_PRESS);

    let mut motion = [0u8; 32];
    motion[0] = ffi::MOTION_NOTIFY;
    motion[8..12].copy_from_slice(&xid.to_ne_bytes()); motion[12..16].copy_from_slice(&xid.to_ne_bytes());
    motion[24..26].copy_from_slice(&31i16.to_ne_bytes()); motion[26..28].copy_from_slice(&41i16.to_ne_bytes());
    send_raw(&motion, ffi::EVENT_POINTER_MOTION);

    let mut focus = [0u8; 32];
    focus[0] = ffi::FOCUS_IN;
    focus[4..8].copy_from_slice(&xid.to_ne_bytes());
    send_raw(&focus, ffi::EVENT_FOCUS_CHANGE);

    let mut seen = Vec::new();
    for _ in 0..500 {
        while let Some(event) = backend.poll_event() { seen.push(event); }
        if seen.len() >= 3 { break; }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(seen.contains(&BridgeEvent::Input(InputEvent::Pointer { hwnd, x: 30, y: 40, buttons: crate::pointer::MK_LBUTTON, wheel: 0, hwheel: 0 })), "button event did not reach the bridge as an HWND: {seen:?}");
    assert!(seen.contains(&BridgeEvent::Input(InputEvent::Pointer { hwnd, x: 31, y: 41, buttons: 0, wheel: 0, hwheel: 0 })), "motion event did not reach the bridge as an HWND: {seen:?}");
    assert!(seen.contains(&BridgeEvent::Input(InputEvent::Focus { hwnd, focused: true })), "focus event did not reach the bridge as an HWND: {seen:?}");
    // An event on a window this bridge does not own is dropped, not forwarded
    // with a foreign identifier the GUI owner would have to reject.
    let (other, root) = unsafe { connect(&server.display) };
    unsafe { ffi::xcb_disconnect(other); }
    let mut stray = button; stray[8..12].copy_from_slice(&root.to_ne_bytes()); stray[12..16].copy_from_slice(&root.to_ne_bytes());
    unsafe { ffi::xcb_send_event(conn, 0, xid, ffi::EVENT_BUTTON_PRESS, stray.as_ptr() as *const _); ffi::xcb_flush(conn); }
    for _ in 0..50 { assert_eq!(backend.poll_event(), None, "an event naming a foreign X window must not become a window event"); std::thread::sleep(Duration::from_millis(1)); }
    unsafe { ffi::xcb_disconnect(conn); }
}

// 31gd geometry under a decorating window manager: the desktop reparents a
// top-level window into a frame, after which a real ConfigureNotify reports a
// position inside that frame rather than a position on the screen.
#[test]
fn xvfb_configure_under_a_reparenting_window_manager_reports_screen_position() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let hwnd = 0xa1u32;
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 60, bottom: 40 }, parent: 0, style: 0x1000_0000, ex_style: 0 }).unwrap();
    let xid = backend.xid_for(hwnd).unwrap();
    let (conn, root) = unsafe { connect(&server.display) };
    let frame = unsafe { ffi::xcb_generate_id(conn) };
    unsafe {
        ffi::xcb_create_window(conn, 0, frame, root, 40, 50, 100, 80, 0, ffi::WINDOW_CLASS_INPUT_OUTPUT, 0, 0, ptr::null());
        ffi::xcb_map_window(conn, frame);
        ffi::xcb_reparent_window(conn, xid, frame, 0, 0);
        let values = [3u32, 4];
        ffi::xcb_configure_window(conn, xid, ffi::CONFIGURE_X | ffi::CONFIGURE_Y, values.as_ptr());
        ffi::xcb_flush(conn);
    }
    let mut configure = None;
    for _ in 0..500 {
        while let Some(event) = backend.poll_event() { if let BridgeEvent::Configure { hwnd: id, rect } = event { assert_eq!(id, hwnd); configure = Some(rect); } }
        if configure.is_some_and(|rect: Rect| rect.left != 0 || rect.top != 0) { break; }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(configure, Some(Rect { left: 43, top: 54, right: 103, bottom: 94 }), "a reparented window's configure must name its screen position");
    unsafe { ffi::xcb_disconnect(conn); }
}

// 31gd geometry of a child: a child window's canonical rect is stated in its
// parent's client coordinates, and its own ConfigureNotify already reports
// exactly that. Translating it to the screen would offset every child by
// wherever its top level happens to sit, which is what pushed Notepad's edit
// control out of its own client area.
#[test]
fn xvfb_configure_of_a_child_stays_in_its_parents_coordinates() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let top = 0xb1u32; let child = 0xb2u32;
    backend.handle_command(BridgeCommand::Create { hwnd: top, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 120, bottom: 90 }, parent: 0, style: 0x1000_0000, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Create { hwnd: child, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 100, bottom: 70 }, parent: top as u64, style: 0x5000_0000, ex_style: 0 }).unwrap();
    // Put the top level away from the origin so a screen position and a
    // parent-relative one cannot be the same number.
    backend.handle_command(BridgeCommand::Configure { hwnd: top, rect: Rect { left: 37, top: 29, right: 157, bottom: 119 } }).unwrap();
    backend.handle_command(BridgeCommand::Configure { hwnd: child, rect: Rect { left: 5, top: 7, right: 95, bottom: 67 } }).unwrap();
    let mut configure = None;
    for _ in 0..500 {
        while let Some(event) = backend.poll_event() { if let BridgeEvent::Configure { hwnd: id, rect } = event { if id == child { configure = Some(rect); } } }
        if configure.is_some() { break; }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(configure, Some(Rect { left: 5, top: 7, right: 95, bottom: 67 }), "a child's configure must stay in its parent's coordinates");
}

// 31fn: what leaves the bridge for a click and a wheel notch is a Win32 button
// mask and a wheel axis, not the X modifier state and button number.
#[test]
fn xvfb_pointer_wire_carries_win32_buttons_and_wheel_not_x11_state() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let hwnd = 0xb1u32;
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(), rect: Rect { left: 0, top: 0, right: 60, bottom: 40 }, parent: 0, style: 0x1000_0000, ex_style: 0 }).unwrap();
    let xid = backend.xid_for(hwnd).unwrap();
    let (conn, _) = unsafe { connect(&server.display) };
    // X reports the state that preceded the event: a press is not yet held,
    // and a release still is.
    const X_SHIFT: u16 = 1;
    const X_BUTTON1: u16 = 1 << 8;
    let mut send_button = |press: bool, button: u8, state: u16| {
        let mut event = [0u8; 32];
        event[0] = if press { ffi::BUTTON_PRESS } else { ffi::BUTTON_RELEASE }; event[1] = button;
        event[8..12].copy_from_slice(&xid.to_ne_bytes()); event[12..16].copy_from_slice(&xid.to_ne_bytes());
        event[24..26].copy_from_slice(&5i16.to_ne_bytes()); event[26..28].copy_from_slice(&6i16.to_ne_bytes());
        event[28..30].copy_from_slice(&state.to_ne_bytes());
        unsafe { ffi::xcb_send_event(conn, 0, xid, if press { ffi::EVENT_BUTTON_PRESS } else { ffi::EVENT_BUTTON_RELEASE }, event.as_ptr() as *const _); ffi::xcb_flush(conn); }
    };
    send_button(true, 1, X_SHIFT);
    send_button(false, 1, X_SHIFT | X_BUTTON1);
    send_button(true, 5, 0);
    send_button(false, 5, 0);
    send_button(true, 7, 0);

    let mut seen = Vec::new();
    for _ in 0..500 {
        while let Some(event) = backend.poll_event() { seen.push(event); }
        if seen.len() >= 4 { break; }
        std::thread::sleep(Duration::from_millis(2));
    }
    let pointer = |buttons, wheel, hwheel| BridgeEvent::Input(InputEvent::Pointer { hwnd, x: 5, y: 6, buttons, wheel, hwheel });
    assert_eq!(seen, vec![
        pointer(crate::pointer::MK_LBUTTON | crate::pointer::MK_SHIFT, 0, 0),
        pointer(crate::pointer::MK_SHIFT, 0, 0),
        pointer(0, -crate::pointer::WHEEL_DELTA, 0),
        pointer(0, 0, crate::pointer::WHEEL_DELTA),
    ], "the wheel's release is not a second notch and the X state is not the Win32 mask");
    // Every one of these encodes; the raw X form never reaches the wire.
    for event in &seen { assert!(crate::protocol::encode_event(event, 1).is_ok()); }
    assert!(crate::protocol::encode_event(&BridgeEvent::Input(InputEvent::Button { hwnd, press: true, button: 1, x: 0, y: 0, state: X_BUTTON1 }), 1).is_err());
    unsafe { ffi::xcb_disconnect(conn); }
}

/// The server itself is asked what it holds: a dropdown menu is a bare popup,
/// which the window manager does not manage, so its window is override-redirect
/// and no desktop frame, placement or focus grab can reach it. The application's
/// own captioned window stays managed alongside it.
#[test]
fn xvfb_a_bare_popup_is_override_redirect_and_a_captioned_window_is_not() {
    use crate::styles::{WS_CAPTION, WS_CHILD, WS_POPUP, WS_SYSMENU, WS_VISIBLE};
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let create = |backend: &mut Backend, hwnd: u32, parent: u64, style: u32| {
        backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(), rect: Rect { left: 4, top: 5, right: 44, bottom: 25 }, parent, style, ex_style: 0 }).unwrap();
    };
    let frame = 0x91; let menu = 0x92; let dialog = 0x93; let child = 0x94; let owned = 0x95;
    create(&mut backend, frame, 0, WS_CAPTION | WS_SYSMENU | WS_VISIBLE);
    create(&mut backend, menu, frame as u64, WS_POPUP | WS_VISIBLE);
    create(&mut backend, dialog, frame as u64, WS_POPUP | WS_CAPTION | WS_VISIBLE);
    create(&mut backend, child, frame as u64, WS_CHILD | WS_VISIBLE);
    create(&mut backend, owned, frame as u64, WS_CAPTION | WS_VISIBLE);

    let (conn, _) = unsafe { connect(&server.display) };
    let attribute = |hwnd: u32| unsafe { override_redirect(conn, backend.xid_for(hwnd).unwrap()) };
    assert!(!attribute(frame), "a captioned application window is managed");
    assert!(attribute(menu), "a bare popup menu must be override-redirect");
    assert!(!attribute(dialog), "a captioned popup is still managed");
    // A child window is not the window manager's either.
    assert!(attribute(child));
    // The owner still travels as WM_TRANSIENT_FOR for the windows that are
    // parented to it in the window-manager sense.
    assert_eq!(backend.transient_xid_for(menu), backend.xid_for(frame));
    assert_eq!(backend.transient_xid_for(dialog), backend.xid_for(frame));
    // An owned window names its owner whether or not it is a popup.
    assert_eq!(backend.transient_xid_for(owned), backend.xid_for(frame));
    assert_eq!(backend.transient_xid_for(frame), None);
    unsafe { ffi::xcb_disconnect(conn); }
}
