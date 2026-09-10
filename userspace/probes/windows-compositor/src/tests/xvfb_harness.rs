//! Shared Xvfb harness: a private server, a second connection to read it back,
//! and the bridge-protocol send/ack pair every window test is written against.

use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::Duration;

use syscall::nt_compositor::{self as wire, Opcode, Record};
use crate::ffi;
use crate::{Backend, StreamTransport};

pub(crate) struct Xvfb { child: Child, pub(crate) display: String }
impl Drop for Xvfb { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }

pub(crate) fn xvfb() -> Xvfb {
    let mut child = Command::new("Xvfb").args(["-displayfd", "1", "-screen", "0", "320x240x24", "-nolisten", "tcp"])
        .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb is required for non-GNOME compositor integration");
    let mut line = String::new(); BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    Xvfb { child, display: format!(":{}", line.trim()) }
}

pub(crate) unsafe fn connect(display: &str) -> (*mut ffi::Connection, ffi::Window) {
    let name = CString::new(display).unwrap(); let mut screen = 0; let conn = ffi::xcb_connect(name.as_ptr(), &mut screen);
    assert!(!conn.is_null() && ffi::xcb_connection_has_error(conn) == 0);
    let mut it = ffi::xcb_setup_roots_iterator(ffi::xcb_get_setup(conn)); for _ in 0..screen { ffi::xcb_screen_next(&mut it); }
    (conn, (*it.data).root)
}

pub(crate) unsafe fn override_redirect(conn: *mut ffi::Connection, window: ffi::Window) -> bool {
    let cookie = ffi::xcb_get_window_attributes(conn, window); let mut err = ptr::null_mut();
    let reply = ffi::xcb_get_window_attributes_reply(conn, cookie, &mut err); assert!(!reply.is_null());
    let value = (*reply).override_redirect != 0; libc::free(reply as *mut _); value
}

pub(crate) unsafe fn child_order(conn: *mut ffi::Connection, parent: ffi::Window) -> Vec<ffi::Window> {
    let cookie = ffi::xcb_query_tree(conn, parent); let mut err = ptr::null_mut(); let reply = ffi::xcb_query_tree_reply(conn, cookie, &mut err); assert!(!reply.is_null());
    let count = ffi::xcb_query_tree_children_length(reply); let children = std::slice::from_raw_parts(ffi::xcb_query_tree_children(reply), count as usize).to_vec(); libc::free(reply as *mut _); children
}

pub(crate) fn send(peer: &mut UnixStream, opcode: Opcode, seq: u64, hwnd: u64, payload: Vec<u8>) { peer.write_all(&Record::new(opcode, seq, hwnd, payload).unwrap().encode().unwrap()).unwrap(); }
pub(crate) fn position(peer: &mut UnixStream, backend: &mut Backend, transport: &mut StreamTransport, seq: u64, hwnd: u64, after: u64, flags: u32) { let mut payload = Vec::new(); payload.extend_from_slice(&after.to_le_bytes()); payload.extend_from_slice(&flags.to_le_bytes()); payload.extend_from_slice(&0u32.to_le_bytes()); send(peer, Opcode::Position, seq, hwnd, payload); ack(peer, backend, transport, seq); }
pub(crate) fn rect(x: i32, y: i32, w: u32, h: u32) -> Vec<u8> { wire::Rect { x, y, width: w, height: h }.encode().unwrap().to_vec() }
pub(crate) fn ack(peer: &mut UnixStream, backend: &mut Backend, transport: &mut StreamTransport, seq: u64) {
    ack_status(peer, backend, transport, seq, 0);
}
pub(crate) fn ack_status(peer: &mut UnixStream, backend: &mut Backend, transport: &mut StreamTransport, seq: u64, expected: u32) {
    for _ in 0..100 {
        let _ = backend.run_once(transport);
        let mut header = [0u8; wire::HEADER_LEN]; if peer.set_read_timeout(Some(Duration::from_millis(5))).is_ok() && peer.read_exact(&mut header).is_ok() {
            let header = wire::Header::decode(&header).unwrap(); let mut payload = vec![0u8; header.length as usize]; peer.read_exact(&mut payload).unwrap();
            if header.opcode == Opcode::Ack && header.sequence == seq { assert_eq!(wire::u32_at(&payload, 0).unwrap(), expected); return; }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("protocol ACK timeout for sequence {seq}");
}

