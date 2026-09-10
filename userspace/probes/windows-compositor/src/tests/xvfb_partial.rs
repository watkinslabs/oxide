//! What a frame's rectangle means, proved against a real server.
//!
//! A completed paint publishes a sub-rectangle of a window, not the window.
//! Two things have to hold for that to be safe, and neither is visible from
//! this backend's own bookkeeping: the sub-rectangle has to land at its own
//! origin and leave every other pixel as the last frame left it, and what the
//! display holds for the window has to be what the retained surface holds for
//! it. A drawable that disagrees with the surface is double-buffer
//! corruption by definition: the difference appears the moment anything makes
//! the window repaint from the copy.

use std::os::unix::net::UnixStream;
use std::ptr;

use syscall::nt_compositor::{self as wire, Opcode};
use crate::ffi;
use crate::xvfb_harness::{ack, connect, rect, send, xvfb};
use crate::{Backend, Rect, StreamTransport};

const W: u32 = 40;
const H: u32 = 30;
const FIRST: u32 = 0x0011_2233;
const SECOND: u32 = 0x0044_5566;

/// One frame payload: the surface extent, the damaged sub-rectangle, and only
/// that sub-rectangle's pixels.
fn frame(width: u32, height: u32, damage: Rect, colour: u32) -> Vec<u8> {
    let row = (damage.right - damage.left) as u32;
    let mut payload = Vec::new();
    payload.extend_from_slice(&width.to_le_bytes()); payload.extend_from_slice(&height.to_le_bytes());
    payload.extend_from_slice(&(row * 4).to_le_bytes()); payload.extend_from_slice(&wire::PIXEL_BGRA8888.to_le_bytes());
    payload.extend_from_slice(&wire::Damage { left: damage.left, top: damage.top, right: damage.right, bottom: damage.bottom }.encode());
    for _ in 0..row * (damage.bottom - damage.top) as u32 { payload.extend_from_slice(&colour.to_le_bytes()); }
    payload
}

/// Every pixel the server holds for a drawable, as stored words.
unsafe fn server_image(conn: *mut ffi::Connection, drawable: ffi::Window, width: u32, height: u32) -> Vec<u32> {
    let cookie = ffi::xcb_get_image(conn, ffi::IMAGE_FORMAT_Z_PIXMAP, drawable, 0, 0, width as u16, height as u16, u32::MAX);
    let mut error = ptr::null_mut();
    let reply = ffi::xcb_get_image_reply(conn, cookie, &mut error);
    assert!(!reply.is_null(), "the server refused to read back drawable {drawable:#x}");
    let len = ffi::xcb_get_image_data_length(reply) as usize;
    let data = std::slice::from_raw_parts(ffi::xcb_get_image_data(reply), len);
    let pixels: Vec<u32> = data.chunks_exact(4).map(|v| u32::from_le_bytes(v.try_into().unwrap())).collect();
    libc::free(reply as *mut _);
    assert_eq!(pixels.len(), (width * height) as usize);
    pixels
}

fn create(x: i32, y: i32, w: u32, h: u32, parent: u64, style: u32) -> Vec<u8> {
    let mut payload = rect(x, y, w, h);
    payload.extend_from_slice(&parent.to_le_bytes());
    payload.extend_from_slice(&style.to_le_bytes()); payload.extend_from_slice(&0u32.to_le_bytes());
    payload
}

struct Fixture { _server: crate::xvfb_harness::Xvfb, backend: Backend, peer: UnixStream, transport: StreamTransport, conn: *mut ffi::Connection, xid: ffi::Window, sequence: u64 }

impl Fixture {
    fn open(width: u32, height: u32) -> Self {
        let server = xvfb();
        let mut backend = Backend::connect(Some(&server.display)).unwrap();
        backend.seed_test_ewmh();
        let (mut peer, bridge) = UnixStream::pair().unwrap();
        let mut transport = StreamTransport::from_stream(bridge).unwrap();
        send(&mut peer, Opcode::Create, 1, 0xb1, create(0, 0, width, height, 0, 0));
        ack(&mut peer, &mut backend, &mut transport, 1);
        send(&mut peer, Opcode::Visibility, 2, 0xb1, 1u32.to_le_bytes().to_vec());
        ack(&mut peer, &mut backend, &mut transport, 2);
        let xid = backend.xid_for(0xb1).unwrap();
        let (conn, _) = unsafe { connect(&server.display) };
        Self { _server: server, backend, peer, transport, conn, xid, sequence: 2 }
    }
    fn present(&mut self, width: u32, height: u32, damage: Rect, colour: u32) {
        self.sequence += 1;
        send(&mut self.peer, Opcode::Frame, self.sequence, 0xb1, frame(width, height, damage, colour));
        ack(&mut self.peer, &mut self.backend, &mut self.transport, self.sequence);
    }
    /// What the display holds for the window, what the backend retains for
    /// it, and the areas the surface claims to hold. The retained pixels
    /// are what a re-expose puts on the display, but only inside the claim.
    fn displayed_and_retained(&mut self, width: u32, height: u32) -> (Vec<u32>, Vec<u32>, Vec<Rect>) {
        self.backend.flush();
        let displayed = unsafe { server_image(self.conn, self.xid, width, height) };
        let (retained, held) = self.backend.retained_for_test(0xb1).unwrap();
        (displayed, retained, held)
    }
}

impl Drop for Fixture { fn drop(&mut self) { unsafe { ffi::xcb_disconnect(self.conn); } } }

/// A sub-rectangle lands at its own origin and nowhere else: the pixels the
/// first frame put outside it are still the first frame's, read back from the
/// server rather than from this backend's copy of them.
#[test]
fn a_sub_rectangle_reaches_its_own_offset_and_leaves_the_rest_of_the_window_alone() {
    let mut f = Fixture::open(W, H);
    f.present(W, H, Rect { left: 0, top: 0, right: W as i32, bottom: H as i32 }, FIRST);
    let part = Rect { left: 8, top: 6, right: 16, bottom: 12 };
    f.present(W, H, part, SECOND);
    let (displayed, retained, held) = f.displayed_and_retained(W, H);
    assert_eq!(held, vec![Rect { left: 0, top: 0, right: W as i32, bottom: H as i32 }]);
    for y in 0..H as i32 { for x in 0..W as i32 {
        let inside = x >= part.left && x < part.right && y >= part.top && y < part.bottom;
        let want = if inside { SECOND } else { FIRST } | 0xff00_0000;
        let got = displayed[(y as u32 * W + x as u32) as usize] | 0xff00_0000;
        assert_eq!(got, want, "display holds {got:#010x} at ({x},{y}), expected {want:#010x}");
    } }
    assert_eq!(displayed.iter().map(|p| p | 0xff00_0000).collect::<Vec<_>>(),
        retained.iter().map(|p| p | 0xff00_0000).collect::<Vec<_>>(), "the display and the retained surface disagree");
}

/// The surface a window retains and the pixels the display holds for it are
/// one picture. A surface allocated fresh - the window's first frame, or a
/// server-side resize that made the old one describe nothing - holds no
/// pixels the display has ever been given, so a partial frame into it leaves
/// the display holding whatever was underneath the window while the copy that
/// answers the next expose holds something else. Read both back and require
/// them to agree.
#[test]
fn a_partial_frame_into_a_fresh_surface_leaves_the_display_and_the_surface_agreeing() {
    let mut f = Fixture::open(W, H);
    let part = Rect { left: 10, top: 4, right: 30, bottom: 20 };
    f.present(W, H, part, SECOND);
    let (displayed, retained, held) = f.displayed_and_retained(W, H);
    // The surface claims the sub-rectangle it was given and nothing else: the
    // rest of the window has never been presented and its pixels are the
    // window's, not this backend's storage colour.
    assert_eq!(held, vec![part], "a fresh surface claimed pixels no frame ever gave it");
    for y in part.top..part.bottom { for x in part.left..part.right {
        let index = (y as u32 * W + x as u32) as usize;
        assert_eq!(displayed[index] | 0xff00_0000, SECOND | 0xff00_0000);
        assert_eq!(retained[index] | 0xff00_0000, SECOND | 0xff00_0000, "the display and the surface disagree inside the claim");
    } }
}

/// The same thing after the server has resized the window: the old surface
/// describes nothing at the new extent and is dropped, so the next partial
/// frame is a partial frame into a fresh surface again.
#[test]
fn a_partial_frame_after_a_server_resize_leaves_the_display_and_the_surface_agreeing() {
    const WIDE: u32 = 48;
    let mut f = Fixture::open(W, H);
    f.present(W, H, Rect { left: 0, top: 0, right: W as i32, bottom: H as i32 }, FIRST);
    // The window manager sizes the window, as one does on screen: the
    // request comes from another connection, not from the application.
    let values = [WIDE, H];
    unsafe { ffi::xcb_configure_window(f.conn, f.xid, ffi::CONFIGURE_WIDTH | ffi::CONFIGURE_HEIGHT, values.as_ptr()); ffi::xcb_flush(f.conn); }
    for _ in 0..200 {
        while f.backend.poll_event().is_some() {}
        if f.backend.window_layout_for_test(0xb1).map(|(_, w, _)| w) == Some(WIDE) { break; }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(f.backend.window_layout_for_test(0xb1).map(|(_, w, h)| (w, h)), Some((WIDE, H)));
    let part = Rect { left: 2, top: 2, right: 20, bottom: 10 };
    f.present(WIDE, H, part, SECOND);
    let (displayed, retained, held) = f.displayed_and_retained(WIDE, H);
    assert_eq!(held, vec![part], "the surface allocated for the new extent claimed the old surface's coverage");
    for y in 0..H as i32 { for x in 0..WIDE as i32 {
        let index = (y as u32 * WIDE + x as u32) as usize;
        let inside = x >= part.left && x < part.right && y >= part.top && y < part.bottom;
        if inside { assert_eq!(displayed[index] | 0xff00_0000, SECOND | 0xff00_0000);
            assert_eq!(retained[index] | 0xff00_0000, SECOND | 0xff00_0000, "the display and the surface disagree inside the claim"); }
    } }
}

#[path = "xvfb_partial/show.rs"]
mod show;
#[path = "xvfb_partial/readback.rs"]
mod readback;
