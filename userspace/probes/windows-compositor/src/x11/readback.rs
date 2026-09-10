//! Optional X-server pixel observation; never changes frame acceptance or retained pixels.
use super::{Backend, Rect};
use crate::ffi;
const RGB: u32 = 0x00ff_ffff;

#[derive(Default)]
pub(super) struct State { enabled: bool, matched: u64, mismatched: u64, unavailable: u64 }
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Report { pub pixels: usize, pub mismatches: usize, pub first: Option<(i32, i32, u32, u32)> }
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Error { Window, Coverage, Geometry, X11(u8), Format }
struct Reply(*mut ffi::GetImageReply);
impl Drop for Reply {
    fn drop(&mut self) {
        // SAFETY: Reply uniquely owns the allocation returned by xcb_get_image_reply.
        unsafe { libc::free(self.0.cast()); }
    }
}

impl Backend {
    /// Adds one X-server read round trip per accepted frame when enabled. # C: O(1)
    pub fn set_frame_readback(&mut self, enabled: bool) { self.readback.enabled = enabled; }

    pub(super) fn observe_frame(&mut self, hwnd: u32, damage: Rect) {
        if !self.readback.enabled { return; }
        match self.read_frame_pixels(hwnd, damage) {
            Ok(report) if report.mismatches == 0 => {
                self.readback.matched += 1;
                eprintln!("[WINDOWS-FRAME-READBACK] hwnd={hwnd:#x} damage={damage:?} pixels={} matched={}", report.pixels, self.readback.matched);
            }
            Ok(report) => {
                self.readback.mismatched += 1;
                eprintln!("[WINDOWS-FRAME-READBACK-MISMATCH] hwnd={hwnd:#x} damage={damage:?} pixels={} mismatches={} first={:?}", report.pixels, report.mismatches, report.first);
            }
            Err(error) => {
                self.readback.unavailable += 1;
                eprintln!("[WINDOWS-FRAME-READBACK-UNAVAILABLE] hwnd={hwnd:#x} damage={damage:?} error={error:?}");
            }
        }
    }

    /// Read actual drawable pixels, including current caret overlay. Occlusion/unmapped
    /// windows can make pixels unavailable; no successful read is invented. # C: O(damage pixels)
    pub(crate) fn read_frame_pixels(&self, hwnd: u32, damage: Rect) -> Result<Report, Error> {
        let window = self.windows.get(&hwnd).ok_or(Error::Window)?;
        let surface = window.surface.as_ref().filter(|s| damage.is_inside(s.width, s.height) && s.holds(damage)).ok_or(Error::Coverage)?;
        let x = i16::try_from(damage.left).map_err(|_| Error::Geometry)?;
        let y = i16::try_from(damage.top).map_err(|_| Error::Geometry)?;
        let width = u16::try_from(damage.right - damage.left).map_err(|_| Error::Geometry)?;
        let height = u16::try_from(damage.bottom - damage.top).map_err(|_| Error::Geometry)?;
        let mut error = core::ptr::null_mut();
        // SAFETY: backend owns the live connection/drawable; copied rectangle fits X11 coordinates.
        let reply = unsafe {
            let cookie = ffi::xcb_get_image(self.conn, ffi::IMAGE_FORMAT_Z_PIXMAP, window.xid, x, y, width, height, u32::MAX);
            ffi::xcb_get_image_reply(self.conn, cookie, &mut error)
        };
        if !error.is_null() {
            // SAFETY: xcb returned an owned error record; read its code before freeing that allocation.
            let code = unsafe { let code = (*error.cast::<ffi::GenericError>()).error_code; libc::free(error); code };
            if !reply.is_null() { drop(Reply(reply)); }
            return Err(Error::X11(code));
        }
        if reply.is_null() { return Err(Error::X11(0)); }
        let reply = Reply(reply);
        let count = usize::from(width) * usize::from(height);
        // SAFETY: Reply retains the complete XCB reply allocation throughout this validation and comparison.
        let data = unsafe {
            let length = ffi::xcb_get_image_data_length(reply.0);
            if !matches!((*reply.0).depth, 24 | 32) || length < 0 || length as usize != count * 4 { return Err(Error::Format); }
            core::slice::from_raw_parts(ffi::xcb_get_image_data(reply.0), length as usize)
        };
        let mut report = Report { pixels: count, mismatches: 0, first: None };
        for row in 0..usize::from(height) {
            let y = damage.top + row as i32;
            let expected = surface.run(y as usize, damage.left as usize, width as usize).ok_or(Error::Coverage)?;
            for (column, expected) in expected.iter().enumerate() {
                let x = damage.left + column as i32;
                let offset = (row * width as usize + column) * 4;
                let actual = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) & RGB;
                let expected = (*expected ^ window.caret.xor_at(x, y)) & RGB;
                if actual != expected {
                    report.mismatches += 1;
                    if report.first.is_none() { report.first = Some((x, y, expected, actual)); }
                }
            }
        }
        Ok(report)
    }

    #[cfg(test)]
    pub(crate) fn frame_readback_counts(&self) -> (u64, u64, u64) {
        (self.readback.matched, self.readback.mismatched, self.readback.unavailable)
    }
}
