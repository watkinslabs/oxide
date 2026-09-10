//! Raw paint lifetime and presentation boundary (`31fj`, `31fk`).
use super::*;
const STATUS_PENDING_OUTPUT: u64 = 0x103;
pub(super) fn begin_paint<F, G>(args: &[u64; 17], native: F, gdi: G) -> u64
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let Some(hdc) = open_paint_dc(args[0], native, gdi) else { return 0; };
    crate::nt_window::paint_prepare::prepare_for_current(args[0] as u32, hdc as u32, args[1])
}

/// Which step of one paint open refused to hand over its resource. A paint
/// that opens nothing draws nothing, and the step that refused is the whole
/// diagnosis; bounded so a running system stays quiet.
fn trace_open_failure(hwnd: u64, step: &'static [u8]) {
    if !u32::try_from(hwnd).is_ok_and(crate::nt_window::paint_trace::take) { return; }
    klog::write_raw(b"[WINDOWS-PAINT-OPEN-FAIL] hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" step="); klog::write_raw(step); klog::write_raw(b"\n");
}

/// What one paint end did with the pixels the window procedure drew. A paint
/// whose region was empty submits nothing, and a submitted region that the
/// canonical owner refuses reaches no screen: both leave the last presented
/// pixels standing, which reads as a control that never drew. Bounded per
/// window: a budget spent by whichever windows painted first goes silent
/// exactly when a new dialog appears, and that silence reads as a window
/// that never painted at all.
fn trace_end(hwnd: u64, hdc: u64, submitted: bool, present: u64, status: u64) {
    if !u32::try_from(hwnd).is_ok_and(crate::nt_window::paint_trace::take) { return; }
    klog::write_raw(b"[WINDOWS-PAINT-END] hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" dc="); klog::write_hex_u64(hdc);
    klog::write_raw(b" submitted="); klog::write_hex_u64(submitted as u64);
    klog::write_raw(b" present="); klog::write_hex_u64(present);
    klog::write_raw(b" status="); klog::write_hex_u64(status);
    klog::write_raw(b"\n");
}

/// Bind the live owners to the paint-open order. # C: O(owner work)
struct Open<F> { hwnd: u64, hwnd32: u32, native: F }

impl<F> crate::nt_wine_paint_open::PaintOpen for Open<F>
where F: Fn(NtService, SyscallArgs) -> u64 {
    fn reserve(&mut self) -> bool {
        let reserved = crate::nt_window::paint::reserve_for_current(self.hwnd).is_ok();
        if !reserved { trace_open_failure(self.hwnd, b"reserve"); }
        reserved
    }
    fn release(&mut self) {
        let _ = (self.native)(NtService::EndWindowPaint, SyscallArgs { a0: self.hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
    }
    fn backing(&mut self) -> bool {
        crate::nt_window::dc_lease_context_for_current(self.hwnd32,ipc::win32_gdi::DCX_USESTYLE).is_some()
    }
    fn create_dc(&mut self) -> u64 {
        crate::nt_gdi::get_dc_ex_for_current(self.hwnd32,0,ipc::win32_gdi::DCX_USESTYLE)
    }
    fn seed(&mut self, dc: u64) -> bool {
        let seeded = u32::try_from(dc).ok().is_some_and(|dc| crate::nt_gdi::seed_paint_for_current(self.hwnd32, dc).is_ok());
        if !seeded { trace_open_failure(self.hwnd, b"seed"); }
        seeded
    }
    fn bind(&mut self, dc: u64) -> bool {
        let bound = u32::try_from(dc).ok().is_some_and(|dc| crate::nt_window::paintlease::bind_paint_dc_for_current(self.hwnd32, dc).is_ok());
        if !bound { trace_open_failure(self.hwnd, b"bind"); }
        bound
    }
    fn delete_dc(&mut self, dc: u64) {
        let _ = crate::nt_gdi::delete_paint_dc_current(dc as u32);
    }
}

/// Reserve window damage and bind a clipped DC lease. Owns the HDC and the
/// paint session on every failure path; the caller prepares the session.
/// # C: O(owner work)
pub(crate) fn open_paint_dc<F, G>(hwnd: u64, native: F, _gdi: G) -> Option<u64>
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let _ = crate::nt_window::caret::paint::begin_for_current(hwnd);
    let hwnd32 = u32::try_from(hwnd).ok().filter(|hwnd| *hwnd != 0)?;
    crate::nt_wine_paint_open::open(&mut Open { hwnd, hwnd32, native })
}

pub(super) fn end_paint<F, G>(args: &[u64; 17], _native: F, gdi: G) -> u64
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let Ok(hdc) = uaccess::get_user_u64(args[1]) else { let _ = crate::nt_window::caret::paint::end_for_current(args[0]); return 0; };
    end_paint_with_dc(args[0], hdc, gdi)
}

/// Present the painted region, release the lease and the HDC. # C: O(owner work + pixels)
pub(crate) fn end_paint_with_dc<G>(window: u64, hdc: u64, gdi: G) -> u64
where G: Fn(NtService, SyscallArgs) -> u64 {
    let args = [window, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let _ = crate::nt_window::caret::paint::end_for_current(args[0]);
    let Some((hwnd, dc)) = u32::try_from(args[0]).ok().zip(u32::try_from(hdc).ok()) else { return 0; };
    if crate::nt_window::paintlease::validate_for_current(hwnd, dc).is_err() { return 0; }
    let mut submitted = false;
    let present = if hdc != 0 {
        match crate::nt_window::paint::current_rect(args[0]) {
            Some(region) if region.left >= region.right || region.top >= region.bottom => STATUS_SUCCESS,
            Some(region) => {
                submitted = true;
                gdi(NtService::PresentGdiWindowRegion, SyscallArgs { a0: args[0], a1: hdc, a2: region.left as u64, a3: region.top as u64, a4: region.right as u64, a5: region.bottom as u64 })
            }
            None => STATUS_INVALID_PARAMETER,
        }
    } else { STATUS_INVALID_PARAMETER };
    let result = if crate::nt_window::paintlease::end_for_current(hwnd, dc).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER };
    if result == STATUS_SUCCESS { let _ = crate::nt_gdi::delete_paint_dc_current(dc); }
    let accepted = if present == STATUS_PENDING_OUTPUT { STATUS_SUCCESS } else { present };
    let status = win_bool(if result == STATUS_SUCCESS { accepted } else { result });
    trace_end(args[0], hdc, submitted, present, status);
    // The present milestone is recorded where the frame is handed to the
    // desktop, which is the pump flush, not this paint.
    status
}
