//! Default WM_PAINT: the reference begins and ends a paint that draws nothing.
//! Same work as the raw BeginPaint/EndPaint ordinals (erase callback, present,
//! release), with the PAINTSTRUCT kept in the kernel.
use super::*;
use syscall::{nt::NtService, SyscallArgs};

fn native(service: NtService, args: SyscallArgs) -> u64 { dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER) }
fn gdi(service: NtService, args: SyscallArgs) -> u64 { crate::nt_gdi::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER) }

/// Called by default-procedure dispatch outside GUI/GDI locks. STATUS_PENDING
/// means an erase callback is running; `finish_for_current` ends the paint.
/// # C: O(owner work + pixels); # Sleeps: yes
pub(crate) fn for_current(hwnd: u64) -> u64 {
    let Some(hdc) = crate::nt_wine_window::paint::open_paint_dc(hwnd, native, gdi) else { return 0; };
    match paint_prepare::prepare_default_for_current(hwnd as u32, hdc as u32) {
        0 => 0,
        STATUS_PENDING => STATUS_PENDING,
        dc => end(hwnd, dc),
    }
}

/// Completion of a pending default paint: publish the session, then end it.
/// # C: O(owner work + pixels)
pub(crate) fn finish_for_current(prepared: paint_prepare::Prepared, result: Result<bool, ()>) -> u64 {
    let dc = paint_prepare::finish_for_current(prepared, result);
    if dc == 0 { return 0; }
    end(u64::from(prepared.hwnd), dc)
}

fn end(hwnd: u64, dc: u64) -> u64 {
    // A builtin class paints its own content between the begin and the end of
    // the paint it did not open itself; the popup-menu class draws its items.
    menu_raw::paint_popup_menu_window(hwnd, dc);
    // Item text rasterizes in the font backend after this syscall returns, so
    // the present and the deletion of this HDC wait for the runs the class
    // just issued instead of racing them.
    crate::nt_text_order::end_paint_for_current(hwnd, dc, present);
    0
}

/// Present the finished surface and release the paint session. # C: O(pixels)
fn present(hwnd: u64, dc: u64) {
    let _ = crate::nt_wine_window::paint::end_paint_with_dc(hwnd, dc, gdi);
}
