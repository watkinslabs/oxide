//! Raw paint lifetime and presentation boundary (`31fj`, `31fk`).
use super::*;
const STATUS_PENDING_OUTPUT: u64 = 0x103;
pub(super) fn begin_paint<F, G>(args: &[u64; 17], native: F, gdi: G) -> u64
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let Some(hdc) = open_paint_dc(args[0], native, gdi) else { return 0; };
    crate::nt_window::paint_prepare::prepare_for_current(args[0] as u32, hdc as u32, args[1])
}

/// Reserve the window, create and bind a fresh paint HDC. Owns the HDC on
/// every failure path; the caller prepares the session. # C: O(owner work)
pub(crate) fn open_paint_dc<F, G>(hwnd: u64, native: F, gdi: G) -> Option<u64>
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let _ = crate::nt_window::caret::paint::begin_for_current(hwnd);
    let hwnd32 = u32::try_from(hwnd).ok().filter(|hwnd| *hwnd != 0)?;
    let (window, _) = crate::nt_window::window_rect_for_current(hwnd32)?;
    let width = window.right.checked_sub(window.left).filter(|value| *value > 0)?;
    let height = window.bottom.checked_sub(window.top).filter(|value| *value > 0)?;
    let backing = crate::nt_gdi::acquire_window_dc_for_current(hwnd32, width as i32, height as i32);
    if backing == 0 || backing == STATUS_INVALID_PARAMETER { return None; }
    let hdc = gdi(NtService::CreateCompatibleDc, SyscallArgs { a0: width as u64, a1: height as u64, a2: 0, a3: 0, a4: 0, a5: 0 });
    if hdc == STATUS_INVALID_PARAMETER || hdc == 0 { return None; }
    let seeded = u32::try_from(hdc).ok().is_some_and(|dc| crate::nt_gdi::seed_paint_for_current(hwnd32, dc).is_ok());
    if !seeded {
        let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
        return None;
    }
    if crate::nt_window::paint::reserve_for_current(hwnd).is_err() {
        let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
        return None;
    }
    let bound = u32::try_from(hdc).ok().is_some_and(|dc| crate::nt_window::paintlease::bind_paint_dc_for_current(hwnd32, dc).is_ok());
    if !bound {
        let _ = native(NtService::EndWindowPaint, SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
        let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
        return None;
    }
    Some(hdc)
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
    if result == STATUS_SUCCESS { let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }); }
    let accepted = if present == STATUS_PENDING_OUTPUT { STATUS_SUCCESS } else { present };
    let status = win_bool(if result == STATUS_SUCCESS { accepted } else { result });
    if status != 0 && submitted && present == STATUS_SUCCESS { crate::nt_milestone::paint_present(); }
    status
}
