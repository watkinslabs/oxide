//! Sleepable submission follows released GUI/GDI ownership.
use super::*;
use alloc::sync::Arc;
use crate::nt_gdi::{GDI, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, output};

/// Sink for canonical scrollbar actions; success requires a Presented ACK.
/// # C: O(processes + DCs + frame pixels); # Sleeps: compositor completion
pub(crate) fn repaint_nonclient_scroll_for_current(hwnd: u64, bar: i32, scroll: ScrollState, interior: bool) -> bool {
    let Ok(hwnd) = u32::try_from(hwnd) else { return false; };
    let Some(current) = sched::live::current().filter(|current| current.is_nt_personality()) else { return false; };
    let Some(context) = crate::nt_window::nonclient_scroll_context_for_current(u64::from(hwnd)) else { return false; };
    let dc=crate::nt_gdi::get_dc_ex_for_current(hwnd,0,ipc::win32_gdi::DCX_WINDOW|ipc::win32_gdi::DCX_USESTYLE)as u32;
    if dc==0{return false;}
    let group = Arc::downgrade(&current.thread_group);
    let frame = (||{
        let mut entries=GDI.lock();
        let entry=entries.iter_mut().find(|entry|entry.group.ptr_eq(&group)).ok_or(STATUS_INVALID_PARAMETER)?;
        let (_,outcome)=render_dc_parts(&mut entry.state,dc,bar,scroll,context,interior).map_err(|_|STATUS_INVALID_PARAMETER)?;
        if !matches!(outcome,ScrollDrawOutcome::Painted(_)){return Err(STATUS_INVALID_PARAMETER);}
        let (owner,backing)=entry.state.dc_presentation_owner(dc).ok_or(STATUS_INVALID_PARAMETER)?;
        output::prepare_explicit(&mut entry.state,owner,backing).map_err(|_|STATUS_INVALID_PARAMETER)
    })();
    let released=crate::nt_gdi::release_dc_lease_for_current(dc);
    output::submit_prepared_for_current(frame)==STATUS_SUCCESS&&released
}
