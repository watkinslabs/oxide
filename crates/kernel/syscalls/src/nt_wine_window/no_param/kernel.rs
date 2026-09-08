//! Kernel binding: the canonical owners each `NtUserCallNoParam` code reads.
use super::*;
use super::super::*;

/// The colour depth the desktop is composited at, which `WM_DISPLAYCHANGE`
/// reports.
const DISPLAY_BITS_PER_PIXEL: u64 = 32;
const WM_DISPLAYCHANGE: u32 = 0x007e;

/// # C: O(1)
fn unhandled(code: u64) -> u64 {
    klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=133c code=");
    klog::write_hex_u64(code);
    klog::write_raw(b"\n");
    UNHANDLED
}

/// # C: O(N_monitors) plus the selected code's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let raw = args.first().copied().unwrap_or(u64::MAX);
    let Some(code) = code(raw) else { return Some(unhandled(raw)); };
    Some(match code {
        Code::GetDesktopWindow => builtin_classes::kernel::get_desktop_window(),
        Code::GetDialogBaseUnits => {
            let Some((width, height)) = crate::nt_gdi::dialog_base_units() else { return Some(STATUS_INVALID_PARAMETER); };
            dialog_base_units(width, height, drm::primary_system_dpi() as i32)
        }
        Code::GetLastInputTime => u64::from(crate::nt_window::last_input_time()),
        Code::GetProgmanWindow => crate::nt_window::progman_window(),
        Code::GetShellWindow => crate::nt_window::shell_window(),
        Code::GetTaskmanWindow => crate::nt_window::taskman_window(),
        Code::DisplayModeChanged => display_mode_changed(),
        Code::ExitingThread => { crate::nt_window::mark_exiting_thread_for_current(); 0 }
        Code::ThreadDetach => { crate::nt_window::thread_detach_for_current(); 0 }
    })
}

/// Refresh the desktop geometry and tell the desktop window the mode changed.
/// The answer is TRUE, as the reference's is whenever the cache refreshed.
/// # C: O(N_monitors); # Sleeps: yes
fn display_mode_changed() -> u64 {
    let Some(monitors) = crate::nt_compositor::monitors_current() else { return 0; };
    let Some(primary) = metrics::primary(&monitors) else { return 0; };
    let desktop = builtin_classes::kernel::get_desktop_window();
    let lparam = display_change_lparam(primary.monitor.width, primary.monitor.height);
    crate::nt_window::send_display_change(desktop, WM_DISPLAYCHANGE, DISPLAY_BITS_PER_PIXEL, lparam);
    1
}
