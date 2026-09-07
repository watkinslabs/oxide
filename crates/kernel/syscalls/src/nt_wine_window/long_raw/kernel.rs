use super::*;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
/// Bounded trace of the dialog extra range: control classes keep their state
/// pointer at offset zero, and a dialog keeps its procedure and user word at
/// the DWLP slots just above it. Two crashes read garbage through offset zero,
/// and a dialog that cannot store its procedure faults on the next read, so
/// the whole DLGWINDOWEXTRA span is reported rather than the first slot alone.
const DIALOG_EXTRA_SPAN: i32 = 0x20;
fn trace_slot(op: &'static [u8], hwnd: u64, index: i32, value: u64) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    if !(0..DIALOG_EXTRA_SPAN).contains(&index) { return; }
    if BUDGET.fetch_add(1, Ordering::Relaxed) >= 96 { return; }
    klog::write_raw(b"[WINDOWS-WNDEXTRA] op="); klog::write_raw(op);
    klog::write_raw(b" hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" index="); klog::write_hex_u64(index as u32 as u64);
    klog::write_raw(b" value="); klog::write_hex_u64(value); klog::write_raw(b"\n");
}

fn last_error(error: u32) {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let teb = task.nt_teb();
    if teb == 0 { return; }
    if let Some(address) = teb.checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, error); }
}

/// Handle only the three claimed setter ordinals. # C: O(N_process_gui_states + N_windows)
pub(crate) fn dispatch(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    let request = decode(ordinal, args)?;
    Some(set_with(request, |request| {
        trace_slot(b"set", request.hwnd, request.index, request.value);
        crate::nt_window::set_window_long_with_encoding_for_current(request.hwnd, request.index, request.width, request.value, !request.ansi)
    }, last_error))
}

/// Query methods share error encoding and retain LastError on success.
/// `GWLP_ID` is a child-only identifier, not a generic extra-bytes slot: read
/// it through the canonical control-id accessor, which refuses a window that
/// is not an effective child instead of returning its menu handle as an id.
/// # C: O(N_process_gui_states + N_windows)
pub(crate) fn get(hwnd: u64, index: i32, width: usize) -> u64 {
    let result = if index == ipc::win32_window::GWLP_ID {
        crate::nt_window::control_id_for_current(hwnd).ok_or(LongPtrError::InvalidWindow)
    } else {
        crate::nt_window::get_window_long_for_current(hwnd, index, width)
    };
    trace_slot(b"get", hwnd, index, result.unwrap_or(u64::MAX));
    finish(result, width, last_error)
}
