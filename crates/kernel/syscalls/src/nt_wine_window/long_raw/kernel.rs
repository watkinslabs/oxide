use super::*;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
/// Bounded trace of the offset-0 pointer slot: control classes keep their state
/// pointer there, and two crashes read garbage through it.
fn trace_slot(op: &'static [u8], hwnd: u64, index: i32, value: u64) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    if index != 0 || BUDGET.fetch_add(1, Ordering::Relaxed) >= 96 { return; }
    klog::write_raw(b"[WINDOWS-WNDEXTRA] op="); klog::write_raw(op);
    klog::write_raw(b" hwnd="); klog::write_hex_u64(hwnd);
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
/// # C: O(N_process_gui_states + N_windows)
pub(crate) fn get(hwnd: u64, index: i32, width: usize) -> u64 {
    let result = crate::nt_window::get_window_long_for_current(hwnd, index, width);
    trace_slot(b"get", hwnd, index, result.unwrap_or(u64::MAX));
    finish(result, width, last_error)
}
