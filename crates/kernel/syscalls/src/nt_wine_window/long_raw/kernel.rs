use super::*;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;

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
        crate::nt_window::set_window_long_with_encoding_for_current(request.hwnd, request.index, request.width, request.value, !request.ansi)
    }, last_error))
}

/// Query methods share error encoding and retain LastError on success.
/// # C: O(N_process_gui_states + N_windows)
pub(crate) fn get(hwnd: u64, index: i32, width: usize) -> u64 {
    finish(crate::nt_window::get_window_long_for_current(hwnd, index, width), width, last_error)
}
