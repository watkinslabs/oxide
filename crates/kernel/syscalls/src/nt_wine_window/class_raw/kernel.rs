//! Kernel binding: the canonical class owner answers, the TEB carries the error.
use super::*;
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;

fn last_error(error: u32) {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let teb = task.nt_teb();
    if teb == 0 { return; }
    if let Some(address) = teb.checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, error); }
}

/// # C: O(N_process_gui_states + N_windows + N_classes)
pub(crate) fn dispatch_set(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    let (request, value) = decode_set(ordinal, args)?;
    // A menu name is exchanged rather than assigned: the caller hands over its
    // own handle and takes back the one the class held, which it then frees.
    if request.offset == ipc::win32_window::GCLP_MENUNAME { return Some(exchange_menu_name(request, value)); }
    Some(access_with(request, |request| crate::nt_window::set_class_long_for_current(request.hwnd, request.offset, value, request.width), last_error))
}

/// Swap the caller's client menu-name handle with the class's and answer the
/// one the class held. The handle is the caller's own value — an opaque
/// pointer or an integer resource id — and is never dereferenced.
/// # C: O(N_process_gui_states + N_windows + N_classes)
fn exchange_menu_name(request: ClassLong, handed: u64) -> u64 {
    crate::nt_window::exchange_class_menu_name_for_current(request.hwnd, handed).unwrap_or(0)
}

/// # C: O(N_process_gui_states + N_windows + N_classes)
pub(crate) fn get(request: ClassLong) -> u64 {
    access_with(request, |request| crate::nt_window::class_long_for_current(request.hwnd, request.offset, request.width), last_error)
}
