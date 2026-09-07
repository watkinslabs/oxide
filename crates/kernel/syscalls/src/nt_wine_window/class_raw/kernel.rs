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
    // A menu name is not a scalar: the caller hands over its own record and
    // takes back the one the class held, which it then frees.
    if request.offset == ipc::win32_window::GCLP_MENUNAME { return Some(exchange_menu_name(request, value)); }
    Some(access_with(request, |request| crate::nt_window::set_class_long_for_current(request.hwnd, request.offset, value, request.width), last_error))
}

/// Swap the caller's three client menu-name pointers with the class's.
/// # C: O(N_process_gui_states + N_windows + N_classes) plus bounded usercopy
fn exchange_menu_name(request: ClassLong, record: u64) -> u64 {
    let field = |slot: u64| record.checked_add(slot * 8).and_then(|address| uaccess::get_user_u64(address).ok());
    let (Some(ansi), Some(wide), Some(counted)) = (field(0), field(1), field(2)) else { return 0; };
    let handed = ipc::win32_window::ClassMenuName { ansi, wide, unicode_string: counted };
    let Ok(previous) = crate::nt_window::exchange_class_menu_name_for_current(request.hwnd, handed) else { return 0; };
    for (slot, value) in [previous.ansi, previous.wide, previous.unicode_string].iter().enumerate() {
        let Some(address) = record.checked_add(slot as u64 * 8) else { return 0; };
        if uaccess::put_user_u64(address, *value).is_err() { return 0; }
    }
    0
}

/// # C: O(N_process_gui_states + N_windows + N_classes)
pub(crate) fn get(request: ClassLong) -> u64 {
    access_with(request, |request| crate::nt_window::class_long_for_current(request.hwnd, request.offset, request.width, request.ansi), last_error)
}
