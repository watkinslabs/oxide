//! Same-thread user32 dispatch setup; cross-thread execution belongs to the GUI send owner.
use crate::nt_message_params::{self as params, Params};

/// None requires owner-thread execution; Some is the raw result after local publication.
/// # C: O(processes + windows); # Sleeps: usercopy only, no GUI lock retained
pub(crate) fn prepare_current(hwnd: u64, message: u32, wparam: u64, lparam: u64,
    pointer: u64, ansi: bool, selector: u64) -> Option<u64> {
    let dispatch = selector == params::GET_DISPATCH_PARAMS;
    if selector != params::SEND_MESSAGE && !dispatch { return None; }
    let Some((window, same_thread)) = crate::nt_window::window_call_context_current(hwnd) else { return Some(0); };
    if !same_thread || pointer == 0 { return if dispatch { Some(0) } else { None }; }
    let ready = params::publish(pointer, Params { procedure: window.wndproc, hwnd, message, wparam, lparam,
        ansi, ansi_dst: !window.unicode, mapping: if dispatch { params::MAP_DISPATCH } else { params::MAP_SEND },
        dpi_context: 0 }, |address, bytes| uaccess::copy_to_user(address, bytes).is_ok());
    Some(if dispatch { ready as u64 } else { 0 })
}
