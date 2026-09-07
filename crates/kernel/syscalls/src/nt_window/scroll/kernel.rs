//! Kernel-only raw scroll ingress and concrete continuation wiring.

#[cfg(any(target_os = "oxide-kernel", test))]
use super::{live, raw, sink};

#[cfg(any(target_os = "oxide-kernel", test))]
pub(crate) fn dispatch(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    match ordinal {
        raw::SET_SCROLL_INFO_ORDINAL => {
            let request = raw::SetScrollInfoArgs::decode(args);
            let mut sink = sink::production(send_message, resume_frame);
            Some(live::set_scroll_info_for_current(
                request.hwnd, request.bar, request.info, request.redraw, &mut sink,
            ))
        }
        _ => None,
    }
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn send_message(hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64> {
    Some(crate::nt_window::send::send_for_current(hwnd, message, wparam, lparam))
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn resume_frame(token: u64, outcome: crate::nt_window::position::Outcome) -> u64 {
    let mut sink = sink::production(send_message, resume_frame);
    sink::resume_frame(token, outcome, &mut sink)
}
