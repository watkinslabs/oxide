//! The state half: the descriptive record, window words, thread ownership,
//! the child test, the two window marks, the private extra region and one
//! injected hardware input record.
use super::super::params::{PrivateData, HardwareInput, Rect};
use super::super::params::{GET_PRIVATE_BYTES, HARDWARE_INPUT_BYTES, SET_PRIVATE_BYTES};
use super::super::window_info::WindowInfo;
use crate::nt_window::rect_query;
use crate::nt_wine_window::{input_raw, long_raw, query_window};

const FALSE: u64 = 0;
const TRUE: u64 = 1;
/// A dpi ratio of zero means the calling thread's, which is the system's here.
const THREAD_DPI: u32 = 0;
/// The extra-area slot an MDI client's info occupies, one pointer in.
const MDI_CLIENT_INFO_OFFSET: i32 = 8;
/// `STATUS_SUCCESS`, which is what an accepted hardware input answers.
const STATUS_SUCCESS: u64 = 0;
/// `STATUS_INVALID_PARAMETER`, for an input record that cannot be read.
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

fn rect_of(hwnd: u64, kind: rect_query::RectKind) -> Option<Rect> {
    if hwnd > u32::MAX as u64 { return None; }
    let rect = rect_query::query_current(hwnd as u32, kind, THREAD_DPI)?;
    Some(Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
}

/// GetWindowWord. A negative index other than the user-data slot names no
/// word, which the window-long owner already refuses.
/// # C: O(N_processes + N_windows)
pub(super) fn window_word(hwnd: u64, offset: i32) -> u64 { long_raw::get(hwnd, offset, 2) }

/// GetWindowInfo. Both rectangles are screen-relative, and the border widths
/// follow from them. # C: O(N_processes + N_windows)
pub(super) fn window_info(hwnd: u64, info_ptr: u64) -> u64 {
    if info_ptr == 0 { return FALSE; }
    let (Some(window), Some(client)) = (rect_of(hwnd, rect_query::RectKind::Window),
        rect_of(hwnd, rect_query::RectKind::ClientScreen)) else { return FALSE; };
    let Some((style, ex_style, active, class_atom)) = crate::nt_window::window_info_for_current(hwnd) else { return FALSE; };
    let record = WindowInfo { window, client, style, ex_style, active, class_atom };
    if uaccess::copy_to_user(info_ptr, &record.encode()).is_err() { return FALSE; }
    TRUE
}

/// GetScrollInfo, whose parameter record the scroll owner already decodes.
/// # C: O(N_processes + N_windows)
pub(super) fn scroll_info(hwnd: u64, params_ptr: u64) -> u64 {
    use crate::nt_window::scroll::raw;
    if params_ptr == 0 { return FALSE; }
    let mut bytes = [0u8; raw::GET_PARAMS_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return FALSE; }
    let request = raw::GetScrollInfoParams::decode(bytes);
    crate::nt_window::scroll::live::get_scroll_info_for_current(hwnd, request.bar, request.info)
}

/// GetWindow. # C: O(N_processes + N_windows²)
pub(super) fn window_relative(hwnd: u64, relationship: u32) -> u64 {
    crate::nt_window::window_relative_for_current(hwnd, relationship)
}

/// GetWindowThreadProcessId: the owning thread is the answer, the owning
/// process is written through the caller's pointer when it gives one.
/// # C: O(N_processes + N_windows)
pub(super) fn window_thread(hwnd: u64, process_ptr: u64) -> u64 {
    let facts = crate::nt_window::imc::query_window_facts(hwnd, query_window::WINDOW_THREAD, timekeeper::monotonic_ns());
    let Some(facts) = facts else { return 0; };
    if process_ptr != 0 && uaccess::put_user_u32(process_ptr, facts.pid as u32).is_err() { return 0; }
    facts.thread_id
}

/// IsChild. # C: O(N_processes + N_windows²)
pub(super) fn is_child(parent: u64, child: u64) -> bool {
    crate::nt_window::is_child_for_current(parent, child)
}

/// SetDialogInfo hands one window its dialog state pointer.
/// # C: O(N_processes + N_windows)
pub(super) fn set_dialog_info(hwnd: u64, info: u64) -> u64 {
    u64::from(crate::nt_window::set_dialog_info_for_current(hwnd, info))
}

/// SetMDIClientInfo writes the client info to the window's pointer slot and
/// marks the window an MDI client, which is what makes the slot readable back.
/// # C: O(N_processes + N_windows)
pub(super) fn set_mdi_client_info(hwnd: u64, info: u64) -> u64 {
    let stored = crate::nt_window::set_window_long_with_encoding_for_current(hwnd, MDI_CLIENT_INFO_OFFSET, 8, info, true);
    if stored.is_err() { return FALSE; }
    u64::from(crate::nt_window::mark_mdi_client_for_current(hwnd))
}

/// GetPrivateData reads the region an application's own window-long access
/// cannot reach. # C: O(N_processes + N_windows)
pub(super) fn private_data(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return 0; }
    let mut bytes = [0u8; GET_PRIVATE_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return 0; }
    let params = PrivateData::decode_get(bytes);
    crate::nt_window::private_data_for_current(hwnd, params.offset as i32, params.size as usize).unwrap_or(0)
}

/// SetPrivateData writes that region, answering the value it replaced.
/// # C: O(N_processes + N_windows)
pub(super) fn set_private_data(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return 0; }
    let mut bytes = [0u8; SET_PRIVATE_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return 0; }
    let params = PrivateData::decode_set(bytes);
    crate::nt_window::set_private_data_for_current(hwnd, params.offset as i32, params.size as usize, params.value).unwrap_or(0)
}

/// SendHardwareInput delivers one input record as hardware input, which the
/// input owner applies exactly as an injected record from the same table.
/// # C: O(input application)
pub(super) fn send_hardware_input(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; HARDWARE_INPUT_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return STATUS_INVALID_PARAMETER; }
    let params = HardwareInput::decode(bytes);
    // The named window and the record's extra word steer raw-input delivery,
    // which no device stack here produces; the input itself is applied by the
    // one owner every injected record goes through.
    let _unrouted = (hwnd, params.flags, params.lparam);
    if input_raw::kernel::apply_one_input(params.input) { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}
