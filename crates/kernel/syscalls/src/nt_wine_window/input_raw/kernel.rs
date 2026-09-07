//! Kernel binding: read the client records, call the canonical input owner and
//! write the answers back.
use ipc::win32_window::{thread_state, HotkeyError, MouseTracking, TrackAction};
use crate::nt_window::user_input as owner;
use super::*;

const FALSE: u64 = 0;
const TRUE: u64 = 1;
const REFUSED: u64 = u32::MAX as u64;
const WM_MOUSELEAVE: u32 = 0x02a3;
const WM_NCMOUSELEAVE: u32 = 0x02a2;
/// The timer identity the tracking hover uses, as the reference reserves one
/// system timer for it.
const SYSTEM_TIMER_TRACK_MOUSE: u64 = 0xfffa;

/// # C: O(1)
fn write_point(pointer: u64, point: (i32, i32)) -> bool {
    if pointer == 0 { return false; }
    let mut bytes = [0u8; POINT_BYTES];
    bytes[0..4].copy_from_slice(&point.0.to_le_bytes());
    bytes[4..8].copy_from_slice(&point.1.to_le_bytes());
    uaccess::copy_to_user(pointer, &bytes).is_ok()
}

/// # C: O(1)
fn read_rect(pointer: u64) -> Option<ipc::win32_window::WindowRect> {
    let mut bytes = [0u8; RECT_BYTES];
    uaccess::copy_from_user(&mut bytes, pointer).ok()?;
    Some(decode_rect(&bytes))
}

/// # C: O(N_cursor_history)
fn get_mouse_move_points(args: &[u64]) -> u64 {
    let (size, probe, out, count, resolution) = (args[0] as u32, args[1], args[2], args[3] as i32, args[4] as u32);
    if check_move_points(size, probe, out, count, resolution).is_err() { return REFUSED; }
    let mut bytes = [0u8; MOUSEMOVEPOINT_BYTES];
    if uaccess::copy_from_user(&mut bytes, probe).is_err() { return REFUSED; }
    let wanted = ipc::win32_window::CursorPos {
        x: i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        y: i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        time: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        info: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
    };
    let Some(history) = owner::cursor_history_for_current() else { return REFUSED; };
    let Ok(history) = <[ipc::win32_window::CursorPos; MOVE_POINT_HISTORY]>::try_from(history.as_slice()) else { return REFUSED; };
    let Some(points) = ipc::win32_window::move_points_from(&history, wanted, count as usize) else { return REFUSED; };
    for (index, point) in points.iter().enumerate() {
        let Some(address) = out.checked_add((index * MOUSEMOVEPOINT_BYTES) as u64) else { return REFUSED; };
        if uaccess::copy_to_user(address, &encode_move_point(*point)).is_err() { return REFUSED; }
    }
    points.len() as u64
}

/// # C: O(N_windows + N_queues)
fn track_mouse_event(pointer: u64) -> u64 {
    if pointer == 0 { return FALSE; }
    let mut bytes = [0u8; TRACKMOUSEEVENT_BYTES];
    if uaccess::copy_from_user(&mut bytes, pointer).is_err() { return FALSE; }
    let size = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if size != TRACKMOUSEEVENT_BYTES { return FALSE; }
    let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let hwnd = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let hover = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let Some(stored) = owner::mouse_tracking_for_current() else { return FALSE; };
    if flags & ipc::win32_window::TME_QUERY != 0 { return write_tracking(pointer, stored); }
    let Some(window) = owner::window_id(hwnd) else { return FALSE; };
    if owner::window_is_current_thread(window) != Some(true) { return FALSE; }
    let system = crate::nt_window::settings::mouse_hover_time_for_current().unwrap_or(ipc::win32_window::DEFAULT_HOVER_TIME);
    match ipc::win32_window::track_action(stored, window, flags, hover, owner::pointer_inside_for_current(window), system) {
        TrackAction::Query(record) => write_tracking(pointer, record),
        TrackAction::PostLeave { hwnd, nonclient } => {
            let message = if nonclient { WM_NCMOUSELEAVE } else { WM_MOUSELEAVE };
            owner::post_message_for_current(hwnd.raw() as u64, message, 0, 0) as u64
        }
        TrackAction::Stop { hwnd } => {
            if let Some(id) = hwnd { owner::kill_system_timer_for_current(id.raw() as u64, SYSTEM_TIMER_TRACK_MOUSE); }
            owner::set_mouse_tracking_for_current(MouseTracking::default());
            TRUE
        }
        TrackAction::Track(record) => {
            if let Some(id) = stored.hwnd { owner::kill_system_timer_for_current(id.raw() as u64, SYSTEM_TIMER_TRACK_MOUSE); }
            owner::set_mouse_tracking_for_current(record);
            if let Some(id) = record.hwnd {
                owner::set_system_timer_for_current(id.raw() as u64, SYSTEM_TIMER_TRACK_MOUSE, record.hover_time);
            }
            TRUE
        }
    }
}

/// # C: O(1)
fn write_tracking(pointer: u64, record: MouseTracking) -> u64 {
    let mut bytes = [0u8; TRACKMOUSEEVENT_BYTES];
    bytes[0..4].copy_from_slice(&(TRACKMOUSEEVENT_BYTES as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&record.flags.to_le_bytes());
    bytes[8..16].copy_from_slice(&record.hwnd.map_or(0u64, |id| id.raw() as u64).to_le_bytes());
    bytes[16..20].copy_from_slice(&record.hover_time.to_le_bytes());
    if uaccess::copy_to_user(pointer, &bytes).is_err() { return FALSE; }
    TRUE
}

/// Apply one decoded injection step through the canonical hardware path.
/// # C: O(N_windows + N_queues)
fn apply_step(step: SendStep) -> bool {
    use ipc::win32_window::{EV_KEY, EV_REL, REL_WHEEL, REL_X, REL_Y};
    match step {
        SendStep::MoveTo { x, y } => {
            let Some((from_x, from_y)) = owner::cursor_pos_for_current() else { return false; };
            owner::inject_mouse_for_current(EV_REL, REL_X, x.saturating_sub(from_x))
                && owner::inject_mouse_for_current(EV_REL, REL_Y, y.saturating_sub(from_y))
        }
        SendStep::MoveBy { dx, dy } => owner::inject_mouse_for_current(EV_REL, REL_X, dx)
            && owner::inject_mouse_for_current(EV_REL, REL_Y, dy),
        SendStep::Button { code, pressed } => owner::inject_mouse_for_current(EV_KEY, code, pressed as i32),
        SendStep::Wheel { notches } => owner::inject_mouse_for_current(EV_REL, REL_WHEEL, notches),
        SendStep::Key { vkey, pressed } => owner::inject_key_for_current(vkey, pressed),
    }
}

/// Inject the caller's input records, answering how many were accepted.
/// # C: O(N_records * (N_windows + N_queues))
fn send_input(args: &[u64]) -> u64 {
    let (count, inputs, size) = (args[0] as u32, args[1], args[2] as u32 as u64);
    if !check_send_input(count, inputs, size) { return 0; }
    let screen = owner::virtual_screen();
    for index in 0..count as u64 {
        let Some(base) = inputs.checked_add(index * INPUT_BYTES) else { return index; };
        let Ok(kind) = uaccess::get_user_u32(base) else { return index; };
        match kind {
            INPUT_MOUSE => {
                let Ok(dx) = uaccess::get_user_u32(base + MOUSE_DX) else { return index; };
                let Ok(dy) = uaccess::get_user_u32(base + MOUSE_DY) else { return index; };
                let Ok(data) = uaccess::get_user_u32(base + MOUSE_DATA) else { return index; };
                let Ok(flags) = uaccess::get_user_u32(base + MOUSE_FLAGS) else { return index; };
                let (steps, used) = mouse_steps(dx as i32, dy as i32, data, flags, screen);
                for step in &steps[..used] { if !apply_step(*step) { return index; } }
            }
            INPUT_KEYBOARD => {
                let Ok(vkey) = uaccess::get_user_u16(base + KEY_VK) else { return index; };
                let Ok(flags) = uaccess::get_user_u32(base + KEY_FLAGS) else { return index; };
                if !apply_step(key_step(vkey, flags)) { return index; }
            }
            // The reference refuses hardware records outright.
            INPUT_HARDWARE => return 0,
            _ => return index,
        }
    }
    count as u64
}

/// # C: O(N_hotkeys)
fn hotkey_result(result: Result<Option<ipc::win32_window::Hotkey>, HotkeyError>) -> u64 {
    match result { Ok(_) => TRUE, Err(_) => FALSE }
}

/// Answer the cursor, capture, queue-status and tracking ordinals.
/// # C: O(owner work)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    Some(match ordinal {
        GET_CURSOR_POS if !args.is_empty() => {
            let Some(point) = owner::cursor_pos_for_current() else { return Some(FALSE); };
            write_point(args[0], point) as u64
        }
        SET_CURSOR_POS if args.len() >= 2 => owner::set_cursor_pos_for_current(args[0] as i32, args[1] as i32) as u64,
        GET_CURSOR_INFO if !args.is_empty() => {
            if args[0] == 0 { return Some(FALSE); }
            let Some(point) = owner::cursor_pos_for_current() else { return Some(FALSE); };
            let cursor = crate::nt_window::current_cursor_for_current().unwrap_or(0);
            let bytes = encode_cursor_info(cursor, owner::cursor_showing_for_current(), point);
            uaccess::copy_to_user(args[0], &bytes).is_ok() as u64
        }
        GET_CLIP_CURSOR if !args.is_empty() => {
            let Some(rect) = owner::clip_cursor_rect_for_current().filter(|_| args[0] != 0) else { return Some(FALSE); };
            uaccess::copy_to_user(args[0], &encode_rect(rect)).is_ok() as u64
        }
        CLIP_CURSOR if !args.is_empty() => {
            let request = if args[0] == 0 { None } else {
                let Some(rect) = read_rect(args[0]) else { return Some(FALSE); };
                Some(rect)
            };
            owner::clip_cursor_for_current(request) as u64
        }
        GET_MOUSE_MOVE_POINTS_EX if args.len() >= 5 => get_mouse_move_points(args),
        TRACK_MOUSE_EVENT if !args.is_empty() => track_mouse_event(args[0]),
        SET_CAPTURE if !args.is_empty() => owner::set_capture_for_current(args[0], 0).unwrap_or(0),
        RELEASE_CAPTURE => owner::release_capture_for_current() as u64,
        GET_MESSAGE_POS => owner::message_pos_for_current() as u64,
        SET_MESSAGE_EXTRA_INFO if !args.is_empty() => owner::set_message_extra_for_current(args[0] as i64) as u64,
        GET_QUEUE_STATUS if !args.is_empty() => owner::queue_status_for_current(args[0] as u32).unwrap_or(0) as u64,
        GET_THREAD_STATE if !args.is_empty() => {
            let Some(class) = thread_state(args[0] as u32) else { return Some(0); };
            owner::thread_state_for_current(class)
        }
        GET_CURRENT_INPUT_MESSAGE_SOURCE if !args.is_empty() => {
            if args[0] == 0 { return Some(FALSE); }
            uaccess::copy_to_user(args[0], &[0u8; INPUT_MESSAGE_SOURCE_BYTES]).is_ok() as u64
        }
        GET_DOUBLE_CLICK_TIME => crate::nt_window::settings::double_click_time_for_current()
            .unwrap_or(DEFAULT_DOUBLE_CLICK_MS) as u64,
        REGISTER_HOTKEY if args.len() >= 4 => hotkey_result(
            owner::register_hotkey_for_current(args[0], args[1] as i32, args[2] as u32, args[3] as u32)),
        UNREGISTER_HOTKEY if args.len() >= 2 => owner::unregister_hotkey_for_current(args[0], args[1] as i32).is_ok() as u64,
        ATTACH_THREAD_INPUT if args.len() >= 3 => owner::attach_thread_input_for_current(
            args[0] as u32 as u64, args[1] as u32 as u64, args[2] != 0).is_ok() as u64,
        SEND_INPUT if args.len() >= 3 => send_input(args),
        // The pointer-input device stack is not present, which is the state
        // these three report when no pointer device is enabled.
        ENABLE_MOUSE_IN_POINTER | ENABLE_MOUSE_IN_POINTER_FOR_THREAD | IS_MOUSE_IN_POINTER_ENABLED
            | REGISTER_TOUCH_PAD_CAPABLE => FALSE,
        _ => return None,
    })
}

