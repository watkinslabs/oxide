//! Live scrollbar visibility, arrow enabling and accessibility snapshot.
use crate::nt_window::{send, GUI};
use syscall::nt::{NtCall, NtService};
use syscall::SyscallArgs;
use super::bar_raw::*;
use super::{sink, ScrollActionSink};
use alloc::sync::Arc;
use ipc::win32_window::{SB_CTL, SB_HORZ, SB_VERT};
use ipc::win32_window::scroll_owner::{scrollbar_states, SCROLLBARINFO_BYTES};

const SW_HIDE: u64 = 0;
const SW_SHOW: u64 = 5;

/// Route one scrollbar ordinal. # C: O(1) plus the arm's own cost; # Sleeps: yes
pub(crate) fn route(ordinal: u64, args: [u64; 4]) -> Option<u64> {
    match ordinal {
        SHOW_SCROLL_BAR => Some(show(args[0], args[1] as i32, args[2] != 0)),
        ENABLE_SCROLL_BAR => Some(enable(args[0], args[1] as i32, enable_flags(args[2] as u32))),
        GET_SCROLL_BAR_INFO => Some(info(args[0], args[1] as i32, args[2])),
        _ => None,
    }
}

fn show_window(hwnd: u64, visible: bool) {
    let _ = crate::nt_window::dispatch(NtCall { service: NtService::ShowWindow,
        args: SyscallArgs { a0: hwnd, a1: if visible { SW_SHOW } else { SW_HIDE }, a2: 0, a3: 0, a4: 0, a5: 0 } });
}

fn production() -> sink::ScrollSink { sink::production(send_message, resume_frame) }

fn send_message(hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64> {
    Some(send::send_for_current(hwnd, message, wparam, lparam))
}

fn resume_frame(token: u64, outcome: crate::nt_window::position::Outcome) -> u64 {
    let mut sink = production();
    sink::resume_frame(token, outcome, &mut sink)
}

fn styled(hwnd: u64, bar: i32) -> Option<bool> {
    let window = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw)?;
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    entry.state.owned_scroll_state(window, bar).ok().map(|state| state.visible)
}

/// Move the named standard bars into or out of the window frame; a scrollbar
/// control instead shows or hides its own window. # C: O(N_windows); # Sleeps: yes
fn show(hwnd: u64, bar: i32, visible: bool) -> u64 {
    if hwnd == 0 { return 0; }
    if bar == SB_CTL { show_window(hwnd, visible); return 1; }
    let Some((horizontal, vertical)) = show_targets(bar, visible) else { return 0; };
    let (touch_horizontal, touch_vertical) = show_touches(bar);
    let mut sink = production();
    let mut changed = false;
    for (target, wanted, touched) in [(SB_HORZ, horizontal, touch_horizontal), (SB_VERT, vertical, touch_vertical)] {
        if !touched { continue; }
        if styled(hwnd, target) == Some(wanted) { continue; }
        let moved = if wanted { sink.show_scrollbar(hwnd, target) } else { sink.hide_scrollbar(hwnd, target) };
        changed |= moved;
    }
    if changed { let _ = sink.frame_changed(hwnd, bar, 0); }
    1
}

fn stored_flags(hwnd: u64, bar: i32) -> Option<u32> {
    let window = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw)?;
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    entry.state.owned_scroll_state(window, bar).ok().map(|state| state.flags)
}

fn store_flags(hwnd: u64, bar: i32, flags: u32) -> bool {
    let Some(window) = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw) else { return false; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return false; };
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return false; };
    entry.state.set_scroll_flags(window, bar, flags).is_ok()
}

/// Store the arrow-disable flags; a request that changes nothing reports so.
/// # C: O(N_windows); # Sleeps: yes
fn enable(hwnd: u64, bar: i32, flags: u32) -> u64 {
    let other_matched = if bar == ipc::win32_window::SB_BOTH {
        let matched = stored_flags(hwnd, SB_VERT) == Some(flags);
        if !store_flags(hwnd, SB_VERT, flags) { return 0; }
        if !matched { let mut sink = production(); sink.repaint_scrollbar(hwnd, SB_VERT, true); }
        matched
    } else { false };
    let target = enable_target(bar);
    let Some(previous) = stored_flags(hwnd, target) else { return 0; };
    if !store_flags(hwnd, target, flags) { return 0; }
    if enable_unchanged(bar, other_matched, previous == flags) { return 0; }
    if let Some(enabled) = control_window_enabled(target, flags) { let _ = crate::nt_window::enable_window_for_current(hwnd, enabled); }
    let mut sink = production();
    sink.repaint_scrollbar(hwnd, target, true);
    1
}

/// Fill one `SCROLLBARINFO`: the bar's screen rectangle, its arrow and thumb
/// metrics, and the accessibility state of each part.
/// # C: O(N_windows); # Sleeps: yes
fn info(hwnd: u64, id: i32, output: u64) -> u64 {
    if defers_to_control(id) {
        return send::send_for_current(hwnd, SBM_GETSCROLLBARINFO, 0, output);
    }
    let Some(bar) = info_bar(id) else { return 0; };
    if output == 0 || uaccess::get_user_u32(output).ok() != Some(SCROLLBARINFO_BYTES as u32) { return 0; }
    let Some(context) = crate::nt_window::nonclient_scroll_context_for_current(hwnd) else { return 0; };
    let Ok(Some(bounds)) = crate::nt_gdi::nonclient_scroll::bounds(context, bar) else { return 0; };
    let Some(window) = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw) else { return 0; };
    let (state, visible, enabled, origin) = {
        let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
        let entries = GUI.lock();
        let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
        let Ok(state) = entry.state.owned_scroll_state(window, bar) else { return 0; };
        let Some(record) = entry.state.get(window) else { return 0; };
        let Some(rect) = entry.state.rect(window) else { return 0; };
        (state, state.visible, record.visible, rect)
    };
    let vertical = bar == SB_VERT;
    let length = if vertical { bounds.bottom - bounds.top } else { bounds.right - bounds.left };
    let Ok(layout) = ipc::win32_gdi::scrollbar_layout(length, state, context.metrics) else { return 0; };
    let mut bytes = [0u8; SCROLLBARINFO_BYTES];
    let mut put = |offset: usize, value: i32| bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    put(0, SCROLLBARINFO_BYTES as i32);
    put(4, bounds.left + origin.left); put(8, bounds.top + origin.top);
    put(12, bounds.right + origin.left); put(16, bounds.bottom + origin.top);
    put(20, layout.arrow_size);
    put(24, layout.thumb_pos);
    put(28, layout.thumb_pos + layout.thumb_size);
    for (index, value) in scrollbar_states(state, bar, visible, enabled).into_iter().enumerate() {
        bytes[36 + index * 4..40 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    if uaccess::copy_to_user(output, &bytes).is_err() { return 0; }
    1
}
