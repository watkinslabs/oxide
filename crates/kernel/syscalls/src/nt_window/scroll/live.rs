//! Live NtUser scrollbar adapters.
//!
//! User memory is copied before taking `GUI`; action publication and SB_CTL
//! sends happen after releasing it.  The parent module owns the `GuiEntry`
//! fields and raw dispatch registration.  Its proposed field is:
//! `OwnedWindow.scroll: [ipc::win32_window::ScrollState; 2]`.

use alloc::sync::Arc;

use super::{consume_actions, ScrollActionSink, SCROLLINFO_BYTES};
use super::sink::ScrollSink;
use super::pending::Outcome;
use ipc::win32_window::{self, WindowId};
use ipc::win32_window::ScrollInfo;
use crate::nt_window::{GUI, STATUS_INVALID_PARAMETER};

fn current_group() -> Option<Arc<sched::thread_group::ThreadGroup>> {
    let current = sched::live::current()?;
    if !current.is_nt_personality() { return None; }
    Some(Arc::clone(&current.thread_group))
}

fn window_id(hwnd: u64) -> Option<WindowId> {
    u32::try_from(hwnd).ok().and_then(WindowId::from_raw)
}

fn entry_index(entries: &[super::super::GuiEntry], group: &Arc<sched::thread_group::ThreadGroup>) -> Option<usize> {
    entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, group)))
}

fn snapshot_info(address: u64) -> Result<(ScrollInfo, usize), u64> {
    if address == 0 { return Err(STATUS_INVALID_PARAMETER); }
    let mut header = [0u8; 4];
    uaccess::copy_from_user(&mut header, address).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let size = match u32::from_le_bytes(header) as usize {
        24 | SCROLLINFO_BYTES => u32::from_le_bytes(header) as usize,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    let mut bytes = [0u8; SCROLLINFO_BYTES];
    uaccess::copy_from_user(&mut bytes[..size], address).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let info = super::super::scroll::decode_scroll_info(bytes);
    if !info.valid() { return Err(STATUS_INVALID_PARAMETER); }
    Ok((info, size))
}

fn copy_info(address: u64, info: ScrollInfo, size: usize) -> bool {
    let bytes = super::super::scroll::encode_scroll_info(info);
    uaccess::copy_to_user(address, &bytes[..size]).is_ok()
}

/// Implements the live GetScrollInfo path.  The selected state is copied to a
/// stack value while `GUI` is held; the user destination is written only after
/// the lock has been released.
pub(crate) fn get_scroll_info_for_current(hwnd: u64, bar: i32, info_address: u64) -> u64 {
    let Ok((mut requested, size)) = snapshot_info(info_address) else { return 0; };
    if !matches!(bar, win32_window::SB_HORZ | win32_window::SB_VERT) { return 0; }
    let Some(group) = current_group() else { return 0; };
    let Some(window) = window_id(hwnd) else { return 0; };
    let filled = {
        let entries = GUI.lock();
        let Some(entry_index) = entry_index(&entries, &group) else { return 0; };
        let entry = &entries[entry_index];
        if entry.state.get(window).is_none() { return 0; }
        if entry.state.get_owned_scroll_info(window, bar, &mut requested).ok() != Some(true) { return 0; }
        true
    };
    if !filled { return 0; }
    if !copy_info(info_address, requested, size) { return 0; }
    1
}

/// Implements SetScrollInfo against canonical process state.  `hooks` is the
/// compositor/nonclient owner supplied by the parent dispatch layer; it must
/// also implement the real SB_CTL send path.  No callback is made under GUI.
pub(crate) fn set_scroll_info_for_current(
    hwnd: u64, bar: i32, info_address: u64, redraw: bool, hooks: &mut ScrollSink,
) -> u64 {
    let Ok((info, _)) = snapshot_info(info_address) else { return 0; };
    let Some(group) = current_group() else { return 0; };
    let Some(window) = window_id(hwnd) else { return 0; };
    if !win32_window::valid_bar(bar) { return 0; }

    let outcome = if bar == win32_window::SB_CTL {
        // A child scrollbar owns its state and must receive SBM_SETSCROLLINFO;
        // do not create a second kernel shadow state for it.
        None
    } else {
        let mut entries = GUI.lock();
        let Some(entry_index) = entry_index(&entries, &group) else { return 0; };
        let entry = &mut entries[entry_index];
        match entry.state.set_owned_scroll_info(window, bar, info, redraw) {
            Ok(outcome) => Some(outcome),
            Err(_) => return 0,
        }
    };

    if bar == win32_window::SB_CTL {
        return hooks.send_scrollbar_message(hwnd, super::SBM_SETSCROLLINFO, redraw as u64, info_address).unwrap_or(0);
    }
    let Some(outcome) = outcome else { return 0; };
    let result = outcome.result;
    let token = if outcome.action.show || outcome.action.hide {
        let Some(current) = sched::live::current() else { return 0; };
        let tid = current.tid as u64;
        let mut entries = GUI.lock();
        let Some(index) = entry_index(&entries, &group) else { return 0; };
        entries[index].scroll_pending.admit(tid, hwnd, bar, result, redraw, outcome.action.hide)
    } else { None };
    let consumed = consume_actions(hooks, hwnd, bar, info_address, redraw, outcome, token);
    if let Some(token) = token {
        let current = sched::live::current();
        let tid = current.map_or(0, |current| current.tid as u64);
        let mut entries = GUI.lock();
        if let Some(index) = entry_index(&entries, &group) {
            match consumed {
                Outcome::Pending => return super::super::STATUS_PENDING,
                Outcome::Complete(_) => { let _ = entries[index].scroll_pending.complete(tid, token, Outcome::Complete(1)); }
                Outcome::Failed => { let _ = entries[index].scroll_pending.complete(tid, token, Outcome::Failed); return 0; }
            }
        } else { return 0; }
    } else if consumed == Outcome::Pending { return super::super::STATUS_PENDING; }
    if consumed == Outcome::Failed { return 0; }
    result as i64 as u64
}

/// Curie calls this after the frame-change continuation reaches a terminal
/// result. Raster publication and the saved SetScrollInfo position return are
/// deliberately after queue removal and outside GUI.
pub(crate) fn complete_pending_for_current(token: u64, outcome: Outcome, hooks: &mut ScrollSink) -> u64 {
    let Some(current) = sched::live::current() else { return 0; };
    let group = Arc::clone(&current.thread_group);
    let tid = current.tid as u64;
    if outcome == Outcome::Pending { return super::super::STATUS_PENDING; }
    let Some(pending) = ({
        let mut entries = GUI.lock();
        let Some(index) = entry_index(&entries, &group) else { return 0; };
        entries[index].scroll_pending.complete(tid, token, outcome)
    }) else { return 0; };
    if outcome == Outcome::Failed { return 0; }
    if pending.should_repaint() && !hooks.repaint_scrollbar(pending.root, pending.bar) { return 0; }
    pending.result as i64 as u64
}
