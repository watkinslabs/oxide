//! What a show projects onto the window stack, beside the visibility it changes.
//!
//! The reference finishes every show that reaches its positioning step by
//! placing the window at the top of its band and activating it; which of the
//! two a command suppresses, and which a child window suppresses, is decided
//! by `nt_window_policy::show_projection`. Publishing only the visibility
//! leaves a newly mapped window wherever the display already had it in the
//! stack, so an owned dialog appears under the owner it was opened over.
use super::*;
use crate::nt_window_policy::{show_projection, ShowProjection};
use ipc::win32_window::{PositionOrder, WindowId, WindowPosition};

/// `SWP_NOACTIVATE`, the one positioning flag this projection ever sets.
const NOACTIVATE: u32 = 0x0010;
/// Insertion value naming the top of a window's own band.
const INSERT_TOP: u64 = 0;
/// Insertion value naming the top of the topmost band.
const INSERT_TOPMOST: u64 = u64::MAX;
const WS_EX_TOPMOST: u32 = 0x0000_0008;

/// Publish one completed show: its visibility, then the stack and activation
/// the reference's positioning step performs. Call after the canonical GUI
/// lock is released. `was_visible` is the visibility the show replaced.
/// # C: O(processes + windows) + publication; # Sleeps: yes
pub(crate) fn publish_for_current(hwnd: u64, command: u64, was_visible: bool) -> Result<(), crate::nt_compositor::TransportError> {
    bridge::publish_visibility_current(hwnd)?;
    let Some(id) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return Ok(()); };
    let Some(style) = style_for_current(id) else { return Ok(()); };
    let Some(projection) = show_projection(command, style, was_visible).filter(|projection| projection.projects()) else { return Ok(()); };
    // A stack the canonical owner refuses is not a failed show: the reference
    // discards its positioning result too, and the window is already visible.
    let Some(stack) = apply_for_current(id, projection) else { return Ok(()); };
    for (window, insertion) in stack { bridge::publish_position_current(window, Some(insertion), false)?; }
    if projection.activate { bridge::publish_position_current(hwnd, None, true)?; }
    Ok(())
}

/// # C: O(processes + windows)
fn style_for_current(id: WindowId) -> Option<u32> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some(entry.state.get(id)?.style)
}

/// Lift the window in the canonical order and report the band the display has
/// to be told about, top-to-bottom, exactly as an explicit positioning does.
/// # C: O(processes + windows²)
fn apply_for_current(id: WindowId, projection: ShowProjection) -> Option<Vec<(u64, u64)>> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let record = entry.state.get(id)?;
    let rect = entry.state.rect(id)?;
    let change = WindowPosition { window: id, rect, client: None,
        order: projection.raise.then_some(PositionOrder::Top), visible: None,
        flags: if projection.activate { 0 } else { NOACTIVATE }, notify_geometry: false };
    entry.state.apply_position(cur.tid as u64, change).ok()?;
    entry.foreground = entry.state.active_window().is_some();
    if !projection.raise { return Some(Vec::new()); }
    let mut stack = Vec::new();
    let mut previous = None;
    for sibling in entry.state.position_siblings(record.parent).into_iter().rev() {
        let Some(r) = entry.state.get(sibling) else { continue; };
        if !r.presentation_ready { continue; }
        let insertion = previous.unwrap_or(if r.ex_style & WS_EX_TOPMOST != 0 { INSERT_TOPMOST } else { INSERT_TOP });
        stack.push((sibling.raw() as u64, insertion));
        previous = Some(sibling.raw() as u64);
    }
    Some(stack)
}
