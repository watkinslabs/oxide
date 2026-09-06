//! Sleepable submission follows released GUI/GDI ownership.
use super::*;
use alloc::sync::Arc;
use crate::nt_gdi::{GDI, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, submit_frame};

/// Sink for canonical scrollbar actions; success requires a Presented ACK.
/// # C: O(processes + DCs + frame pixels); # Sleeps: compositor completion
pub(crate) fn repaint_nonclient_scroll_for_current(hwnd: u64, bar: i32, scroll: ScrollState) -> bool {
    let Ok(hwnd) = u32::try_from(hwnd) else { return false; };
    let Some(current) = sched::live::current().filter(|current| current.is_nt_personality()) else { return false; };
    let Some(context) = crate::nt_window::nonclient_scroll_context_for_current(u64::from(hwnd)) else { return false; };
    let group = Arc::downgrade(&current.thread_group);
    let frame = {
        let mut entries = GDI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) else { return false; };
        let Ok((dc, outcome)) = render(&mut entry.state, hwnd, bar, scroll, context) else { return false; };
        // Hidden does not erase the old bar. Frame recalculation/repaint owns
        // removal; neither Hidden nor Clipped proves a submitted repaint.
        if !matches!(outcome, ScrollDrawOutcome::Painted(_)) { return false; }
        let Some((width, height, pixels)) = entry.state.surface(dc) else { return false; };
        crate::nt_gdi_frame::snapshot(hwnd, 1, width, height, pixels).map_err(|_| STATUS_INVALID_PARAMETER)
    };
    submit_frame(frame) == STATUS_SUCCESS
}
