// Canonical Win32 user-settings adapters. Runtime deadlines remain queue data.

use crate::nt_window::GUI;
use alloc::sync::Arc;

/// Read the one canonical GetCaretBlinkTime setting.
/// # C: O(1)
pub(crate) fn get_caret_blink_time() -> u64 { super::USER_SETTINGS.lock().caret_blink_ms() as u64 }

/// Snapshot the canonical setting for a future queue deadline arm.
/// # C: O(1)
pub(crate) fn snapshot_caret_blink_time() -> u32 { get_caret_blink_time() as u32 }

/// Set the canonical setting and update only the current queue's future arm
/// interval; an already-derived deadline is intentionally left untouched.
/// # C: O(GUI entries + queues)
pub(crate) fn set_caret_blink_time(value: u32) -> bool {
    {
        let mut settings = super::USER_SETTINGS.lock();
        settings.set_caret_blink_ms(value);
    }
    let Some(current) = sched::live::current().filter(|task| task.is_nt_personality()) else { return true; };
    let group = Arc::clone(&current.thread_group);
    let mut entries = GUI.lock();
    if let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))) {
        let _ = entry.state.set_current_caret_blink_interval(current.tid as u64, value);
    }
    true
}

/// Double-click interval in milliseconds. # C: O(1)
pub(crate) fn double_click_time_for_current() -> Option<u32> { Some(super::USER_SETTINGS.lock().double_click_ms()) }

/// Store the double-click interval, answering the previous one. # C: O(1)
pub(crate) fn set_double_click_time(value: u32) -> u32 { super::USER_SETTINGS.lock().set_double_click_ms(value) }

/// Hover dwell in milliseconds. # C: O(1)
pub(crate) fn mouse_hover_time_for_current() -> Option<u32> { Some(super::USER_SETTINGS.lock().mouse_hover_ms()) }

/// Store the hover dwell, answering the previous one. # C: O(1)
pub(crate) fn set_mouse_hover_time(value: u32) -> u32 { super::USER_SETTINGS.lock().set_mouse_hover_ms(value) }

/// Warning-beep setting. # C: O(1)
pub(crate) fn beep_enabled() -> bool { super::USER_SETTINGS.lock().beep_enabled() }

/// Store the warning-beep setting, answering the previous one. # C: O(1)
pub(crate) fn set_beep_enabled(value: bool) -> bool { super::USER_SETTINGS.lock().set_beep_enabled(value) }
