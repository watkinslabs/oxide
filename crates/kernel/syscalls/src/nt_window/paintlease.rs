//! Current-thread GUI paint-session lease wrappers (`31fj`).

use alloc::sync::Arc;
use ipc::win32_window::{PaintSession, PaintSessionError, WindowId};
use super::GUI;

/// Bind one fresh canonical HDC to the current thread's existing reservation.
pub(crate) fn bind_paint_dc_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
    let window = WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?;
    let current = sched::live::current().ok_or(PaintSessionError::NotActive)?;
    let group = Arc::clone(&current.thread_group);
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))).ok_or(PaintSessionError::NotActive)?;
    entry.state.bind_paint_dc(window, dc)
}

/// Validate EndPaint's exact HDC while keeping the session active for presentation.
pub(crate) fn validate_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
    let window = WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?;
    let current = sched::live::current().ok_or(PaintSessionError::NotActive)?;
    let group = Arc::clone(&current.thread_group);
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))).ok_or(PaintSessionError::NotActive)?;
    entry.state.validate_paint_session(window, dc)
}

/// Consume the validated current-thread session after presentation.
pub(crate) fn end_for_current(hwnd: u32, dc: u32) -> Result<PaintSession, PaintSessionError> {
    let window = WindowId::from_raw(hwnd).ok_or(PaintSessionError::NotActive)?;
    let current = sched::live::current().ok_or(PaintSessionError::NotActive)?;
    let group = Arc::clone(&current.thread_group);
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group))).ok_or(PaintSessionError::NotActive)?;
    entry.state.end_paint_session(window, dc)
}

/// Consume a current-thread session during HWND destruction before GDI deletion.
pub(crate) fn remove_for_current(hwnd: u32) -> Option<PaintSession> {
    let window = WindowId::from_raw(hwnd)?;
    let current = sched::live::current()?;
    let group = Arc::clone(&current.thread_group);
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, &group)))?;
    entry.state.remove_paint_session(window)
}
