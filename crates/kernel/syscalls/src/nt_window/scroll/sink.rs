//! Concrete SetScrollInfo side-effect sink.
//!
//! This is the executable bridge between canonical scroll policy, native
//! frame recalculation and Mc's nonclient raster adapter. The function
//! pointers are integration seams for those existing owners, not alternate
//! state or generic syscall policy.

use alloc::sync::Arc;

use super::super::{position, GUI};
use ipc::win32_window::{ScrollState, WindowId};
use crate::nt_window::position::{Continuation, Outcome as PositionOutcome};
use crate::nt_wine_window::position::Request;
use super::pending::Outcome;

const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOMOVE: u32 = 0x0002;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_FRAMECHANGED: u32 = 0x0020;

pub(crate) type NonclientRepaint = fn(hwnd: u64, bar: i32, state: ScrollState) -> bool;
pub(crate) type ScrollSend = fn(hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64>;
pub(crate) type FrameResume = fn(token: u64, outcome: PositionOutcome) -> u64;

fn map_position_outcome(outcome: PositionOutcome) -> Outcome {
    match outcome {
        PositionOutcome::Complete(true) => Outcome::Complete(1),
        PositionOutcome::Complete(false) | PositionOutcome::Failed => Outcome::Failed,
        PositionOutcome::Pending => Outcome::Pending,
    }
}

pub(crate) struct ScrollSink {
    repaint: NonclientRepaint,
    send: ScrollSend,
    resume: FrameResume,
}

impl ScrollSink {
    pub(crate) const fn new(repaint: NonclientRepaint, send: ScrollSend, resume: FrameResume) -> Self { Self { repaint, send, resume } }

    fn current_entry(hwnd: u64) -> Option<(Arc<sched::thread_group::ThreadGroup>, u64, WindowId)> {
        let current = sched::live::current()?;
        if !current.is_nt_personality() { return None; }
        let window = u32::try_from(hwnd).ok().and_then(WindowId::from_raw)?;
        Some((Arc::clone(&current.thread_group), current.tid as u64, window))
    }

    fn mutate_visibility(&mut self, hwnd: u64, bar: i32, visible: bool) -> bool {
        let Some((group, tid, window)) = Self::current_entry(hwnd) else { return false; };
        let mut entries = GUI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return false; };
        let _ = tid;
        entry.state.set_scrollbar_style(window, bar, visible).is_ok()
    }

    fn state(&self, hwnd: u64, bar: i32) -> Option<ScrollState> {
        let Some((group, _, window)) = Self::current_entry(hwnd) else { return None; };
        let entries = GUI.lock();
        let entry = entries.iter().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
        entry.state.owned_scroll_state(window, bar).ok()
    }

    fn frame_changed(&mut self, hwnd: u64, token: u64) -> Outcome {
        let Some(context) = position::position_context_for_current(hwnd) else { return Outcome::Failed; };
        let request = Request { hwnd, rect: context.rect, order: None, visible: None,
            flags: SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED };
        map_position_outcome(position::position_apply_resumable_for_current(
            request,
            Some(Continuation { token, resume: self.resume }),
        ))
    }
}

/// Construct the production sink with Mc's canonical nonclient raster path.
/// The message sender and terminal resume callback remain Main-owned seams.
pub(crate) fn production(
    send: ScrollSend,
    resume: FrameResume,
) -> ScrollSink {
    ScrollSink::new(crate::nt_gdi::repaint_nonclient_scroll_for_current, send, resume)
}

/// Curie's terminal position callback enters here.  The saved SetScrollInfo
/// result is released only after the pending record is removed and the
/// nonclient raster hook succeeds.
pub(crate) fn resume_frame(
    token: u64,
    outcome: PositionOutcome,
    sink: &mut ScrollSink,
) -> u64 {
    super::live::complete_pending_for_current(token, map_position_outcome(outcome), sink)
}

#[cfg(test)]
#[path = "tests/sink.rs"]
mod tests;

impl super::ScrollActionSink for ScrollSink {
    fn show_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool { self.mutate_visibility(hwnd, bar, true) }
    fn hide_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool { self.mutate_visibility(hwnd, bar, false) }
    fn enable_scroll_arrows(&mut self, _: u64, _: i32) -> bool { true }
    fn disable_scroll_arrows(&mut self, _: u64, _: i32) -> bool { true }
    fn frame_changed(&mut self, hwnd: u64, _: i32, token: u64) -> Outcome { self.frame_changed(hwnd, token) }
    fn repaint_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool {
        let Some(state) = self.state(hwnd, bar) else { return false; };
        (self.repaint)(hwnd, bar, state)
    }
    fn send_scrollbar_message(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64> {
        (self.send)(hwnd, message, wparam, lparam)
    }
}
