//! Per-thread mouse hover and leave tracking.
//!
//! One record per thread names the window being tracked, the events wanted and
//! the hover dwell. A query answers the record; a cancel clears the named
//! events and drops the record once neither hover nor leave remains.

use alloc::vec::Vec;
use super::{WindowId, WindowManager};

pub const TME_HOVER: u32 = 0x0000_0001;
pub const TME_LEAVE: u32 = 0x0000_0002;
pub const TME_NONCLIENT: u32 = 0x0000_0010;
pub const TME_QUERY: u32 = 0x4000_0000;
pub const TME_CANCEL: u32 = 0x8000_0000;
/// Dwell request meaning "use the system hover time".
pub const HOVER_DEFAULT: u32 = 0xffff_ffff;
/// System hover dwell in milliseconds when no setting overrides it.
pub const DEFAULT_HOVER_TIME: u32 = 400;

/// One thread's tracking record. A record with no window tracks nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MouseTracking { pub hwnd: Option<WindowId>, pub flags: u32, pub hover_time: u32 }

/// What a tracking request asks the caller to do next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackAction {
    /// Answer the stored record without changing it.
    Query(MouseTracking),
    /// The pointer is outside the tracked window: post the leave message now
    /// (non-client when the request asked for it) and keep the stored record.
    PostLeave { hwnd: WindowId, nonclient: bool },
    /// Track this window, arming the hover timer for `hover_time` ms.
    Track(MouseTracking),
    /// Stop tracking; kill any armed hover timer for `hwnd`.
    Stop { hwnd: Option<WindowId> },
}

/// Per-thread tracking records.
#[derive(Default)]
pub struct MouseTracks { entries: Vec<(u64, MouseTracking)> }

impl MouseTracks {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: Vec::new() } }
    /// # C: O(N_threads)
    pub fn get(&self, tid: u64) -> MouseTracking {
        self.entries.iter().find(|(owner, _)| *owner == tid).map_or(MouseTracking::default(), |(_, record)| *record)
    }
    /// # C: O(N_threads)
    pub fn set(&mut self, tid: u64, record: MouseTracking) {
        if let Some((_, slot)) = self.entries.iter_mut().find(|(owner, _)| *owner == tid) { *slot = record; return; }
        if self.entries.try_reserve(1).is_err() { return; }
        self.entries.push((tid, record));
    }
}

/// Decide one tracking request. `pointer_inside` reports whether the pointer
/// currently sits over the requested window. # C: O(1)
pub fn track_action(stored: MouseTracking, hwnd: WindowId, flags: u32, hover_time: u32,
    pointer_inside: bool, system_hover: u32) -> TrackAction {
    if flags & TME_QUERY != 0 { return TrackAction::Query(stored); }
    if flags & TME_CANCEL != 0 {
        if stored.hwnd != Some(hwnd) { return TrackAction::Query(stored); }
        let remaining = stored.flags & !(flags & !TME_CANCEL);
        if remaining & (TME_HOVER | TME_LEAVE) == 0 { return TrackAction::Stop { hwnd: stored.hwnd }; }
        return TrackAction::Track(MouseTracking { hwnd: stored.hwnd, flags: remaining, hover_time: stored.hover_time });
    }
    if flags & TME_LEAVE != 0 && !pointer_inside {
        return TrackAction::PostLeave { hwnd, nonclient: flags & TME_NONCLIENT != 0 };
    }
    if !pointer_inside { return TrackAction::Stop { hwnd: stored.hwnd }; }
    let requested = if flags & TME_HOVER != 0 { hover_time } else { HOVER_DEFAULT };
    let dwell = if requested == HOVER_DEFAULT || requested == 0 { system_hover } else { requested };
    TrackAction::Track(MouseTracking { hwnd: Some(hwnd), flags, hover_time: dwell })
}

impl WindowManager {
    /// # C: O(N_threads)
    pub fn mouse_tracking(&self, tid: u64) -> MouseTracking { self.tracks.get(tid) }
    /// # C: O(N_threads)
    pub fn set_mouse_tracking(&mut self, tid: u64, record: MouseTracking) { self.tracks.set(tid, record) }
    /// Whether the screen cursor sits inside one window's rectangle.
    /// # C: O(N_windows)
    pub fn pointer_inside(&self, id: WindowId) -> bool {
        let Some(rect) = self.rect(id) else { return false; };
        let (x, y) = self.cursor;
        x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
    }
}

#[cfg(test)]
#[path = "tests/mouse_track.rs"]
mod tests;
