//! Desktop cursor position, the clip rectangle that bounds it, and the
//! position history the mouse-move-point query reads back.
//!
//! The virtual screen rectangle is not owned here: the caller resolves it from
//! the compositor and passes it in, so this module carries no second copy of
//! the display geometry.

use alloc::vec::Vec;
use super::{WindowManager, WindowRect};

/// Positions the history retains, matching the recorded depth the mouse
/// move-point query walks.
pub const CURSOR_HISTORY: usize = 64;

/// One recorded cursor position. `info` is the extra-info word the injecting
/// input carried.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CursorPos { pub x: i32, pub y: i32, pub time: u32, pub info: u64 }

/// Clamp one coordinate into `[low, high - 1]`, the inclusive range the clip
/// rectangle admits. An empty range collapses onto its low edge. # C: O(1)
const fn clamp_axis(value: i32, low: i32, high: i32) -> i32 {
    let top = if high > low { high - 1 } else { low };
    if value < low { low } else if value > top { top } else { value }
}

/// Intersect the requested clip with the screen. A request that leaves an
/// inverted rectangle falls back to the whole screen, as does no request.
/// # C: O(1)
pub fn clip_within(request: Option<WindowRect>, screen: WindowRect) -> WindowRect {
    let Some(rect) = request else { return screen; };
    let clipped = WindowRect {
        left: rect.left.max(screen.left), top: rect.top.max(screen.top),
        right: rect.right.min(screen.right), bottom: rect.bottom.min(screen.bottom),
    };
    if clipped.left > clipped.right || clipped.top > clipped.bottom { screen } else { clipped }
}

impl WindowManager {
    /// # C: O(1)
    pub fn cursor_pos(&self) -> (i32, i32) { self.cursor }

    /// Effective clip rectangle: the whole screen while nothing clips.
    /// # C: O(1)
    pub fn clip_cursor_rect(&self, screen: WindowRect) -> WindowRect { clip_within(self.cursor_clip, screen) }

    /// Install a clip rectangle and warp the cursor inside it. A rectangle
    /// whose left edge is past its right, or whose top is past its bottom, is
    /// refused before any state changes. # C: O(1)
    pub fn clip_cursor(&mut self, request: Option<WindowRect>, screen: WindowRect, time: u32) -> bool {
        if let Some(rect) = request {
            if rect.left > rect.right || rect.top > rect.bottom { return false; }
        }
        let rect = clip_within(request, screen);
        self.cursor_clip = request.map(|_| rect);
        let x = clamp_axis(self.cursor.0, rect.left, rect.right);
        let y = clamp_axis(self.cursor.1, rect.top, rect.bottom);
        if (x, y) != self.cursor { self.set_cursor_pos(x, y, screen, time); }
        true
    }

    /// Move the cursor, clamped into the clip rectangle, and record the new
    /// position in the history. Answers whether the position changed.
    /// # C: O(1)
    pub fn set_cursor_pos(&mut self, x: i32, y: i32, screen: WindowRect, time: u32) -> bool {
        let clip = self.clip_cursor_rect(screen);
        let point = (clamp_axis(x, clip.left, clip.right), clamp_axis(y, clip.top, clip.bottom));
        let moved = point != self.cursor;
        self.cursor = point;
        self.cursor_change = time;
        self.record_cursor(point.0, point.1, time, 0);
        moved
    }

    /// Tick count of the last cursor position change. # C: O(1)
    pub fn cursor_last_change(&self) -> u32 { self.cursor_change }

    /// Prepend one position to the history, newest first. # C: O(1)
    pub fn record_cursor(&mut self, x: i32, y: i32, time: u32, info: u64) {
        self.cursor_latest = (self.cursor_latest + CURSOR_HISTORY - 1) % CURSOR_HISTORY;
        self.cursor_history[self.cursor_latest] = CursorPos { x, y, time, info };
    }

    /// The history newest-first. # C: O(CURSOR_HISTORY)
    pub fn cursor_history(&self) -> [CursorPos; CURSOR_HISTORY] {
        let mut out = [CursorPos::default(); CURSOR_HISTORY];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = self.cursor_history[(index + self.cursor_latest) % CURSOR_HISTORY];
        }
        out
    }
}

/// Positions from the first history entry matching `probe`, newest first.
/// A zero probe time matches any time. Answers `None` when the probe names no
/// recorded position, which the caller reports as a point-not-found refusal.
/// # C: O(CURSOR_HISTORY)
pub fn move_points_from(history: &[CursorPos; CURSOR_HISTORY], probe: CursorPos, count: usize) -> Option<Vec<CursorPos>> {
    let start = history.iter().position(|pos| pos.x == probe.x && pos.y == probe.y
        && (probe.time == 0 || probe.time == pos.time))?;
    let end = (start + count).min(CURSOR_HISTORY);
    Some(history[start..end].to_vec())
}



#[cfg(test)]
#[path = "tests/cursor_pos.rs"]
mod tests;
