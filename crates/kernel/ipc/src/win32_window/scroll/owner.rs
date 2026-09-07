//! OwnedWindow scrollbar accessors. The parent adds
//! `scroll: [ScrollState; 2]` to `OwnedWindow`; these helpers keep all state
//! attached to that lifetime.

use super::super::{OwnedWindow, ScrollError, ScrollInfo, ScrollOutcome, ScrollState, WindowId, WindowManager, WindowError, SB_HORZ, SB_VERT};

const WS_HSCROLL: u32 = 0x0010_0000;
const WS_VSCROLL: u32 = 0x0020_0000;

fn index(bar: i32) -> Option<usize> {
    match bar { SB_HORZ => Some(0), SB_VERT => Some(1), _ => None }
}

fn style_bit(bar: i32) -> Option<u32> {
    match bar { SB_HORZ => Some(WS_HSCROLL), SB_VERT => Some(WS_VSCROLL), _ => None }
}

impl OwnedWindow {
    /// Keep non-client scrollbar visibility in lockstep with the owning HWND
    /// style. The style is the authority for whether a standard scrollbar
    /// exists; SCROLLINFO transitions update it through set_scrollbar_style.
    pub(crate) fn sync_scrollbar_visibility(&mut self, style: u32) {
        self.scroll[0].visible = style & WS_HSCROLL != 0;
        self.scroll[1].visible = style & WS_VSCROLL != 0;
    }

    pub fn get_scroll_info(&self, bar: i32, info: &mut ScrollInfo) -> Result<bool, ScrollError> {
        let Some(index) = index(bar) else { return Err(ScrollError::InvalidBar); };
        self.scroll[index].fill(info)
    }

    pub fn set_scroll_info(&mut self, bar: i32, info: ScrollInfo, redraw: bool) -> Result<ScrollOutcome, ScrollError> {
        let Some(index) = index(bar) else { return Err(ScrollError::InvalidBar); };
        self.scroll[index].apply_for_bar(bar, info, redraw)
    }

    pub fn scroll_state(&self, bar: i32) -> Result<ScrollState, ScrollError> {
        let Some(index) = index(bar) else { return Err(ScrollError::InvalidBar); };
        Ok(self.scroll[index])
    }
}

impl WindowManager {
    pub fn set_scrollbar_style(&mut self, window: WindowId, bar: i32, visible: bool) -> Result<u32, WindowError> {
        let bit = match bar { SB_HORZ => WS_HSCROLL, SB_VERT => WS_VSCROLL, _ => return Err(WindowError::InvalidParent) };
        let (style, ex_style) = self.window_styles(window).ok_or(WindowError::NoSuchWindow)?;
        let next = if visible { style | bit } else { style & !bit };
        self.set_window_styles(window, next, ex_style).map(|(previous, _)| previous)
    }

    pub fn owned_scroll_state(&self, window: WindowId, bar: i32) -> Result<ScrollState, ScrollError> {
        let Some((_, owned)) = self.windows.iter().find(|(candidate, _)| *candidate == window) else {
            return Err(ScrollError::InvalidWindow);
        };
        owned.scroll_state(bar)
    }

    pub fn get_owned_scroll_info(&self, window: WindowId, bar: i32, info: &mut ScrollInfo) -> Result<bool, ScrollError> {
        let Some((_, owned)) = self.windows.iter().find(|(candidate, _)| *candidate == window) else {
            return Err(ScrollError::InvalidWindow);
        };
        // Standard scrollbar state is addressable only while its HWND style
        // advertises that bar. This preserves the Win32 failure boundary for
        // a window with no WS_HSCROLL/WS_VSCROLL bar.
        let Some(bit) = style_bit(bar) else { return Err(ScrollError::InvalidBar); };
        if owned.record.style & bit == 0 { return Ok(false); }
        owned.get_scroll_info(bar, info)
    }

    pub fn set_owned_scroll_info(&mut self, window: WindowId, bar: i32, info: ScrollInfo, redraw: bool) -> Result<ScrollOutcome, ScrollError> {
        let Some((_, owned)) = self.windows.iter_mut().find(|(candidate, _)| *candidate == window) else {
            return Err(ScrollError::InvalidWindow);
        };
        owned.set_scroll_info(bar, info, redraw)
    }
}

/// `SCROLLBARINFO.rgstate` element count: the bar, then its five parts.
pub const SCROLLBAR_STATE_PARTS: usize = 6;
/// `SCROLLBARINFO` size in bytes: cbSize, rcScrollBar, three metrics plus one
/// reserved word, then six per-part states.
pub const SCROLLBARINFO_BYTES: usize = 4 + 16 + 16 + SCROLLBAR_STATE_PARTS * 4;
pub const STATE_SYSTEM_INVISIBLE: u32 = 0x0000_8000;
pub const STATE_SYSTEM_OFFSCREEN: u32 = 0x0001_0000;
pub const STATE_SYSTEM_UNAVAILABLE: u32 = 0x0000_0001;
pub const STATE_SYSTEM_PRESSED: u32 = 0x0000_0008;

/// Per-part accessibility state a scrollbar reports. `bar` is the whole bar;
/// the remaining entries are the top arrow, the page-up region, the thumb,
/// the page-down region and the bottom arrow, in that order.
/// # C: O(1)
pub fn scrollbar_states(state: ScrollState, bar: i32, styled_visible: bool, control_enabled: bool)
    -> [u32; SCROLLBAR_STATE_PARTS] {
    let mut parts = [0u32; SCROLLBAR_STATE_PARTS];
    if bar != super::super::SB_CTL && !styled_visible { parts[0] |= STATE_SYSTEM_INVISIBLE; }
    if state.min >= state.max - (state.page - 1).max(0) {
        parts[0] |= if parts[0] & STATE_SYSTEM_INVISIBLE == 0 { STATE_SYSTEM_UNAVAILABLE } else { STATE_SYSTEM_OFFSCREEN };
    }
    if bar == super::super::SB_CTL && !control_enabled { parts[0] |= STATE_SYSTEM_UNAVAILABLE; }
    if state.flags & super::super::ESB_DISABLE_LTUP != 0 { parts[1] |= STATE_SYSTEM_UNAVAILABLE; }
    if state.pos == state.min { parts[2] |= STATE_SYSTEM_INVISIBLE; }
    if state.pos >= state.max - 1 { parts[4] |= STATE_SYSTEM_INVISIBLE; }
    if state.flags & super::super::ESB_DISABLE_RTDN != 0 { parts[5] |= STATE_SYSTEM_UNAVAILABLE; }
    parts
}

impl WindowManager {
    /// Store one bar's arrow-disable flags and report whether they changed.
    /// # C: O(N_windows)
    pub fn set_scroll_flags(&mut self, window: WindowId, bar: i32, flags: u32) -> Result<bool, ScrollError> {
        let Some(index) = index(bar) else { return Err(ScrollError::InvalidBar); };
        let Some((_, owned)) = self.windows.iter_mut().find(|(candidate, _)| *candidate == window) else {
            return Err(ScrollError::InvalidWindow);
        };
        let changed = owned.scroll[index].flags != flags;
        owned.scroll[index].flags = flags;
        Ok(changed)
    }
}

#[cfg(test)]
#[path = "tests/states.rs"]
mod state_tests;
