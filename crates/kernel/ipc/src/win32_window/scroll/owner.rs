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
