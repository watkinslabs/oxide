//! Canonical per-window scrollbar state and SCROLLINFO policy.

pub const SB_HORZ: i32 = 0;
pub const SB_VERT: i32 = 1;
pub const SB_CTL: i32 = 2;
pub const SIF_RANGE: u32 = 0x0001;
pub const SIF_PAGE: u32 = 0x0002;
pub const SIF_POS: u32 = 0x0004;
pub const SIF_DISABLENOSCROLL: u32 = 0x0008;
pub const SIF_TRACKPOS: u32 = 0x0010;
pub const SIF_ALL: u32 = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS;
pub const SIF_RETURNPREV: u32 = 0x1000;
pub const SCROLLINFO_BYTES: usize = 28;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScrollInfo { pub cb_size: u32, pub mask: u32, pub min: i32, pub max: i32, pub page: u32, pub pos: i32, pub track_pos: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScrollState {
    pub min: i32, pub max: i32, pub page: i32, pub pos: i32, pub track_pos: i32,
    pub tracking: bool, pub visible: bool, pub disabled: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ScrollError { InvalidWindow, InvalidBar, InvalidInfo }

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct ScrollAction {
    pub show: bool, pub hide: bool, pub enable_arrows: bool, pub disable_arrows: bool,
    pub repaint: bool, pub redraw: bool, pub control_message: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScrollOutcome { pub result: i32, pub action: ScrollAction }

impl ScrollInfo {
    pub const fn valid_size(self) -> bool { self.cb_size == 24 || self.cb_size == SCROLLINFO_BYTES as u32 }
    pub const fn valid_mask(self) -> bool { self.mask & !(SIF_ALL | SIF_DISABLENOSCROLL | SIF_RETURNPREV) == 0 }
    pub const fn valid(self) -> bool { self.valid_size() && self.valid_mask() }
}

impl Default for ScrollState { fn default() -> Self { Self::new() } }

impl ScrollState {
    pub const fn new() -> Self { Self { min: 0, max: 0, page: 0, pos: 0, track_pos: 0, tracking: false, visible: false, disabled: false } }

    pub fn apply(&mut self, info: ScrollInfo) -> Result<i32, ScrollError> {
        Ok(self.apply_for_bar(SB_VERT, info, false)?.result)
    }

    pub fn apply_for_bar(&mut self, bar: i32, info: ScrollInfo, redraw: bool) -> Result<ScrollOutcome, ScrollError> {
        if !info.valid() { return Err(ScrollError::InvalidInfo); }
        if !valid_bar(bar) { return Err(ScrollError::InvalidBar); }
        let previous = self.pos;
        let old = *self;
        if info.mask & SIF_PAGE != 0 { self.page = (info.page as i32).max(0); }
        if info.mask & SIF_POS != 0 { self.pos = info.pos; }
        if info.mask & SIF_RANGE != 0 {
            if info.min > info.max || (i64::from(info.max) - i64::from(info.min)) >= 0x8000_0000 {
                self.min = 0; self.max = 0;
            } else { self.min = info.min; self.max = info.max; }
        }
        let span = i64::from(self.max) - i64::from(self.min) + 1;
        self.page = self.page.min(span.max(0).min(i64::from(i32::MAX)) as i32);
        let upper = i64::from(self.max) - i64::from(self.page.saturating_sub(1));
        self.pos = self.pos.max(self.min).min(upper as i32);

        let mut action = ScrollAction { redraw, ..ScrollAction::default() };
        let no_scroll = self.min >= self.max - self.page.saturating_sub(1);
        let page_only = info.mask == SIF_PAGE;
        if bar == SB_CTL { action.control_message = true; }
        if info.mask & (SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL) != 0 && !page_only {
            if no_scroll {
                self.disabled = info.mask & SIF_DISABLENOSCROLL != 0;
                action.disable_arrows = self.disabled && !old.disabled;
                if bar != SB_CTL { self.visible = false; action.hide = old.visible; }
            } else {
                self.disabled = false;
                action.enable_arrows = old.disabled;
                if bar != SB_CTL { self.visible = true; action.show = !old.visible; }
            }
        }
        action.repaint = old != *self;
        Ok(ScrollOutcome { result: if info.mask & SIF_RETURNPREV != 0 { previous } else { self.pos }, action })
    }

    pub fn fill(&self, info: &mut ScrollInfo) -> Result<bool, ScrollError> {
        if !info.valid() { return Err(ScrollError::InvalidInfo); }
        if info.mask & SIF_PAGE != 0 { info.page = self.page.max(0) as u32; }
        if info.mask & SIF_POS != 0 { info.pos = self.pos; }
        if info.mask & SIF_RANGE != 0 { info.min = self.min; info.max = self.max; }
        if info.mask & SIF_TRACKPOS != 0 && info.cb_size == SCROLLINFO_BYTES as u32 {
            info.track_pos = if self.tracking { self.track_pos } else { self.pos };
        }
        Ok(info.mask & SIF_ALL != 0)
    }
}

pub const fn valid_bar(bar: i32) -> bool { matches!(bar, SB_HORZ | SB_VERT | SB_CTL) }

#[path = "scroll/owner.rs"]
pub(crate) mod owner;

#[cfg(test)]
#[path = "scroll/tests.rs"]
mod tests;
