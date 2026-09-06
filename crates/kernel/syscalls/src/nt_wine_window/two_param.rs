//! `NtUserCallTwoParam` multiplexer: monitor lookup, DPI metrics and frame
//! adjustment selected by a code.
extern crate alloc;
use alloc::vec::Vec;
use syscall::nt_compositor::Monitor;

pub(crate) const ORDINAL: u64 = 0x133e;
pub(crate) const GET_DIALOG_PROC: u32 = 0;
pub(crate) const GET_MENU_INFO: u32 = 1;
pub(crate) const GET_MONITOR_INFO: u32 = 2;
pub(crate) const GET_SYSTEM_METRICS_FOR_DPI: u32 = 3;
pub(crate) const MONITOR_FROM_RECT: u32 = 4;
pub(crate) const SET_ICON_PARAM: u32 = 5;
pub(crate) const SET_IME_COMPOSITION_RECT: u32 = 6;
pub(crate) const ADJUST_WINDOW_RECT: u32 = 7;
pub(crate) const GET_VIRTUAL_SCREEN_RECT: u32 = 8;
pub(crate) const ALLOC_WINPROC: u32 = 9;

pub(crate) const MONITOR_DEFAULTTOPRIMARY: u64 = 1;
pub(crate) const MONITOR_DEFAULTTONEAREST: u64 = 2;
pub(crate) const MONITORINFOF_PRIMARY: u32 = 1;
pub(crate) const MONITORINFO_BYTES: usize = 40;
pub(crate) const MONITORINFOEXW_BYTES: usize = 104;
pub(crate) const RECT_BYTES: usize = 16;
pub(crate) const ADJUST_PARAMS_BYTES: usize = 16;
const DEVICE_NAME: &[u8] = b"\\\\.\\DISPLAY";

const WS_BORDER: u32 = 0x0080_0000;
const WS_DLGFRAME: u32 = 0x0040_0000;
const WS_CAPTION: u32 = WS_BORDER | WS_DLGFRAME;
const WS_THICKFRAME: u32 = 0x0004_0000;
const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
const WS_EX_STATICEDGE: u32 = 0x0002_0000;
const SM_CYCAPTION: i32 = 4;
const SM_CXDLGFRAME: i32 = 7;
const SM_CXFRAME: i32 = 32;
const SM_CYMENU: i32 = 15;
const SM_CXEDGE: i32 = 45;
const SM_CYEDGE: i32 = 46;
const SM_CYSMCAPTION: i32 = 51;
const SM_CXPADDEDBORDER: i32 = 92;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Rect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

impl Rect {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RECT_BYTES { return None; }
        let at = |o: usize| i32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        Some(Self { left: at(0), top: at(4), right: at(8), bottom: at(12) })
    }
    pub(crate) fn encode(self) -> [u8; RECT_BYTES] {
        let mut out = [0u8; RECT_BYTES];
        for (i, v) in [self.left, self.top, self.right, self.bottom].iter().enumerate() { out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes()); }
        out
    }
    fn from_monitor(r: syscall::nt_compositor::Rect) -> Self {
        Self { left: r.x, top: r.y, right: r.x.saturating_add(r.width as i32), bottom: r.y.saturating_add(r.height as i32) }
    }
    fn intersect(self, other: Self) -> Option<Self> {
        let r = Self { left: self.left.max(other.left), top: self.top.max(other.top), right: self.right.min(other.right), bottom: self.bottom.min(other.bottom) };
        (r.right > r.left && r.bottom > r.top).then_some(r)
    }
    fn inflate(&mut self, dx: i32, dy: i32) { self.left -= dx; self.right += dx; self.top -= dy; self.bottom += dy; }
}

/// Monitor handles are the 1-based position in the desktop snapshot; the
/// snapshot is fetched per call so a stale handle answers nothing.
/// # C: O(1)
pub(crate) fn monitor_for_handle(handle: u64, monitors: &[Monitor]) -> Option<(usize, Monitor)> {
    let index = usize::try_from(handle.checked_sub(1)?).ok()?;
    monitors.get(index).map(|m| (index, *m))
}

/// Largest intersecting area wins; DEFAULTTONEAREST falls back to the
/// smallest edge distance; DEFAULTTOPRIMARY falls back to the primary.
/// # C: O(monitors)
pub(crate) fn monitor_from_rect(rect: Rect, flags: u64, monitors: &[Monitor], primary: Option<usize>) -> u64 {
    let mut rect = rect;
    if rect.right <= rect.left || rect.bottom <= rect.top { rect.right = rect.left + 1; rect.bottom = rect.top + 1; }
    let mut found = None; let mut max_area = 0u64;
    let mut nearest = None; let mut min_distance = u64::MAX;
    for (index, monitor) in monitors.iter().enumerate() {
        let mr = Rect::from_monitor(monitor.monitor);
        if let Some(i) = mr.intersect(rect) {
            let area = ((i.right - i.left) as u64) * ((i.bottom - i.top) as u64);
            if area > max_area { max_area = area; found = Some(index); }
        }
        if found.is_none() && flags & MONITOR_DEFAULTTONEAREST != 0 {
            let x = if rect.right <= mr.left { mr.left - rect.right } else if mr.right <= rect.left { rect.left - mr.right } else { 0 } as u64;
            let y = if rect.bottom <= mr.top { mr.top - rect.bottom } else if mr.bottom <= rect.top { rect.top - mr.bottom } else { 0 } as u64;
            let distance = x * x + y * y;
            if distance < min_distance { min_distance = distance; nearest = Some(index); }
        }
    }
    let primary = if found.is_none() && flags & MONITOR_DEFAULTTOPRIMARY != 0 { primary } else { None };
    found.or(primary).or(nearest).map(|index| index as u64 + 1).unwrap_or(0)
}

/// Caller-declared size selects MONITORINFO or MONITORINFOEXW; anything else
/// is rejected before any write. Returns the bytes to publish. # C: O(1)
pub(crate) fn monitor_info(handle: u64, cb_size: u32, monitors: &[Monitor], primary: Option<usize>) -> Option<Vec<u8>> {
    let size = cb_size as usize;
    if size != MONITORINFO_BYTES && size != MONITORINFOEXW_BYTES { return None; }
    let (index, monitor) = monitor_for_handle(handle, monitors)?;
    let area = Rect::from_monitor(monitor.monitor);
    let work = Rect::from_monitor(monitor.workarea).intersect(area).unwrap_or(area);
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&cb_size.to_le_bytes());
    out.extend_from_slice(&area.encode());
    out.extend_from_slice(&work.encode());
    out.extend_from_slice(&(if primary == Some(index) { MONITORINFOF_PRIMARY } else { 0 }).to_le_bytes());
    if size == MONITORINFOEXW_BYTES {
        let mut name = [0u16; 32];
        let digits = alloc::format!("{}", index + 1);
        for (slot, byte) in name.iter_mut().zip(DEVICE_NAME.iter().chain(digits.as_bytes())) { *slot = u16::from(*byte); }
        for unit in name { out.extend_from_slice(&unit.to_le_bytes()); }
    }
    Some(out)
}

/// Union of every monitor rectangle. # C: O(monitors)
pub(crate) fn virtual_screen_rect(monitors: &[Monitor]) -> Option<Rect> {
    let mut rects = monitors.iter().map(|m| Rect::from_monitor(m.monitor));
    let first = rects.next()?;
    Some(rects.fold(first, |acc, r| Rect { left: acc.left.min(r.left), top: acc.top.min(r.top), right: acc.right.max(r.right), bottom: acc.bottom.max(r.bottom) }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdjustParams { pub style: u32, pub ex_style: u32, pub menu: bool, pub dpi: u32 }

impl AdjustParams {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ADJUST_PARAMS_BYTES { return None; }
        let at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        Some(Self { style: at(0), ex_style: at(4), menu: at(8) != 0, dpi: at(12) })
    }
}

/// Frame growth from the client rectangle, in the metric owner's units.
/// `metric` answers SM_* indexes with the nonclient defaults already applied.
/// # C: O(1)
pub(crate) fn adjust_window_rect(rect: Rect, params: AdjustParams, metric: impl Fn(i32) -> i32) -> Rect {
    let mut rect = rect;
    let (style, ex_style) = (params.style, params.ex_style);
    let mut adjust = if ex_style & (WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME) == WS_EX_STATICEDGE { 1 }
        else if ex_style & WS_EX_DLGMODALFRAME != 0 || style & (WS_THICKFRAME | WS_DLGFRAME) != 0 { 2 } else { 0 };
    // Resize border = SM_CXFRAME beyond the dialog frame, plus the padded border.
    if style & WS_THICKFRAME != 0 { adjust += metric(SM_CXFRAME) - metric(SM_CXDLGFRAME) + metric(SM_CXPADDEDBORDER); }
    if style & (WS_BORDER | WS_DLGFRAME) != 0 || ex_style & WS_EX_DLGMODALFRAME != 0 { adjust += 1; }
    rect.inflate(adjust, adjust);
    if style & WS_CAPTION == WS_CAPTION {
        rect.top -= if ex_style & WS_EX_TOOLWINDOW != 0 { metric(SM_CYSMCAPTION) } else { metric(SM_CYCAPTION) };
    }
    if params.menu { rect.top -= metric(SM_CYMENU); }
    if ex_style & WS_EX_CLIENTEDGE != 0 { rect.inflate(metric(SM_CXEDGE), metric(SM_CYEDGE)); }
    rect
}

#[cfg(target_os = "oxide-kernel")]
#[path = "two_param/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/two_param.rs"]
mod tests;
