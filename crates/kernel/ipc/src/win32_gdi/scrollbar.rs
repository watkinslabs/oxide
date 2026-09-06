//! Snapshot-only nonclient scrollbar raster; 31fl§2.
use super::{GdiError, GdiManager, Rect};
use crate::win32_window::ScrollState;

const MIN_TRACK: i64 = 4;
const MIN_THUMB: i64 = 17;
const BASE_DPI: i64 = 96;
const RGB_MASK: u32 = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrollMetrics { pub arrow_size: i32, pub dpi: u32 }

/// Colors are surface XRGB, not packed COLORREF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrollColors {
    pub face: u32, pub highlight: u32, pub light: u32, pub shadow: u32,
    pub dark_shadow: u32, pub text: u32, pub window: u32, pub track: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrollPart { None, FirstArrow, LastArrow, FirstPage, LastPage, Thumb }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrollDrawOutcome { Hidden, Clipped, Painted(Rect) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrollLayout { pub arrow_size: i32, pub thumb_pos: i32, pub thumb_size: i32 }

/// Axis-relative geometry from an admitted canonical snapshot. # C: O(1)
pub fn scrollbar_layout(length: i32, state: ScrollState, metrics: ScrollMetrics) -> Result<ScrollLayout, GdiError> {
    let span = i64::from(state.max) - i64::from(state.min) + 1;
    if length < 0 || metrics.arrow_size <= 0 || metrics.dpi == 0 || state.page < 0
        || span <= 0 || span > i64::from(i32::MAX) + 1 || i64::from(state.page) > span {
        return Err(GdiError::InvalidDimensions);
    }
    let length = i64::from(length);
    let arrow = i64::from(metrics.arrow_size);
    if length <= 2 * arrow + MIN_TRACK {
        return Ok(ScrollLayout { arrow_size: ((length - MIN_TRACK).max(0) / 2) as i32, thumb_pos: 0, thumb_size: 0 });
    }
    let track = length - 2 * arrow;
    let thumb = if state.page == 0 { arrow } else {
        muldiv(track, i64::from(state.page), span).max(muldiv(MIN_THUMB, i64::from(metrics.dpi), BASE_DPI))
    };
    if thumb > track || state.disabled { return Ok(ScrollLayout { arrow_size: arrow as i32, thumb_pos: 0, thumb_size: 0 }); }
    let upper = i64::from(state.max) - i64::from((state.page - 1).max(0));
    let min = i64::from(state.min);
    let pos = i64::from(if state.tracking { state.track_pos } else { state.pos }).clamp(min, upper.max(min));
    let offset = if upper <= min { 0 } else { muldiv(track - thumb, pos - min, upper - min) };
    Ok(ScrollLayout { arrow_size: arrow as i32, thumb_pos: (arrow + offset) as i32, thumb_size: thumb as i32 })
}

impl GdiManager {
    /// Paint copied scrollbar state without changing DC attributes or window state. # C: O(DCs + clipped pixels)
    pub fn draw_nonclient_scrollbar(&mut self, dc: u32, bounds: Rect, vertical: bool, state: ScrollState,
        metrics: ScrollMetrics, colors: ScrollColors, pressed: ScrollPart) -> Result<ScrollDrawOutcome, GdiError> {
        let mut target = self.raster_dc(dc)?;
        let width = bounds.right.checked_sub(bounds.left).filter(|v| *v >= 0).ok_or(GdiError::InvalidDimensions)?;
        let height = bounds.bottom.checked_sub(bounds.top).filter(|v| *v >= 0).ok_or(GdiError::InvalidDimensions)?;
        let layout = scrollbar_layout(if vertical { height } else { width }, state, metrics)?;
        if [colors.face, colors.highlight, colors.light, colors.shadow, colors.dark_shadow, colors.text,
            colors.window, colors.track].iter().any(|color| color & !RGB_MASK != 0) { return Err(GdiError::InvalidDimensions); }
        if !state.visible { return Ok(ScrollDrawOutcome::Hidden); }
        let clip = target.bounds();
        let drawn = Rect { left: bounds.left.max(clip.left), top: bounds.top.max(clip.top),
            right: bounds.right.min(clip.right), bottom: bounds.bottom.min(clip.bottom) };
        if drawn.left >= drawn.right || drawn.top >= drawn.bottom { return Ok(ScrollDrawOutcome::Clipped); }
        let length = i64::from(if vertical { height } else { width });
        let breadth = i64::from(if vertical { width } else { height });
        let mut painted: Option<Rect> = None;
        for y in drawn.top..drawn.bottom { for x in drawn.left..drawn.right {
            let (axis, cross) = if vertical { (i64::from(y) - i64::from(bounds.top), i64::from(x) - i64::from(bounds.left)) }
                else { (i64::from(x) - i64::from(bounds.left), i64::from(y) - i64::from(bounds.top)) };
            let color = raster(axis, cross, length, breadth, vertical, layout, colors, state.disabled, pressed, x, y);
            if !target.update(x, y, |_| color) { continue; }
            painted = Some(match painted { None => Rect { left: x, top: y, right: x + 1, bottom: y + 1 },
                Some(r) => Rect { left: r.left.min(x), top: r.top.min(y), right: r.right.max(x + 1), bottom: r.bottom.max(y + 1) } });
        } }
        Ok(painted.map(ScrollDrawOutcome::Painted).unwrap_or(ScrollDrawOutcome::Clipped))
    }
}

fn muldiv(value: i64, numerator: i64, denominator: i64) -> i64 { (value * numerator + denominator / 2) / denominator }

fn raster(axis: i64, cross: i64, length: i64, breadth: i64, vertical: bool, layout: ScrollLayout,
    colors: ScrollColors, disabled: bool, pressed: ScrollPart, x: i32, y: i32) -> u32 {
    let arrow = i64::from(layout.arrow_size);
    let first = axis < arrow;
    if first || axis >= length - arrow {
        let local = if first { axis } else { axis - (length - arrow) };
        let pushed = !disabled && pressed == if first { ScrollPart::FirstArrow } else { ScrollPart::LastArrow };
        let (px, py, w, h) = if vertical { (cross, local, breadth, arrow) } else { (local, cross, arrow, breadth) };
        let base = button(px, py, w, h, colors, pushed);
        let side = w.min(h);
        if side < 3 { return base; }
        let d = side - 2;
        let tri = (290 * d / 1000 - 1).max(2);
        let center = 470 * d / 1000 + 2;
        let tip = 687 * d / 1000 + 1;
        let (a, b) = if vertical { (py - (h - side) / 2, px - (w - side) / 2) }
            else { (px - (w - side) / 2, py - (h - side) / 2) };
        let tip = if first { side - tip } else { tip };
        let inside = |a: i64, b: i64| { let depth = if first { a - tip } else { tip - a };
            depth >= 0 && depth <= tri && (b - center).abs() <= depth };
        // Inactive arrows retain the offset highlight under their shadow glyph.
        let mut result = if disabled && inside(a, b) { colors.highlight } else { base };
        let shift = i64::from(disabled || !pushed);
        if inside(a + shift, b + shift) { result = if disabled { colors.shadow } else { colors.text }; }
        return result;
    }
    let thumb = i64::from(layout.thumb_pos);
    let size = i64::from(layout.thumb_size);
    if size > 0 && axis >= thumb && axis < thumb + size {
        let (px, py, w, h) = if vertical { (cross, axis - thumb, breadth, size) } else { (axis - thumb, cross, size, breadth) };
        return button(px, py, w, h, colors, false);
    }
    let color = if colors.highlight == colors.window {
        if (x ^ y) & 1 == 0 { colors.highlight } else { colors.face }
    } else { colors.track };
    let selected = size > 0 && !disabled && ((axis < thumb && pressed == ScrollPart::FirstPage)
        || (axis >= thumb + size && pressed == ScrollPart::LastPage));
    if selected { color ^ RGB_MASK } else { color }
}

fn button(x: i64, y: i64, width: i64, height: i64, c: ScrollColors, pushed: bool) -> u32 {
    if pushed {
        if x == 0 || y == 0 || x == width - 1 || y == height - 1 { return c.shadow; }
        return c.face;
    }
    if y == height - 1 || x == width - 1 { c.dark_shadow }
    else if y == 0 || x == 0 { c.light }
    else if y == height - 2 || x == width - 2 { c.shadow }
    else if y == 1 || x == 1 { c.highlight }
    else { c.face }
}

#[cfg(test)]
#[path = "tests/scrollbar.rs"]
mod tests;
