//! Nonclient scroll raster/presentation boundary; 31fl§2.
use ipc::win32_gdi::{GdiError, GdiManager, Rect, ScrollColors, ScrollDrawOutcome, ScrollMetrics, ScrollPart};
use ipc::win32_window::{ScrollState, WindowRect, SB_HORZ, SB_VERT};

const WS_HSCROLL: u32 = 0x0010_0000;
const WS_VSCROLL: u32 = 0x0020_0000;
const WS_EX_LEFTSCROLLBAR: u32 = 0x0000_4000;

/// GUI geometry is copied before entering GDI; client coordinates are window-relative.
#[derive(Clone, Copy)]
pub(crate) struct NonclientScrollContext {
    pub window: WindowRect, pub client: Rect, pub style: u32, pub ex_style: u32,
    pub metrics: ScrollMetrics, pub colors: ScrollColors, pub pressed: ScrollPart,
}

/// Convert same-parent coordinate snapshots exactly once, without screen-origin inference.
/// Zero client extents remain valid. # C: O(1)
pub(crate) fn nonclient_scroll_context(window: WindowRect, client: WindowRect, style: u32, ex_style: u32,
    metrics: ScrollMetrics, colors: ScrollColors, pressed: ScrollPart) -> Option<NonclientScrollContext> {
    let width = window.right.checked_sub(window.left).filter(|n| *n >= 0)?;
    let height = window.bottom.checked_sub(window.top).filter(|n| *n >= 0)?;
    let client = Rect { left: client.left.checked_sub(window.left)?, top: client.top.checked_sub(window.top)?,
        right: client.right.checked_sub(window.left)?, bottom: client.bottom.checked_sub(window.top)? };
    if client.left < 0 || client.top < 0 || client.right < client.left || client.bottom < client.top
        || client.right > width || client.bottom > height || metrics.arrow_size <= 0 || metrics.dpi == 0 { return None; }
    Some(NonclientScrollContext { window, client, style, ex_style, metrics, colors, pressed })
}

fn bounds(context: NonclientScrollContext, bar: i32) -> Result<Option<Rect>, GdiError> {
    let client = context.client;
    let metric = context.metrics.arrow_size;
    if metric <= 0 || client.left > client.right || client.top > client.bottom { return Err(GdiError::InvalidDimensions); }
    let overflow = GdiError::InvalidDimensions;
    match bar {
        SB_HORZ if context.style & WS_HSCROLL == 0 => Ok(None),
        SB_VERT if context.style & WS_VSCROLL == 0 => Ok(None),
        SB_HORZ => Ok(Some(Rect { left: client.left, top: client.bottom,
            right: client.right.checked_add(i32::from(context.style & WS_VSCROLL != 0)).ok_or(overflow)?,
            bottom: client.bottom.checked_add(metric).ok_or(overflow)? })),
        SB_VERT => {
            let (left, right) = if context.ex_style & WS_EX_LEFTSCROLLBAR != 0 {
                (client.left.checked_sub(metric).ok_or(overflow)?, client.left)
            } else { (client.right, client.right.checked_add(metric).ok_or(overflow)?) };
            Ok(Some(Rect { left, right, top: client.top,
                bottom: client.bottom.checked_add(i32::from(context.style & WS_HSCROLL != 0)).ok_or(overflow)? }))
        }
        _ => Err(GdiError::InvalidDimensions),
    }
}

/// The existing window DC must retain the latest composed client/frame pixels.
/// No creation, resize, attribute reset or fallback surface occurs here. # C: O(DCs + clipped pixels)
pub(crate) fn render(state: &mut GdiManager, hwnd: u32, bar: i32, scroll: ScrollState,
    context: NonclientScrollContext) -> Result<(u32, ScrollDrawOutcome), GdiError> {
    let dc = state.window_dc(hwnd).ok_or(GdiError::NoSuchObject)?;
    let width = context.window.right.checked_sub(context.window.left).filter(|v| *v > 0).ok_or(GdiError::InvalidDimensions)?;
    let height = context.window.bottom.checked_sub(context.window.top).filter(|v| *v > 0).ok_or(GdiError::InvalidDimensions)?;
    let (surface_width, surface_height, _) = state.surface(dc).ok_or(GdiError::NoSuchObject)?;
    if (surface_width, surface_height) != (width, height) { return Err(GdiError::InvalidDimensions); }
    let Some(bounds) = bounds(context, bar)? else { return Ok((dc, ScrollDrawOutcome::Hidden)); };
    state.draw_nonclient_scrollbar(dc, bounds, bar == SB_VERT, scroll, context.metrics, context.colors, context.pressed)
        .map(|outcome| (dc, outcome))
}

#[cfg(target_os = "oxide-kernel")]
#[path = "nonclient_scroll/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::repaint_nonclient_scroll_for_current;

#[cfg(test)]
#[path = "nonclient_scroll/tests.rs"]
mod tests;
