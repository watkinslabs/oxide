//! Host-testable canonical rectangle policy shared by the kernel adapter.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RectKind { Window, Client }

fn map_dpi(value: i32, source: u32, target: u32) -> i32 {
    if source == 0 || target == 0 || source == target { return value; }
    let product = i64::from(value).saturating_mul(i64::from(target));
    let half = i64::from(source / 2);
    let rounded = if product < 0 { product - half } else { product + half };
    rounded.checked_div(i64::from(source))
        .map(|value| value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)
        .unwrap_or(value)
}

pub(crate) fn map_rect(rect: ipc::win32_window::WindowRect, source_dpi: u32, requested_dpi: u32)
    -> ipc::win32_window::WindowRect
{
    ipc::win32_window::WindowRect {
        left: map_dpi(rect.left, source_dpi, requested_dpi),
        top: map_dpi(rect.top, source_dpi, requested_dpi),
        right: map_dpi(rect.right, source_dpi, requested_dpi),
        bottom: map_dpi(rect.bottom, source_dpi, requested_dpi),
    }
}

pub(crate) fn query_state(
    state: &ipc::win32_window::WindowManager,
    window: ipc::win32_window::WindowId,
    kind: RectKind,
    requested_dpi: u32,
    source_dpi: u32,
) -> Option<ipc::win32_window::WindowRect> {
    let rect = match kind {
        RectKind::Client => state.client_rect(window)?,
        RectKind::Window => {
            let mut current = window;
            let mut rect = state.rect(current)?;
            while let Some(parent) = state.get(current)?.parent {
                let parent_rect = state.rect(parent)?;
                let parent_record = state.get(parent)?;
                let client_origin = parent_record.client_rect.map(|client| (client.left, client.top)).unwrap_or((0, 0));
                let offset_x = parent_rect.left.saturating_add(client_origin.0);
                let offset_y = parent_rect.top.saturating_add(client_origin.1);
                rect.left = rect.left.saturating_add(offset_x);
                rect.right = rect.right.saturating_add(offset_x);
                rect.top = rect.top.saturating_add(offset_y);
                rect.bottom = rect.bottom.saturating_add(offset_y);
                current = parent;
            }
            rect
        }
    };
    Some(map_rect(rect, source_dpi, if requested_dpi == 0 { source_dpi } else { requested_dpi }))
}

#[cfg(test)]
#[path = "tests/rect_query_policy.rs"]
mod tests;
