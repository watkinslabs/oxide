use ipc::win32_window::WindowRect;
use syscall::nt_compositor::Monitor;

/// Virtual desktop bounds use all actual monitor extents, not workarea or guessed primary.
/// # C: O(monitors)
pub(crate) fn bounds(monitors: &[Monitor]) -> Option<WindowRect> {
    if monitors.is_empty() { return None; }
    let mut left=i64::MAX;let mut top=i64::MAX;let mut right=i64::MIN;let mut bottom=i64::MIN;
    for monitor in monitors {
        let rect=monitor.monitor;rect.validate().ok()?;
        left=left.min(i64::from(rect.x));top=top.min(i64::from(rect.y));
        right=right.max(i64::from(rect.x)+i64::from(rect.width));
        bottom=bottom.max(i64::from(rect.y)+i64::from(rect.height));
    }
    i32::try_from(right-left).ok()?;i32::try_from(bottom-top).ok()?;
    Some(WindowRect {left:left.try_into().ok()?,top:top.try_into().ok()?,right:right.try_into().ok()?,bottom:bottom.try_into().ok()?})
}

#[cfg(test)]
#[path="geometry_tests.rs"] mod tests;
