//! System metrics: canonical nonclient defaults, native font normalization and live desktop geometry.
extern crate alloc;

const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
use syscall::nt_compositor::Monitor;

const SM_XVIRTUALSCREEN: i32 = 76;
const SM_YVIRTUALSCREEN: i32 = 77;
const SM_CXVIRTUALSCREEN: i32 = 78;
const SM_CYVIRTUALSCREEN: i32 = 79;
const SM_CMONITORS: i32 = 80;

/// Settings and desktop geometry retain their separate canonical owners.
/// # C: O(bindings + monitors)
#[cfg(target_os = "oxide-kernel")]
pub(super) fn get(index: u64) -> u64 {
    route(index, ipc::win32_gdi::system_metric_default, crate::nt_native_gdi::begin_system_metric,
        crate::nt_compositor::monitors_current)
}

/// Preserve callback return registers; never require a monitor for non-display settings.
/// # C: O(monitors) plus one canonical owner query
pub(super) fn route(index: u64, defaults: impl FnOnce(i32) -> Option<i32>,
    native: impl FnOnce(u32) -> u64, snapshot: impl FnOnce() -> Option<alloc::vec::Vec<Monitor>>) -> u64 {
    let index = index as i32;
    if let Some(value) = defaults(index) { return value as i64 as u64; }
    if syscall::nt_native_gdi::system_metric_needs_font(index as u32) { return native(index as u32); }
    query(index as i64 as u64, snapshot)
}

/// The current backend publishes one connected X screen. Multiple monitor
/// records need an explicit primary identity; enumeration order is not one.
/// # C: O(1)
pub(super) fn primary(monitors: &[Monitor]) -> Option<Monitor> {
    match monitors { [monitor] => Some(*monitor), _ => None }
}

/// Fetch on every call, including after desktop changes and disconnection.
/// # C: O(monitors) plus one snapshot query
pub(super) fn query(index: u64, snapshot: impl FnOnce() -> Option<alloc::vec::Vec<Monitor>>) -> u64 {
    let Some(monitors) = snapshot() else { return 0; };
    from_snapshot(index, primary(&monitors), &monitors)
}

/// Consume a single connection-scoped desktop snapshot. Primary identity is
/// supplied by the bridge contract, not inferred from monitor enumeration.
/// # C: O(monitors)
pub(super) fn from_snapshot(index: u64, primary: Option<Monitor>, monitors: &[Monitor]) -> u64 {
    let index = index as i32;
    if monitors.is_empty() { return 0; }
    if index == SM_CXSCREEN || index == SM_CYSCREEN {
        let Some(primary) = primary.filter(|m| monitors.contains(m)) else { return 0; };
        return if index == SM_CXSCREEN { primary.monitor.width as u64 } else { primary.monitor.height as u64 };
    }
    if index == SM_CMONITORS { return monitors.len() as u64; }
    let mut left = i64::MAX; let mut top = i64::MAX;
    let mut right = i64::MIN; let mut bottom = i64::MIN;
    for m in monitors {
        let r = m.monitor;
        if r.validate().is_err() { return 0; }
        left = left.min(i64::from(r.x)); top = top.min(i64::from(r.y));
        right = right.max(i64::from(r.x) + i64::from(r.width));
        bottom = bottom.max(i64::from(r.y) + i64::from(r.height));
    }
    let value = match index { SM_XVIRTUALSCREEN => left, SM_YVIRTUALSCREEN => top,
        SM_CXVIRTUALSCREEN => right - left, SM_CYVIRTUALSCREEN => bottom - top, _ => return 0 };
    i32::try_from(value).map(|v| v as i64 as u64).unwrap_or(0)
}

#[cfg(test)]
#[path = "tests/desktop_metrics.rs"]
mod tests;
