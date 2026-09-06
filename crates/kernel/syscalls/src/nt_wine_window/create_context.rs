//! Borrow startup placement fields from the canonical process parameters.

use super::geometry::Defaults;
use syscall::nt_compositor::Monitor;
extern crate alloc;

const PEB_PARAMETERS: u64 = 0x20;
const PARAMETERS_X: u64 = 0x88;
const PARAMETERS_Y: u64 = 0x8c;
const PARAMETERS_WIDTH: u64 = 0x90;
const PARAMETERS_HEIGHT: u64 = 0x94;
const PARAMETERS_WINDOW_FLAGS: u64 = 0xa4;
const STARTF_USESIZE: u32 = 2;
const STARTF_USEPOSITION: u32 = 4;

/// Read current process startup overrides and its bound desktop snapshot.
/// # C: O(bindings + monitors) plus bounded process-parameter reads
#[cfg(target_os = "oxide-kernel")]
pub(super) fn defaults() -> Defaults {
    let Some(current) = sched::live::current() else { return Defaults::default(); };
    read_defaults(current.nt_peb(), |p| uaccess::get_user_u64(p).ok(),
        |p| uaccess::get_user_u32(p).ok(), || crate::nt_compositor::monitors(&current.thread_group))
}

/// Fetch process overrides and the current desktop once per placement query.
/// # C: O(monitors) plus bounded reads and one bridge snapshot query
pub(super) fn read_defaults(peb: u64, read64: impl FnMut(u64) -> Option<u64>,
    read32: impl FnMut(u64) -> Option<u32>, snapshot: impl FnOnce() -> Option<alloc::vec::Vec<Monitor>>) -> Defaults {
    let Some(startup) = read_startup(peb, read64, read32) else { return Defaults::default(); };
    let snapshot = snapshot();
    with_monitor(startup, snapshot.as_deref().and_then(super::metrics::primary))
}

/// Read only startup fields enabled by the caller-owned window flags.
/// # C: O(1), at most six bounded reads
pub(super) fn read_startup(peb: u64, mut read64: impl FnMut(u64) -> Option<u64>,
    mut read32: impl FnMut(u64) -> Option<u32>) -> Option<Defaults> {
    let parameters = read64(peb.checked_add(PEB_PARAMETERS)?)?;
    if parameters == 0 { return None; }
    let mut field = |offset| read32(parameters.checked_add(offset)?);
    let flags = field(PARAMETERS_WINDOW_FLAGS)?;
    let position = if flags & STARTF_USEPOSITION != 0 {
        Some((field(PARAMETERS_X)? as i32, field(PARAMETERS_Y)? as i32))
    } else { None };
    let size = if flags & STARTF_USESIZE != 0 {
        Some((field(PARAMETERS_WIDTH)? as i32, field(PARAMETERS_HEIGHT)? as i32))
    } else { None };
    Some(Defaults { position, size, work_area: None })
}

/// Merge one current, bridge-validated primary monitor into borrowed startup
/// fields. Missing desktop data clears any previous work area; never cache it.
/// # C: O(1)
pub(super) fn with_monitor(mut startup: Defaults, monitor: Option<Monitor>) -> Defaults {
    startup.work_area = monitor.and_then(|m| {
        let r = m.workarea;
        r.validate().ok()?;
        Some(super::geometry::Rect { left: r.x, top: r.y,
            right: r.x.checked_add(i32::try_from(r.width).ok()?)?,
            bottom: r.y.checked_add(i32::try_from(r.height).ok()?)? })
    });
    startup
}

#[cfg(test)]
#[path = "tests/desktop_context.rs"]
mod tests;
