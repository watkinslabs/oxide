//! Selected canonical identity plus the bound compositor's real monitor snapshot.
use alloc::sync::Arc;
use ipc::win32_window::WindowRect;
use sched::nt_object::NtObject;
#[path = "geometry.rs"]
mod geometry;
use geometry::bounds;

// KI-0705: no dispatch caller yet; kept as real Win32 surface.
#[allow(dead_code)]
pub(crate) struct BoundDesktop { pub desktop: Arc<NtObject>, pub bounds: WindowRect }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BootstrapError { NoCurrent, NoDisplay, Geometry, Identity }

/// Membership was selected through canonical NT objects before entry; transport supplies only geometry.
/// # C: O(monitors); # Sleeps: no
#[allow(dead_code)]
pub(crate) fn prepare_bound_for_current() -> Result<BoundDesktop, BootstrapError> {
    let current = sched::live::current().ok_or(BootstrapError::NoCurrent)?;
    let station = current.thread_group.nt_window_station.lock().clone().ok_or(BootstrapError::Identity)?;
    let membership = current.nt_desktop.lock().clone();
    let desktop = membership.identity(&station).map_err(|_| BootstrapError::Identity)?;
    let monitors = crate::nt_compositor::monitors_current().ok_or(BootstrapError::NoDisplay)?;
    let bounds = bounds(&monitors).ok_or(BootstrapError::Geometry)?;
    Ok(BoundDesktop { desktop, bounds })
}
