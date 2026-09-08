//! The desktop window: one per desktop, shared by every process attached to it.
//!
//! The desktop window belongs to the desktop object, not to an application.
//! Every process on a desktop resolves the same handle for it, including a
//! process that has created no window of its own, and a second instance of an
//! application resolves the same handle as the first. Its handle is drawn from
//! the window server's own block of the system-wide handle space, so no
//! application's window can ever carry that value.
use core::sync::atomic::{AtomicU32, Ordering};
use ipc::win32_window::handle_space;
use sched::nt_object::NtObject;

#[path = "desktop/bootstrap.rs"]
mod bootstrap;
#[allow(unused_imports)] // KI-0705: orphaned virtual-desktop bootstrap surface
pub(crate) use bootstrap::{prepare_bound_for_current, BoundDesktop, BootstrapError};
#[path = "desktop/bind.rs"]
mod bind;
#[allow(unused_imports)] // KI-0705: orphaned desktop-bind surface
pub(crate) use bind::bind_for_current;

/// Server handles already named. Desktop windows are the only windows drawn
/// from the server's block, so one counter names them all.
static SERVER_HANDLES: AtomicU32 = AtomicU32::new(0);

/// The desktop window of the calling thread's desktop, established on first
/// use. The reference creates it on the first request and answers every later
/// one — in this process or another — with the same handle.
/// # C: O(1); # Sleeps: no
pub(crate) fn resolve_for_current() -> Option<u32> {
    let current = sched::live::current().filter(|task| task.is_nt_personality())?;
    let station = { let station = current.thread_group.nt_window_station.lock().clone(); station? };
    let membership = { let membership = current.nt_desktop.lock().clone(); membership };
    if let Ok(hwnd) = membership.resolve_root(&station) { return Some(hwnd); }
    let desktop = membership.identity(&station).ok()?;
    establish_root(&desktop)
}

/// Name this desktop's window if it has none. A caller that loses the race is
/// answered with the handle the winner established, so one desktop still has
/// one desktop window. # C: O(1)
fn establish_root(desktop: &NtObject) -> Option<u32> {
    let payload = desktop.desktop()?;
    if let Ok(root) = payload.root() { return Some(root.hwnd()); }
    let hwnd = handle_space::desktop_handle(SERVER_HANDLES.fetch_add(1, Ordering::Relaxed));
    if hwnd == 0 { return None; }
    payload.publish_root(hwnd).ok()
}

/// Desktop HWND for NtUserGetDesktopWindow; zero only when the calling thread
/// is attached to no desktop at all. # C: O(1); # Sleeps: no
pub(crate) fn window_for_current() -> u64 {
    resolve_for_current().map(u64::from).unwrap_or(0)
}

