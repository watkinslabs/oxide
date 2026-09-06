//! Independently observed runtime milestones for the native Windows path.

#[cfg(any(target_os = "oxide-kernel", test))]
use core::sync::atomic::Ordering;
#[cfg(any(target_os = "oxide-kernel", test))]
use core::sync::atomic::AtomicU8;

#[cfg(any(test, target_arch = "x86_64"))]
const INITIAL: u8 = sched::thread_group::NT_WINDOWS_MILESTONE_INITIAL;
const UNIX_ENTRY: u8 = 1 << 1;
const SERVER_ENTRY: u8 = 1 << 2;
const WINDOW_CREATE: u8 = 1 << 3;
const MESSAGE_GET: u8 = 1 << 4;
const PAINT_BEGIN: u8 = 1 << 5;
const PAINT_PRESENT: u8 = 1 << 6;
const DESKTOP_ACK: u8 = 1 << 7;

#[cfg(any(target_os = "oxide-kernel", test))]
fn record(state: &AtomicU8, event: u8) -> bool {
    state.fetch_or(event, Ordering::AcqRel) & event == 0
}

#[cfg(target_os = "oxide-kernel")]
fn observe(event: u8, marker: &'static [u8]) {
    let Some(cur) = sched::live::current() else { return; };
    if record(&cur.thread_group.nt_windows_milestone, event) { klog::write_raw(marker); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn observe(_event: u8, _marker: &'static [u8]) {}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) fn reset() { if let Some(cur) = sched::live::current() { cur.thread_group.nt_windows_milestone.store(INITIAL, Ordering::Release); } }
pub(crate) fn unix_entry() { observe(UNIX_ENTRY, b"[WINDOWS-NT-UNIX] entry\n"); }
pub(crate) fn server_entry() { observe(SERVER_ENTRY, b"[WINDOWS-NT-SERVER] entry\n"); }
pub(crate) fn window_create() { observe(WINDOW_CREATE, b"[WINDOWS-USER32] create-window\n"); }
pub(crate) fn message_get() {
    LOOP_REACHED.store(true, core::sync::atomic::Ordering::Relaxed); observe(MESSAGE_GET, b"[WINDOWS-USER32] get-message\n"); }
pub(crate) fn paint_begin() { observe(PAINT_BEGIN, b"[WINDOWS-GDI] begin-paint\n"); }

/// Whether the application has retrieved its first message, which is when the
/// message-loop trace should start counting. # C: O(1)
pub(crate) fn message_loop_reached() -> bool { LOOP_REACHED.load(core::sync::atomic::Ordering::Relaxed) }
static LOOP_REACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub(crate) fn paint_present() { observe(PAINT_PRESENT, b"[WINDOWS-GDI] present\n"); }
pub(crate) fn desktop_ack() { observe(DESKTOP_ACK, b"[WINDOWS-DESKTOP] frame-ack\n"); }

#[cfg(test)]
#[path = "nt_milestone/tests.rs"]
mod tests;
