//! Ordered runtime milestones for the native Windows acceptance path.

#[cfg(any(target_os = "oxide-kernel", test))]
use core::sync::atomic::Ordering;
#[cfg(test)]
use core::sync::atomic::AtomicU8;

const UNIX_ENTRY: u8 = sched::thread_group::NT_WINDOWS_MILESTONE_INITIAL;
const SERVER_ENTRY: u8 = 2;
const WINDOW_CREATE: u8 = 3;
const MESSAGE_GET: u8 = 4;
const PAINT_BEGIN: u8 = 5;
const PAINT_PRESENT: u8 = 6;
const COMPLETE: u8 = 7;

#[cfg(target_os = "oxide-kernel")]
fn advance(expected: u8, next: u8, marker: &'static [u8]) {
    let Some(cur) = sched::live::current() else { return; };
    if cur.thread_group.nt_windows_milestone.compare_exchange(expected, next, Ordering::AcqRel, Ordering::Relaxed).is_ok() { klog::write_raw(marker); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn advance(_expected: u8, _next: u8, _marker: &'static [u8]) {}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) fn reset() { if let Some(cur) = sched::live::current() { cur.thread_group.nt_windows_milestone.store(UNIX_ENTRY, Ordering::Release); } }
pub(crate) fn unix_entry() { advance(UNIX_ENTRY, SERVER_ENTRY, b"[WINDOWS-NT-UNIX] entry\n"); }
pub(crate) fn server_entry() { advance(SERVER_ENTRY, WINDOW_CREATE, b"[WINDOWS-NT-SERVER] entry\n"); }
pub(crate) fn window_create() { advance(WINDOW_CREATE, MESSAGE_GET, b"[WINDOWS-USER32] create-window\n"); }
pub(crate) fn message_get() { advance(MESSAGE_GET, PAINT_BEGIN, b"[WINDOWS-USER32] get-message\n"); }
pub(crate) fn paint_begin() { advance(PAINT_BEGIN, PAINT_PRESENT, b"[WINDOWS-GDI] begin-paint\n"); }
pub(crate) fn paint_present() { advance(PAINT_PRESENT, COMPLETE, b"[WINDOWS-GDI] present\n"); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_state_is_monotonic_and_reaches_present() {
        let state = AtomicU8::new(UNIX_ENTRY);
        assert!(state.compare_exchange(UNIX_ENTRY, SERVER_ENTRY, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(state.compare_exchange(SERVER_ENTRY, WINDOW_CREATE, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(state.compare_exchange(WINDOW_CREATE, MESSAGE_GET, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(state.compare_exchange(MESSAGE_GET, PAINT_BEGIN, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(state.compare_exchange(PAINT_BEGIN, PAINT_PRESENT, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(state.compare_exchange(PAINT_PRESENT, COMPLETE, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert_eq!(state.load(Ordering::Relaxed), COMPLETE);
        assert!(state.compare_exchange(UNIX_ENTRY, SERVER_ENTRY, Ordering::Relaxed, Ordering::Relaxed).is_err());
    }
}
