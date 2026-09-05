//! Ordered runtime milestones for the native Windows acceptance path.

use core::sync::atomic::{AtomicU8, Ordering};

const UNIX_ENTRY: u8 = 1;
const SERVER_ENTRY: u8 = 2;
const WINDOW_CREATE: u8 = 3;
const MESSAGE_GET: u8 = 4;
const PAINT_BEGIN: u8 = 5;
const PAINT_PRESENT: u8 = 6;
const COMPLETE: u8 = 7;

static NEXT: AtomicU8 = AtomicU8::new(UNIX_ENTRY);

#[cfg(target_os = "oxide-kernel")]
fn advance(expected: u8, next: u8, marker: &'static [u8]) {
    if NEXT.compare_exchange(expected, next, Ordering::AcqRel, Ordering::Relaxed).is_ok() { klog::write_raw(marker); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn advance(_expected: u8, _next: u8, _marker: &'static [u8]) {}

#[cfg(target_arch = "x86_64")]
pub(crate) fn reset() { NEXT.store(UNIX_ENTRY, Ordering::Release); }
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
        NEXT.store(UNIX_ENTRY, Ordering::Relaxed);
        assert!(NEXT.compare_exchange(UNIX_ENTRY, SERVER_ENTRY, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(NEXT.compare_exchange(SERVER_ENTRY, WINDOW_CREATE, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(NEXT.compare_exchange(WINDOW_CREATE, MESSAGE_GET, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(NEXT.compare_exchange(MESSAGE_GET, PAINT_BEGIN, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(NEXT.compare_exchange(PAINT_BEGIN, PAINT_PRESENT, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert!(NEXT.compare_exchange(PAINT_PRESENT, COMPLETE, Ordering::Relaxed, Ordering::Relaxed).is_ok());
        assert_eq!(NEXT.load(Ordering::Relaxed), COMPLETE);
        assert!(NEXT.compare_exchange(UNIX_ENTRY, SERVER_ENTRY, Ordering::Relaxed, Ordering::Relaxed).is_err());
    }
}
