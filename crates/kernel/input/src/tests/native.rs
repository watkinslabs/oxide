use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

static NATIVE_EVENTS: AtomicU32 = AtomicU32::new(0);

fn record_native(key: u16, pressed: bool, repeat: bool) -> bool {
    let value = ((key as u32) << 16) | ((pressed as u32) << 1) | repeat as u32;
    NATIVE_EVENTS.store(value, Ordering::Release);
    true
}

#[test]
fn native_key_sink_receives_press_release_and_repeat_state() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::set_native_key_hook(Some(record_native));
    assert!(crate::dispatch_native_key_event(TEST_KEY_CODE, true, false));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 2);
    assert!(crate::dispatch_native_key_event(TEST_KEY_CODE, false, true));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 1);
    crate::set_native_key_hook(None);
    assert!(!crate::dispatch_native_key_event(TEST_KEY_CODE, true, false));
}
