use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

static LAST_KEY: AtomicU32 = AtomicU32::new(0);

fn consume_native(key: u16, pressed: bool, repeat: bool) -> bool {
    LAST_KEY.store(((key as u32) << 16) | ((pressed as u32) << 1) | repeat as u32, Ordering::Release);
    true
}

#[test]
fn accepted_keyboard_drain_offers_repeat_state_to_native_route() {
    let _guard = TEST_LOCK.lock();
    input::set_native_key_hook(Some(consume_native));
    handle_key_event_value(30, 2);
    assert_eq!(LAST_KEY.load(Ordering::Acquire), (30u32 << 16) | 3);
    input::set_native_key_hook(None);
}
