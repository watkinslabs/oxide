use core::sync::atomic::Ordering;

use super::*;

const FIRST_DEVICE_KEY_RAW: u32 = 0x0010_0000;
const SECOND_DEVICE_KEY_RAW: u32 = 0x0020_0000;

#[test]
fn removing_one_eventq_keeps_shared_input_drain_handler() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    reset();
    {
        let mut ctxs = CTXS.lock();
        ctxs[0] = Some(ctx(key(FIRST_DEVICE_KEY_RAW)));
        ctxs[1] = Some(ctx(key(SECOND_DEVICE_KEY_RAW)));
    }
    softirq::set_handler(softirq::Slot::InputDrain, test_handler);
    HANDLER_INSTALLED.store(true, Ordering::Release);

    let Some((removed, last_queue)) = take_eventq(key(FIRST_DEVICE_KEY_RAW)) else {
        panic!("expected first input queue");
    };
    assert_eq!(removed.device_key, key(FIRST_DEVICE_KEY_RAW));
    assert!(!last_queue);
    release_handler_if_last(last_queue);

    softirq::raise(softirq::Slot::InputDrain);
    // SAFETY: hosted unit test owns InputDrain under TEST_LOCK.
    unsafe { softirq::run_pending(); }
    assert_eq!(TEST_DRAINS.load(Ordering::Relaxed), 1);
    assert!(CTXS.lock()[1].is_some());
    reset();
}

#[test]
fn removing_last_eventq_clears_shared_input_drain_handler() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    reset();
    CTXS.lock()[0] = Some(ctx(key(FIRST_DEVICE_KEY_RAW)));
    softirq::set_handler(softirq::Slot::InputDrain, test_handler);
    HANDLER_INSTALLED.store(true, Ordering::Release);

    let Some((removed, last_queue)) = take_eventq(key(FIRST_DEVICE_KEY_RAW)) else {
        panic!("expected last input queue");
    };
    assert_eq!(removed.device_key, key(FIRST_DEVICE_KEY_RAW));
    assert!(last_queue);
    release_handler_if_last(last_queue);

    softirq::raise(softirq::Slot::InputDrain);
    // SAFETY: hosted unit test owns InputDrain under TEST_LOCK.
    unsafe { softirq::run_pending(); }
    assert_eq!(TEST_DRAINS.load(Ordering::Relaxed), 0);
    assert!(!HANDLER_INSTALLED.load(Ordering::Acquire));
    reset();
}

#[test]
fn missing_eventq_key_does_not_remove_another_device_queue() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    reset();
    CTXS.lock()[1] = Some(ctx(key(SECOND_DEVICE_KEY_RAW)));

    assert!(take_eventq(key(FIRST_DEVICE_KEY_RAW)).is_none());
    assert!(CTXS.lock()[1].is_some());
    reset();
}
