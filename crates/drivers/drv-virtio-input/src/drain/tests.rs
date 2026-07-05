use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use super::*;

static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
static TEST_DRAINS: AtomicU32 = AtomicU32::new(0);

fn test_handler() {
    TEST_DRAINS.fetch_add(1, Ordering::Relaxed);
}

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn queue() -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index: 0,
        size: 8,
        desc_pa: 0,
        driver_pa: 0,
        device_pa: 0,
        notify_va: 0,
        notify_off: 0,
    }
}

fn ctx(device_key: virtio::VirtioChildDeviceKey) -> QueueCtx {
    QueueCtx {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        eventq: queue(),
        buf_pa: 0,
        last_used: 0,
        avail_idx: 0,
        is_pointer: false,
    }
}

fn reset() {
    for slot in CTXS.lock().iter_mut() {
        *slot = None;
    }
    HANDLER_INSTALLED.store(false, Ordering::Release);
    TEST_DRAINS.store(0, Ordering::Relaxed);
    let _ = softirq::clear_handler(softirq::Slot::InputDrain);
}

#[test]
fn removing_one_eventq_keeps_shared_input_drain_handler() {
    let _guard = TEST_LOCK.lock();
    reset();
    {
        let mut ctxs = CTXS.lock();
        ctxs[0] = Some(ctx(key(0x0010_0000)));
        ctxs[1] = Some(ctx(key(0x0020_0000)));
    }
    softirq::set_handler(softirq::Slot::InputDrain, test_handler);
    HANDLER_INSTALLED.store(true, Ordering::Release);

    let Some((removed, last_queue)) = take_eventq(key(0x0010_0000)) else {
        panic!("expected first input queue");
    };
    assert_eq!(removed.device_key, key(0x0010_0000));
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
    let _guard = TEST_LOCK.lock();
    reset();
    CTXS.lock()[0] = Some(ctx(key(0x0010_0000)));
    softirq::set_handler(softirq::Slot::InputDrain, test_handler);
    HANDLER_INSTALLED.store(true, Ordering::Release);

    let Some((removed, last_queue)) = take_eventq(key(0x0010_0000)) else {
        panic!("expected last input queue");
    };
    assert_eq!(removed.device_key, key(0x0010_0000));
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
    let _guard = TEST_LOCK.lock();
    reset();
    CTXS.lock()[1] = Some(ctx(key(0x0020_0000)));

    assert!(take_eventq(key(0x0010_0000)).is_none());
    assert!(CTXS.lock()[1].is_some());
    reset();
}
