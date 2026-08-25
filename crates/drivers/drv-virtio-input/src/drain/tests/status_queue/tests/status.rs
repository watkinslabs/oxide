use super::*;

#[test]
fn status_submission_uses_driver_readable_eight_byte_buffer() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4100_0000;
    const QUEUE_SIZE: u16 = 2;
    const EVENT_VALUE: u32 = 7;

    let _guard = TEST_LOCK.lock();
    reset();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(key(DEVICE_KEY_RAW), QUEUE_SIZE);

    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), 0);

    assert_eq!(status::submit(&mut ctx, event(EVENT_VALUE)), Ok(()));
    assert_eq!(read_u64(&fixture.desc, 0), fixture.frames.0.as_ptr() as u64);
    assert_eq!(read_u32(&fixture.desc, DESC_LEN_OFF), EVENT_BYTES as u32);
    assert_eq!(read_u16(&fixture.desc, DESC_FLAGS_OFF), 0);
    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), 1);
    assert_eq!(read_u16(&fixture.avail, RING_ENTRIES_OFF), 0);
    assert_eq!(fixture.notify, STATUS_QUEUE_INDEX);
    let written = unsafe {
        core::ptr::read_volatile(fixture.frames.0.as_ptr() as *const VirtioInputEvent)
    };
    assert_eq!(
        (written.ty, written.code, written.value),
        (crate::EV_LED, TEST_LED_CODE, EVENT_VALUE),
    );
    reset();
}

#[test]
fn completion_is_reaped_before_submit_and_descriptor_is_reused() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4200_0000;
    const QUEUE_SIZE: u16 = 2;
    const FIRST_VALUE: u32 = 1;
    const SECOND_VALUE: u32 = 2;
    const RETRIED_VALUE: u32 = 3;

    let _guard = TEST_LOCK.lock();
    reset();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(key(DEVICE_KEY_RAW), QUEUE_SIZE);

    assert_eq!(status::submit(&mut ctx, event(FIRST_VALUE)), Ok(()));
    assert_eq!(status::submit(&mut ctx, event(SECOND_VALUE)), Ok(()));
    assert_eq!(
        status::submit(&mut ctx, event(RETRIED_VALUE)),
        Err(StatusError::QueueFull),
    );
    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u16(&mut fixture.used, RING_INDEX_OFF, 1);

    assert_eq!(status::submit(&mut ctx, event(RETRIED_VALUE)), Ok(()));
    assert_eq!(ctx.status.last_used, 1);
    assert_eq!(ctx.status.in_flight_len, QUEUE_SIZE);
    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), QUEUE_SIZE + 1);
    assert_eq!(read_u16(&fixture.avail, RING_ENTRIES_OFF), 0);
    let reused = unsafe {
        core::ptr::read_volatile(fixture.frames.0.as_ptr() as *const VirtioInputEvent)
    };
    assert_eq!(reused.value, RETRIED_VALUE);
    reset();
}

#[test]
fn nonzero_status_completion_length_poison_queue() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4250_0000;
    const QUEUE_SIZE: u16 = 2;

    let _guard = TEST_LOCK.lock();
    reset();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(key(DEVICE_KEY_RAW), QUEUE_SIZE);

    assert_eq!(status::submit(&mut ctx, event(INITIAL_EVENT_VALUE)), Ok(()));
    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        EVENT_BYTES as u32,
    );
    write_u16(&mut fixture.used, RING_INDEX_OFF, 1);

    assert_eq!(
        status::submit(&mut ctx, event(SECOND_EVENT_VALUE)),
        Err(StatusError::CorruptQueue),
    );
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        0,
    );
    assert_eq!(
        status::submit(&mut ctx, event(RETRY_EVENT_VALUE)),
        Err(StatusError::CorruptQueue),
    );
    assert_eq!(ctx.status.last_used, 0);
    reset();
}

#[test]
fn duplicate_status_completion_poison_queue() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4260_0000;
    const QUEUE_SIZE: u16 = 2;

    let _guard = TEST_LOCK.lock();
    reset();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(key(DEVICE_KEY_RAW), QUEUE_SIZE);

    assert_eq!(status::submit(&mut ctx, event(INITIAL_EVENT_VALUE)), Ok(()));
    assert_eq!(status::submit(&mut ctx, event(SECOND_EVENT_VALUE)), Ok(()));
    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_ELEM_BYTES + USED_ID_OFF,
        0,
    );
    write_u16(&mut fixture.used, RING_INDEX_OFF, QUEUE_SIZE);

    assert_eq!(
        status::submit(&mut ctx, event(RETRY_EVENT_VALUE)),
        Err(StatusError::CorruptQueue),
    );
    assert_eq!(
        status::submit(&mut ctx, event(POISON_PROBE_VALUE)),
        Err(StatusError::CorruptQueue),
    );
    reset();
}

#[test]
fn status_batch_capacity_failure_does_not_partially_publish() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4270_0000;
    const QUEUE_SIZE: u16 = 2;

    let _guard = TEST_LOCK.lock();
    reset();
    let device_key = key(DEVICE_KEY_RAW);
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(device_key, QUEUE_SIZE);

    assert_eq!(status::submit(&mut ctx, event(INITIAL_EVENT_VALUE)), Ok(()));
    CTXS.lock()[EVENT_QUEUE_SLOT] = Some(ctx);
    assert_eq!(
        send_status_batch(device_key,
            &[event(SECOND_EVENT_VALUE), event(RETRY_EVENT_VALUE)]),
        Err(StatusError::QueueFull),
    );
    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), 1);
    assert_eq!(fixture.notify, STATUS_QUEUE_INDEX);
    reset();
}


