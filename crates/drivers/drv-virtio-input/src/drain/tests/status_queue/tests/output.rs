use super::*;

#[test]
fn canonical_output_batch_is_encoded_for_exact_status_queue() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4280_0000;
    const QUEUE_SIZE: u16 = 2;
    const FIRST_CODE: u16 = 1;
    const SECOND_CODE: u16 = 2;
    const FIRST_VALUE: i32 = 1;
    const SECOND_VALUE: i32 = -1;

    let _guard = TEST_LOCK.lock();
    reset();
    let device_key = key(DEVICE_KEY_RAW);
    let mut fixture = Fixture::new();
    CTXS.lock()[EVENT_QUEUE_SLOT] = Some(fixture.context(device_key, QUEUE_SIZE));
    let output = input::OutputBatch {
        events: alloc::vec![
            input::OutputEvent {
                ev_type: crate::EV_LED,
                code: FIRST_CODE,
                value: FIRST_VALUE,
            },
            input::OutputEvent {
                ev_type: crate::EV_SND,
                code: SECOND_CODE,
                value: SECOND_VALUE,
            },
        ],
    };

    assert_eq!(send_output_batch(device_key, &output), Ok(()));
    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), QUEUE_SIZE);
    let first = unsafe {
        core::ptr::read_volatile(fixture.frames.0.as_ptr() as *const VirtioInputEvent)
    };
    let second = unsafe {
        core::ptr::read_volatile(
            fixture.frames.0.as_ptr().add(EVENT_BYTES)
                as *const VirtioInputEvent,
        )
    };
    assert_eq!(
        (first.ty, first.code, first.value),
        (crate::EV_LED, FIRST_CODE, FIRST_VALUE as u32),
    );
    assert_eq!(
        (second.ty, second.code, second.value),
        (crate::EV_SND, SECOND_CODE, SECOND_VALUE as u32),
    );
    reset();
}

#[test]
fn full_status_queue_retains_and_retries_canonical_output() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4281_0000;
    const QUEUE_SIZE: u16 = 1;
    const FIRST_LED_CODE: u16 = 1;
    const RETRIED_LED_CODE: u16 = 2;
    const FIRST_VALUE: i32 = 7;
    const RETRIED_VALUE: i32 = 9;

    let _guard = TEST_LOCK.lock();
    reset();
    let device_key = key(DEVICE_KEY_RAW);
    let mut fixture = Fixture::new();
    CTXS.lock()[EVENT_QUEUE_SLOT] = Some(fixture.context(device_key, QUEUE_SIZE));
    let output = input::OutputBatch {
        events: alloc::vec![
            input::OutputEvent {
                ev_type: crate::EV_LED,
                code: FIRST_LED_CODE,
                value: FIRST_VALUE,
            },
            input::OutputEvent {
                ev_type: crate::EV_LED,
                code: RETRIED_LED_CODE,
                value: RETRIED_VALUE,
            },
        ],
    };

    assert_eq!(send_output_batch(device_key, &output), Ok(()));
    {
        let contexts = CTXS.lock();
        let ctx = contexts[EVENT_QUEUE_SLOT].as_ref().expect("installed queue");
        assert_eq!(ctx.pending_output.len(), QUEUE_SIZE as usize);
        assert_eq!(ctx.status.avail_idx, QUEUE_SIZE);
    }

    write_u32(&mut fixture.used, RING_ENTRIES_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        0,
    );
    write_u16(&mut fixture.used, RING_INDEX_OFF, QUEUE_SIZE);
    {
        let mut contexts = CTXS.lock();
        let ctx = contexts[EVENT_QUEUE_SLOT].as_mut().expect("installed queue");
        assert_eq!(status::flush_pending(ctx), Ok(()));
        assert!(ctx.pending_output.is_empty());
        assert_eq!(ctx.status.avail_idx, QUEUE_SIZE + 1);
    }
    let retried = unsafe {
        core::ptr::read_volatile(fixture.frames.0.as_ptr() as *const VirtioInputEvent)
    };
    assert_eq!(retried.value, RETRIED_VALUE as u32);
    reset();
}


