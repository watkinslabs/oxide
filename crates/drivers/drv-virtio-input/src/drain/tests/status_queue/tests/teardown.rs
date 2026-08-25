use super::*;

#[test]
fn exact_device_send_and_teardown_retain_both_owned_frames() {
    let _devices = crate::registry::own_device_table();
    const DEVICE_KEY_RAW: u32 = 0x4300_0000;
    const UNKNOWN_DEVICE_KEY_RAW: u32 = 0x4400_0000;
    const QUEUE_SIZE: u16 = 1;
    const SENT_VALUE: u32 = 2;

    let _guard = TEST_LOCK.lock();
    reset();
    let device_key = key(DEVICE_KEY_RAW);
    let mut fixture = Fixture::new();
    let ctx = fixture.context(device_key, QUEUE_SIZE);
    let expected_frames = [ctx.buf_pa, ctx.status_buf_pa];
    CTXS.lock()[EVENT_QUEUE_SLOT] = Some(ctx);

    assert_eq!(
        send_status(key(UNKNOWN_DEVICE_KEY_RAW), event(INITIAL_EVENT_VALUE)),
        Err(StatusError::NoDevice),
    );
    assert_eq!(fixture.notify, 0);
    assert_eq!(send_status(device_key, event(SENT_VALUE)), Ok(()));
    assert_eq!(fixture.notify, STATUS_QUEUE_INDEX);

    let (removed, last) = take_eventq(device_key).expect("exact queue");
    assert!(last);
    assert_eq!(owned_frames(&removed), expected_frames);
    reset();
}

