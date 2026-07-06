use super::*;

const IDLE_KEY_RAW: u32 = 0x0010_0000;
const ACTIVE_KEY_RAW: u32 = 0x0020_0000;
const MISSING_KEY_RAW: u32 = 0x0030_0000;
const EVENTQ_INDEX: u16 = 1;
const QUEUE_SIZE: u16 = 8;
const USED_IDX_OFF: usize = 2;
const USED_RING_OFF: usize = 4;
const USED_ELEM_BYTES: usize = 8;
const AVAIL_IDX_OFF: usize = 2;
const AVAIL_RING_OFF: usize = 4;
const AVAIL_RING_ENTRY_BYTES: usize = 2;
const USED_BYTES: usize = USED_RING_OFF + QUEUE_SIZE as usize * USED_ELEM_BYTES;
const AVAIL_BYTES: usize = AVAIL_RING_OFF + QUEUE_SIZE as usize * AVAIL_RING_ENTRY_BYTES;
const EVENT_BYTES: usize = QUEUE_SIZE as usize * EVENT_SIZE;
const USED_EVENTS: u16 = 2;
const FIRST_DESC_ID: u32 = 3;
const SECOND_DESC_ID: u32 = 4;
const FIRST_EVENT_RAW: u64 = 0xcccc_0000_0000_0003;
const SECOND_EVENT_RAW: u64 = 0xcccc_0000_0000_0004;
const NO_EVENTS: u64 = 0;
const IDLE_AVAIL_IDX: u16 = 0;
const IDLE_LAST_USED: u16 = 0;

#[test]
fn eventq_drain_accounting_is_keyed_by_snd_context() {
    let _guard = TEST_LOCK.lock();
    reset_test_state();
    let mut used0 = [0u8; USED_BYTES];
    let mut avail0 = [0u8; AVAIL_BYTES];
    let mut events0 = [0u8; EVENT_BYTES];
    let mut notify0 = 0u16;
    let mut used1 = [0u8; USED_BYTES];
    let mut avail1 = [0u8; AVAIL_BYTES];
    let mut events1 = [0u8; EVENT_BYTES];
    let mut notify1 = 0u16;
    put_u16(&mut used1, USED_IDX_OFF, USED_EVENTS);
    put_u32(&mut used1, USED_RING_OFF, FIRST_DESC_ID);
    put_u32(&mut used1, USED_RING_OFF + USED_ELEM_BYTES, SECOND_DESC_ID);
    put_event(&mut events1, FIRST_DESC_ID as usize, FIRST_EVENT_RAW);
    put_event(&mut events1, SECOND_DESC_ID as usize, SECOND_EVENT_RAW);

    let mut idle_ctx = ctx(key(IDLE_KEY_RAW));
    let mut idle_q = queue(EVENTQ_INDEX);
    idle_q.device_pa = used0.as_mut_ptr() as u64;
    idle_q.driver_pa = avail0.as_mut_ptr() as u64;
    idle_q.notify_va = (&mut notify0 as *mut u16) as u64;
    idle_ctx.eventq = Some(idle_q);
    idle_ctx.event_buf_pa = events0.as_mut_ptr() as u64;

    let mut active_ctx = ctx(key(ACTIVE_KEY_RAW));
    let mut active_q = queue(EVENTQ_INDEX);
    active_q.device_pa = used1.as_mut_ptr() as u64;
    active_q.driver_pa = avail1.as_mut_ptr() as u64;
    active_q.notify_va = (&mut notify1 as *mut u16) as u64;
    active_ctx.eventq = Some(active_q);
    active_ctx.event_buf_pa = events1.as_mut_ptr() as u64;
    CTX.lock().extend([idle_ctx, active_ctx]);

    event_softirq();

    assert_eq!(event_stats_for(key(IDLE_KEY_RAW)), Some((NO_EVENTS, NO_EVENTS)));
    assert_eq!(event_stats_for(key(ACTIVE_KEY_RAW)), Some((USED_EVENTS as u64, SECOND_EVENT_RAW)));
    assert_eq!(event_stats_for(key(MISSING_KEY_RAW)), None);
    assert_eq!(eventq_state_for(key(IDLE_KEY_RAW)), Some((QUEUE_SIZE, IDLE_LAST_USED, IDLE_AVAIL_IDX)));
    assert_eq!(eventq_state_for(key(ACTIVE_KEY_RAW)), Some((QUEUE_SIZE, USED_EVENTS, USED_EVENTS)));
    assert_eq!(get_u16(&avail0, AVAIL_IDX_OFF), IDLE_AVAIL_IDX);
    assert_eq!(get_u16(&avail1, AVAIL_IDX_OFF), USED_EVENTS);
    assert_eq!(get_u16(&avail1, AVAIL_RING_OFF), FIRST_DESC_ID as u16);
    assert_eq!(
        get_u16(&avail1, AVAIL_RING_OFF + AVAIL_RING_ENTRY_BYTES),
        SECOND_DESC_ID as u16,
    );
    assert_eq!(notify0, IDLE_AVAIL_IDX);
    assert_eq!(notify1, EVENTQ_INDEX);
    assert_eq!(DRAINED_EVENTS.load(Ordering::Relaxed), USED_EVENTS as u64);
    assert_eq!(LAST_EVENT.load(Ordering::Relaxed), SECOND_EVENT_RAW);
    reset_test_state();
}
