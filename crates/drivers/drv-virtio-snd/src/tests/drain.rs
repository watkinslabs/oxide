use super::*;
use crate::lifecycle::prepost_eventq;

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
const FIRST_DESC_ID: u32 = 3;
const SECOND_DESC_ID: u32 = 4;
const FIRST_EVENT_RAW: u64 = 0xcccc_0000_0000_0003;
const SECOND_EVENT_RAW: u64 = 0xcccc_0000_0000_0004;

#[repr(align(4096))]
struct Page([u8; 4096]);

fn eventq(desc: &mut Page, avail: &mut Page, used: &Page, notify: &mut u16) -> virtio::VirtioSplitQueue {
    let resource = virtio::VirtQueueResource {
        index: EVENTQ_INDEX,
        size: QUEUE_SIZE,
        desc_pa: desc.0.as_mut_ptr() as u64,
        driver_pa: avail.0.as_mut_ptr() as u64,
        device_pa: used.0.as_ptr() as u64,
        notify_va: notify as *mut u16 as u64,
        notify_off: 0,
    };
    virtio::VirtioSplitQueue::new(resource, 0).unwrap()
}

#[test]
fn eventq_drain_accounting_is_keyed_by_snd_context() {
    let _guard = TEST_LOCK.lock();
    reset_test_state();
    let mut idle_desc = Page([0; 4096]);
    let mut idle_avail = Page([0; 4096]);
    let idle_used = Page([0; 4096]);
    let mut idle_events = Page([0; 4096]);
    let mut idle_notify = 0u16;
    let mut active_desc = Page([0; 4096]);
    let mut active_avail = Page([0; 4096]);
    let mut active_used = Page([0; 4096]);
    let mut active_events = Page([0; 4096]);
    let mut active_notify = 0u16;

    let mut idle_ctx = ctx(key(IDLE_KEY_RAW));
    let mut idle_q = eventq(&mut idle_desc, &mut idle_avail, &idle_used, &mut idle_notify);
    assert!(prepost_eventq(&mut idle_q, idle_events.0.as_mut_ptr() as u64));
    idle_notify = 0;
    idle_ctx.eventq = Some(idle_q);
    idle_ctx.event_buf_pa = idle_events.0.as_mut_ptr() as u64;

    let mut active_ctx = ctx(key(ACTIVE_KEY_RAW));
    let mut active_q = eventq(&mut active_desc, &mut active_avail, &active_used, &mut active_notify);
    assert!(prepost_eventq(&mut active_q, active_events.0.as_mut_ptr() as u64));
    active_notify = 0;
    put_u16(&mut active_used.0, USED_IDX_OFF, 2);
    put_u32(&mut active_used.0, USED_RING_OFF, FIRST_DESC_ID);
    put_u32(&mut active_used.0, USED_RING_OFF + USED_ELEM_BYTES, SECOND_DESC_ID);
    put_event(&mut active_events.0, FIRST_DESC_ID as usize, FIRST_EVENT_RAW);
    put_event(&mut active_events.0, SECOND_DESC_ID as usize, SECOND_EVENT_RAW);
    active_ctx.eventq = Some(active_q);
    active_ctx.event_buf_pa = active_events.0.as_mut_ptr() as u64;
    CTX.lock().extend([idle_ctx, active_ctx]);

    event_softirq();

    assert_eq!(event_stats_for(key(IDLE_KEY_RAW)), Some((0, 0)));
    assert_eq!(event_stats_for(key(ACTIVE_KEY_RAW)), Some((2, SECOND_EVENT_RAW)));
    assert_eq!(event_stats_for(key(MISSING_KEY_RAW)), None);
    assert_eq!(eventq_state_for(key(IDLE_KEY_RAW)), Some((QUEUE_SIZE, 0, QUEUE_SIZE)));
    assert_eq!(eventq_state_for(key(ACTIVE_KEY_RAW)), Some((QUEUE_SIZE, 2, QUEUE_SIZE + 2)));
    assert_eq!(get_u16(&idle_avail.0, AVAIL_IDX_OFF), QUEUE_SIZE);
    assert_eq!(get_u16(&active_avail.0, AVAIL_IDX_OFF), QUEUE_SIZE + 2);
    assert_eq!(get_u16(&active_avail.0, AVAIL_RING_OFF), FIRST_DESC_ID as u16);
    assert_eq!(
        get_u16(&active_avail.0, AVAIL_RING_OFF + AVAIL_RING_ENTRY_BYTES),
        SECOND_DESC_ID as u16,
    );
    assert_eq!(idle_notify, 0);
    assert_eq!(active_notify, EVENTQ_INDEX);
    assert_eq!(DRAINED_EVENTS.load(Ordering::Relaxed), 2);
    assert_eq!(LAST_EVENT.load(Ordering::Relaxed), SECOND_EVENT_RAW);
    reset_test_state();
}
