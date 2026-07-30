use alloc::collections::VecDeque;

use super::super::{queue, status};
use super::{key, owned_frames, reset, take_eventq, QueueCtx, CTXS, TEST_LOCK};
use crate::drain::{send_output_batch, send_status, send_status_batch, StatusError};
use crate::VirtioInputEvent;

const EVENT_QUEUE_SLOT: usize = 0;
const STATUS_QUEUE_SLOT: usize = 1;
const EVENT_QUEUE_INDEX: u16 = 0;
const STATUS_QUEUE_INDEX: u16 = 1;
const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();
const DESC_BYTES: usize = core::mem::size_of::<virtio::queue::Desc>();
const DESC_LEN_OFF: usize = core::mem::size_of::<u64>();
const DESC_FLAGS_OFF: usize = DESC_LEN_OFF + core::mem::size_of::<u32>();
const DESC_NEXT_OFF: usize = DESC_FLAGS_OFF + core::mem::size_of::<u16>();
const RING_INDEX_OFF: usize = core::mem::size_of::<u16>();
const RING_ENTRIES_OFF: usize = RING_INDEX_OFF + core::mem::size_of::<u16>();
const AVAIL_ENTRY_BYTES: usize = core::mem::size_of::<u16>();
const USED_ELEM_BYTES: usize = core::mem::size_of::<virtio::queue::UsedElem>();
const USED_ID_OFF: usize = 0;
const USED_LEN_OFF: usize = core::mem::size_of::<u32>();
const TEST_LED_CODE: u16 = 2;
const TEST_EVENT_BUF_PA: u64 = 0x1110_0000;
const INITIAL_EVENT_VALUE: u32 = 1;
const SECOND_EVENT_VALUE: u32 = 2;
const RETRY_EVENT_VALUE: u32 = 3;
const POISON_PROBE_VALUE: u32 = 4;

#[repr(align(16))]
struct Page([u8; hal::PAGE_SIZE_BYTES as usize]);

struct Fixture {
    desc: Page,
    avail: Page,
    used: Page,
    frames: Page,
    notify: u16,
}

impl Fixture {
    fn new() -> Self {
        Self {
            desc: Page([0; hal::PAGE_SIZE_BYTES as usize]),
            avail: Page([0; hal::PAGE_SIZE_BYTES as usize]),
            used: Page([0; hal::PAGE_SIZE_BYTES as usize]),
            frames: Page([0; hal::PAGE_SIZE_BYTES as usize]),
            notify: 0,
        }
    }

    fn queue(&mut self, size: u16) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index: STATUS_QUEUE_INDEX,
            size,
            desc_pa: self.desc.0.as_mut_ptr() as u64,
            driver_pa: self.avail.0.as_mut_ptr() as u64,
            device_pa: self.used.0.as_mut_ptr() as u64,
            notify_va: (&mut self.notify as *mut u16) as u64,
            notify_off: 0,
        }
    }

    fn context(
        &mut self,
        device_key: virtio::VirtioChildDeviceKey,
        size: u16,
    ) -> QueueCtx {
        let statusq = self.queue(size);
        let status = status::initialize(0, statusq, self.frames.0.as_mut_ptr() as u64)
            .expect("valid status queue");
        QueueCtx {
            device_key,
            cfg_va: 0,
            hhdm: 0,
            eventq: virtio::VirtQueueResource {
                index: EVENT_QUEUE_INDEX,
                ..statusq
            },
            buf_pa: TEST_EVENT_BUF_PA,
            event_buffers: size.min(queue::MAX_EVENT_BUFFERS),
            statusq,
            status_buf_pa: self.frames.0.as_mut_ptr() as u64,
            status,
            pending_output: VecDeque::new(),
            last_used: 0,
            avail_idx: 0,
            eventq_failed: false,
            is_pointer: false,
        }
    }
}

fn read_u16(page: &Page, off: usize) -> u16 {
    // SAFETY: tests use aligned, in-page offsets.
    unsafe { core::ptr::read_volatile(page.0.as_ptr().add(off) as *const u16) }
}

fn read_u32(page: &Page, off: usize) -> u32 {
    // SAFETY: tests use aligned, in-page offsets.
    unsafe { core::ptr::read_volatile(page.0.as_ptr().add(off) as *const u32) }
}

fn read_u64(page: &Page, off: usize) -> u64 {
    // SAFETY: tests use aligned, in-page offsets.
    unsafe { core::ptr::read_volatile(page.0.as_ptr().add(off) as *const u64) }
}

fn write_u16(page: &mut Page, off: usize, value: u16) {
    // SAFETY: tests use aligned, in-page offsets.
    unsafe {
        core::ptr::write_volatile(page.0.as_mut_ptr().add(off) as *mut u16, value);
    }
}

fn write_u32(page: &mut Page, off: usize, value: u32) {
    // SAFETY: tests use aligned, in-page offsets.
    unsafe {
        core::ptr::write_volatile(page.0.as_mut_ptr().add(off) as *mut u32, value);
    }
}

fn event(value: u32) -> VirtioInputEvent {
    VirtioInputEvent {
        ty: crate::EV_LED,
        code: TEST_LED_CODE,
        value,
    }
}

#[test]
fn transport_profile_requires_event_status_and_device_config() {
    let profile = crate::transport_profile();
    assert!(profile.child_requirements.required_queues[EVENT_QUEUE_SLOT]);
    assert!(profile.child_requirements.required_queues[STATUS_QUEUE_SLOT]);
    assert!(profile.child_requirements.needs_device_cfg);
    let q1 = profile.queue_plans[STATUS_QUEUE_SLOT].expect("statusq plan");
    assert_eq!(q1.index, STATUS_QUEUE_INDEX);
    assert!(q1.map_notify);
    assert_eq!(
        q1.msix_handler.is_some(),
        profile.msix0_handler.is_some(),
    );
}

#[test]
fn resource_gate_rejects_missing_statusq_or_device_config() {
    const QUEUE_SIZE: u16 = 2;
    const EVENT_DESC_PA: u64 = 1;
    const EVENT_DRIVER_PA: u64 = 2;
    const EVENT_DEVICE_PA: u64 = 3;
    const EVENT_NOTIFY_VA: u64 = 4;
    const STATUS_DESC_PA: u64 = 5;
    const STATUS_DRIVER_PA: u64 = 6;
    const STATUS_DEVICE_PA: u64 = 7;
    const STATUS_NOTIFY_VA: u64 = 8;
    const CFG_VA: u64 = 9;
    const HHDM: u64 = 10;
    const DEVICE_CFG_VA: u64 = 11;

    let q0 = virtio::VirtQueueResource::new(EVENT_QUEUE_INDEX, QUEUE_SIZE,
        EVENT_DESC_PA, EVENT_DRIVER_PA, EVENT_DEVICE_PA, EVENT_NOTIFY_VA, 0);
    let q1 = virtio::VirtQueueResource::new(STATUS_QUEUE_INDEX, QUEUE_SIZE,
        STATUS_DESC_PA, STATUS_DRIVER_PA, STATUS_DEVICE_PA, STATUS_NOTIFY_VA, 0);
    let no_q1 = virtio::VirtioResources::from_queues(CFG_VA, HHDM, &[q0])
        .with_device_cfg_va(DEVICE_CFG_VA);
    let no_device_cfg = virtio::VirtioResources::from_queues(CFG_VA, HHDM, &[q0, q1]);
    let complete = no_device_cfg.with_device_cfg_va(DEVICE_CFG_VA);

    assert!(queue::required_queues(&no_q1).is_none());
    assert!(queue::required_queues(&no_device_cfg).is_none());
    assert_eq!(queue::required_queues(&complete), Some((q0, q1)));
}

#[test]
fn eventq_publishes_every_frame_backed_descriptor() {
    let mut fixture = Fixture::new();
    let eventq = virtio::VirtQueueResource {
        index: EVENT_QUEUE_INDEX,
        ..fixture.queue(queue::MAX_EVENT_BUFFERS)
    };
    let frame_pa = fixture.frames.0.as_mut_ptr() as u64;

    let supplied = queue::initialize_eventq(0, eventq, frame_pa);

    assert_eq!(supplied, queue::MAX_EVENT_BUFFERS);
    assert_eq!(
        read_u16(&fixture.avail, RING_INDEX_OFF),
        queue::MAX_EVENT_BUFFERS,
    );
    assert_eq!(
        read_u16(
            &fixture.avail,
            RING_ENTRIES_OFF
                + (queue::MAX_EVENT_BUFFERS as usize - 1) * AVAIL_ENTRY_BYTES,
        ),
        queue::MAX_EVENT_BUFFERS - 1,
    );
    let last = (queue::MAX_EVENT_BUFFERS as usize - 1) * DESC_BYTES;
    assert_eq!(
        read_u64(&fixture.desc, last),
        frame_pa + u64::from(queue::MAX_EVENT_BUFFERS - 1) * EVENT_BYTES as u64,
    );
    assert_eq!(read_u32(&fixture.desc, last + DESC_LEN_OFF), EVENT_BYTES as u32);
}

#[test]
fn status_descriptor_is_driver_readable_eight_byte_indexed_buffer() {
    const DEVICE_KEY_RAW: u32 = 0x4100_0000;
    const QUEUE_SIZE: u16 = 2;
    const EVENT_VALUE: u32 = 7;

    let _guard = TEST_LOCK.lock();
    reset();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(key(DEVICE_KEY_RAW), QUEUE_SIZE);

    assert_eq!(read_u64(&fixture.desc, 0), fixture.frames.0.as_ptr() as u64);
    assert_eq!(read_u32(&fixture.desc, DESC_LEN_OFF), EVENT_BYTES as u32);
    assert_eq!(read_u16(&fixture.desc, DESC_FLAGS_OFF), 0);
    assert_eq!(read_u16(&fixture.desc, DESC_NEXT_OFF), 0);
    assert_eq!(read_u16(&fixture.avail, RING_INDEX_OFF), 0);

    assert_eq!(status::submit(&mut ctx, event(EVENT_VALUE)), Ok(()));
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

#[test]
fn canonical_output_batch_is_encoded_for_exact_status_queue() {
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

#[test]
fn exact_device_send_and_teardown_retain_both_owned_frames() {
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
