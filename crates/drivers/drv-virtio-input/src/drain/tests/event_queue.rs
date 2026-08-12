use alloc::collections::VecDeque;
use core::sync::atomic::Ordering;

use super::super::{queue, ring};
use super::{key, QueueCtx, TEST_LOCK};
use crate::VirtioInputEvent;

const DEVICE_KEY_RAW: u32 = 0x4010_0000;
const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();
const USED_ELEM_BYTES: usize = core::mem::size_of::<virtio::queue::UsedElem>();
const RING_INDEX_OFF: usize = core::mem::size_of::<u16>();
const RING_ENTRIES_OFF: usize = RING_INDEX_OFF + core::mem::size_of::<u16>();
const USED_ID_OFF: usize = 0;
const USED_LEN_OFF: usize = core::mem::size_of::<u32>();
const TWO_ENTRY_QUEUE_SIZE: u16 = 2;
const SINGLE_ENTRY_QUEUE_SIZE: u16 = 1;
const INVALID_DESCRIPTOR_ID: u32 = 2;
const SHORT_COMPLETION_LEN: u32 = 1;

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

    fn context(&mut self, size: u16) -> QueueCtx {
        let eventq = virtio::VirtQueueResource {
            index: 0,
            size,
            desc_pa: self.desc.0.as_mut_ptr() as u64,
            driver_pa: self.avail.0.as_mut_ptr() as u64,
            device_pa: self.used.0.as_mut_ptr() as u64,
            notify_va: (&mut self.notify as *mut u16) as u64,
            notify_off: 0,
        };
        let statusq = virtio::VirtQueueResource { index: 1, ..eventq };
        let mut eventq_owner = virtio::VirtioSplitQueue::new(eventq, 0).expect("event queue");
        let mut event_desc_slots = [u16::MAX; queue::MAX_EVENT_BUFFERS as usize];
        let event_buffers = queue::post_event_buffers(
            &mut eventq_owner,
            self.frames.0.as_mut_ptr() as u64,
            &mut event_desc_slots,
        ).expect("event buffers");
        let statusq_owner = virtio::VirtioSplitQueue::new(statusq, 0).expect("status queue");
        QueueCtx {
            device_key: key(DEVICE_KEY_RAW),
            bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 },
            cfg_va: 0,
            hhdm: 0,
            eventq: Some(eventq_owner),
            buf_pa: self.frames.0.as_mut_ptr() as u64,
            buf_dma: self.frames.0.as_mut_ptr() as u64,
            event_buffers,
            event_desc_slots,
            statusq: Some(statusq_owner),
            status_buf_pa: 0,
            status_buf_dma: 0,
            status: super::super::status::StatusState::new(size)
                .expect("status state"),
            status_desc_slots: [u16::MAX; super::super::status::MAX_STATUS_DESCRIPTORS],
            pending_output: VecDeque::new(),
            eventq_failed: false,
        }
    }
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

fn assert_rejected_without_partial_delivery(fixture: &Fixture, ctx: &QueueCtx, before: u64) {
    assert!(ctx.eventq_failed);
    assert_eq!(fixture.notify, 0);
    assert_eq!(ring::DRAINED_EVENTS.load(Ordering::Relaxed), before);
}

#[test]
fn invalid_later_event_descriptor_rejects_entire_snapshot() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(TWO_ENTRY_QUEUE_SIZE);
    let before = ring::DRAINED_EVENTS.load(Ordering::Relaxed);

    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        EVENT_BYTES as u32,
    );
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_ELEM_BYTES + USED_ID_OFF,
        INVALID_DESCRIPTOR_ID,
    );
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_ELEM_BYTES + USED_LEN_OFF,
        EVENT_BYTES as u32,
    );
    write_u16(
        &mut fixture.used,
        RING_INDEX_OFF,
        TWO_ENTRY_QUEUE_SIZE,
    );

    ring::drain_one(&mut ctx, 0);

    assert_rejected_without_partial_delivery(&fixture, &ctx, before);
}

#[test]
fn duplicate_event_descriptor_rejects_entire_snapshot() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(TWO_ENTRY_QUEUE_SIZE);
    let before = ring::DRAINED_EVENTS.load(Ordering::Relaxed);

    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        EVENT_BYTES as u32,
    );
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_ELEM_BYTES + USED_ID_OFF,
        0,
    );
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_ELEM_BYTES + USED_LEN_OFF,
        EVENT_BYTES as u32,
    );
    write_u16(
        &mut fixture.used,
        RING_INDEX_OFF,
        TWO_ENTRY_QUEUE_SIZE,
    );

    ring::drain_one(&mut ctx, 0);

    assert_rejected_without_partial_delivery(&fixture, &ctx, before);
}

#[test]
fn short_event_completion_rejects_entire_snapshot() {
    let _devices = crate::registry::own_device_table();
    let _guard = TEST_LOCK.lock();
    let mut fixture = Fixture::new();
    let mut ctx = fixture.context(SINGLE_ENTRY_QUEUE_SIZE);
    let before = ring::DRAINED_EVENTS.load(Ordering::Relaxed);

    write_u32(&mut fixture.used, RING_ENTRIES_OFF + USED_ID_OFF, 0);
    write_u32(
        &mut fixture.used,
        RING_ENTRIES_OFF + USED_LEN_OFF,
        SHORT_COMPLETION_LEN,
    );
    write_u16(
        &mut fixture.used,
        RING_INDEX_OFF,
        SINGLE_ENTRY_QUEUE_SIZE,
    );

    ring::drain_one(&mut ctx, 0);

    assert_rejected_without_partial_delivery(&fixture, &ctx, before);
}
