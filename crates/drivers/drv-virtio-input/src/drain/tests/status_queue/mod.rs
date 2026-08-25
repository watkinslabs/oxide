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
        let status = status::StatusState::new(statusq.size).expect("valid status queue");
        let statusq_owner = virtio::VirtioSplitQueue::new(statusq, 0).expect("status queue");
        QueueCtx {
            device_key,
            bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 },
            cfg_va: 0,
            hhdm: 0,
            eventq: None,
            buf_pa: TEST_EVENT_BUF_PA,
            buf_dma: TEST_EVENT_BUF_PA,
            event_buffers: size.min(queue::MAX_EVENT_BUFFERS),
            event_desc_slots: [u16::MAX; queue::MAX_EVENT_BUFFERS as usize],
            statusq: Some(statusq_owner),
            status_buf_pa: self.frames.0.as_mut_ptr() as u64,
            status_buf_dma: self.frames.0.as_mut_ptr() as u64,
            status,
            status_desc_slots: [u16::MAX; status::MAX_STATUS_DESCRIPTORS],
            pending_output: VecDeque::new(),
            eventq_failed: false,
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


#[path = "tests/transport.rs"]
mod transport;
#[path = "tests/event_queue.rs"]
mod event_queue;
#[path = "tests/status.rs"]
mod status_ops;
#[path = "tests/output.rs"]
mod output;
#[path = "tests/teardown.rs"]
mod teardown;
