use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use super::queue::{QueueCtx, CTXS};
use crate::VirtioInputEvent;

const DESC_BYTES: usize = core::mem::size_of::<virtio::queue::Desc>();
const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();
const USED_ELEM_BYTES: usize = core::mem::size_of::<virtio::queue::UsedElem>();
const DESC_LEN_OFF: usize = core::mem::size_of::<u64>();
const DESC_FLAGS_OFF: usize = DESC_LEN_OFF + core::mem::size_of::<u32>();
const DESC_NEXT_OFF: usize = DESC_FLAGS_OFF + core::mem::size_of::<u16>();
const RING_INDEX_OFF: usize = core::mem::size_of::<u16>();
const RING_ENTRIES_OFF: usize = RING_INDEX_OFF + core::mem::size_of::<u16>();
const AVAIL_ENTRY_BYTES: usize = core::mem::size_of::<u16>();
const USED_ID_OFF: usize = 0;
const USED_LEN_OFF: usize = core::mem::size_of::<u32>();
const DESC_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / DESC_BYTES;
const EVENT_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / EVENT_BYTES;
pub(super) const MAX_STATUS_DESCRIPTORS: usize =
    if DESC_FRAME_CAPACITY < EVENT_FRAME_CAPACITY {
        DESC_FRAME_CAPACITY
    } else {
        EVENT_FRAME_CAPACITY
    };

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StatusError {
    NoDevice,
    QueueFull,
    CorruptQueue,
}

/// Bounded ownership ledger for 8-byte, driver-to-device statusq buffers
/// matching virtio 1.2 §5.8.6.
pub(super) struct StatusState {
    pub(super) last_used: u16,
    pub(super) avail_idx: u16,
    pub(super) free: [u16; MAX_STATUS_DESCRIPTORS],
    pub(super) free_len: u16,
    pub(super) in_flight: [bool; MAX_STATUS_DESCRIPTORS],
    pub(super) in_flight_len: u16,
    poisoned: bool,
}

impl StatusState {
    pub(super) fn new(qsize: u16) -> Option<Self> {
        if qsize == 0 || qsize as usize > MAX_STATUS_DESCRIPTORS {
            return None;
        }
        let mut free = [0; MAX_STATUS_DESCRIPTORS];
        let mut i = 0usize;
        while i < qsize as usize {
            free[i] = qsize - 1 - i as u16;
            i += 1;
        }
        Some(Self {
            last_used: 0,
            avail_idx: 0,
            free,
            free_len: qsize,
            in_flight: [false; MAX_STATUS_DESCRIPTORS],
            in_flight_len: 0,
            poisoned: false,
        })
    }

    fn take_free(&mut self) -> Option<u16> {
        if self.free_len == 0 {
            return None;
        }
        self.free_len -= 1;
        let id = self.free[self.free_len as usize];
        self.in_flight[id as usize] = true;
        self.in_flight_len += 1;
        Some(id)
    }

    fn complete(&mut self, id: u32, qsize: u16) -> Result<(), StatusError> {
        if id >= u32::from(qsize) || !self.in_flight[id as usize] {
            return Err(StatusError::CorruptQueue);
        }
        if self.free_len >= qsize || self.in_flight_len == 0 {
            return Err(StatusError::CorruptQueue);
        }
        self.in_flight[id as usize] = false;
        self.in_flight_len -= 1;
        self.free[self.free_len as usize] = id as u16;
        self.free_len += 1;
        Ok(())
    }
}

/// Initialize q1 descriptors as driver-readable 8-byte buffers. In
/// `vring_desc`, absence of `VRING_DESC_F_WRITE` is the required out direction.
pub(super) fn initialize(
    hhdm: u64,
    queue: virtio::VirtQueueResource,
    buf_pa: u64,
) -> Option<StatusState> {
    let state = StatusState::new(queue.size)?;
    let desc = hhdm.wrapping_add(queue.desc_pa) as *mut u8;
    let avail = hhdm.wrapping_add(queue.driver_pa) as *mut u8;
    // SAFETY: transport validated a qsize-entry descriptor/avail allocation;
    // the status frame has one 8-byte slot for every accepted descriptor.
    unsafe {
        for id in 0..queue.size as usize {
            let off = id * DESC_BYTES;
            core::ptr::write_volatile(
                desc.add(off) as *mut u64,
                buf_pa.wrapping_add((id * EVENT_BYTES) as u64),
            );
            core::ptr::write_volatile(
                desc.add(off + DESC_LEN_OFF) as *mut u32,
                EVENT_BYTES as u32,
            );
            core::ptr::write_volatile(desc.add(off + DESC_FLAGS_OFF) as *mut u16, 0);
            core::ptr::write_volatile(desc.add(off + DESC_NEXT_OFF) as *mut u16, 0);
        }
        core::ptr::write_volatile(avail as *mut u16, 0);
        core::ptr::write_volatile(avail.add(RING_INDEX_OFF) as *mut u16, 0);
    }
    Some(state)
}

fn reap_used(ctx: &mut QueueCtx) -> Result<(), StatusError> {
    if ctx.status.poisoned {
        return Err(StatusError::CorruptQueue);
    }
    let used = ctx.hhdm.wrapping_add(ctx.statusq.device_pa) as *const u8;
    // SAFETY: q1 used-ring header is transport-owned mapped memory.
    let device_idx = unsafe {
        core::ptr::read_volatile(used.add(RING_INDEX_OFF) as *const u16)
    };
    fence(Ordering::Acquire);
    let pending = device_idx.wrapping_sub(ctx.status.last_used);
    if pending > ctx.status.in_flight_len || pending > ctx.statusq.size {
        ctx.status.poisoned = true;
        return Err(StatusError::CorruptQueue);
    }
    while ctx.status.last_used != device_idx {
        let slot = (ctx.status.last_used as usize) % ctx.statusq.size as usize;
        let elem = RING_ENTRIES_OFF + slot * USED_ELEM_BYTES;
        // SAFETY: slot is bounded by qsize and the used element is mapped.
        let (id, len) = unsafe {
            (
                core::ptr::read_volatile(used.add(elem + USED_ID_OFF) as *const u32),
                core::ptr::read_volatile(used.add(elem + USED_LEN_OFF) as *const u32),
            )
        };
        if len != 0 || ctx.status.complete(id, ctx.statusq.size).is_err() {
            ctx.status.poisoned = true;
            return Err(StatusError::CorruptQueue);
        }
        ctx.status.last_used = ctx.status.last_used.wrapping_add(1);
    }
    Ok(())
}

fn submit_ready(ctx: &mut QueueCtx, event: VirtioInputEvent) -> Result<(), StatusError> {
    let id = ctx.status.take_free().ok_or(StatusError::QueueFull)?;
    let frame = ctx.hhdm
        .wrapping_add(ctx.status_buf_pa)
        .wrapping_add(u64::from(id) * EVENT_BYTES as u64)
        as *mut VirtioInputEvent;
    let avail = ctx.hhdm.wrapping_add(ctx.statusq.driver_pa) as *mut u8;
    let slot = (ctx.status.avail_idx as usize) % ctx.statusq.size as usize;
    // SAFETY: id owns one 8-byte frame and slot is bounded by qsize.
    unsafe {
        core::ptr::write_volatile(frame, event);
        core::ptr::write_volatile(
            avail.add(RING_ENTRIES_OFF + slot * AVAIL_ENTRY_BYTES) as *mut u16,
            id,
        );
    }
    fence(Ordering::Release);
    ctx.status.avail_idx = ctx.status.avail_idx.wrapping_add(1);
    // SAFETY: q1 avail header and notify register are mapped transport state.
    unsafe {
        core::ptr::write_volatile(
            avail.add(RING_INDEX_OFF) as *mut u16,
            ctx.status.avail_idx,
        );
    }
    fence(Ordering::SeqCst);
    // SAFETY: q1 notify register is mapped transport state.
    unsafe {
        core::ptr::write_volatile(ctx.statusq.notify_va as *mut u16, ctx.statusq.index);
    }
    Ok(())
}

pub(super) fn submit(
    ctx: &mut QueueCtx,
    event: VirtioInputEvent,
) -> Result<(), StatusError> {
    reap_used(ctx)?;
    submit_ready(ctx, event)
}

fn submit_batch(
    ctx: &mut QueueCtx,
    events: &[VirtioInputEvent],
) -> Result<(), StatusError> {
    reap_used(ctx)?;
    if events.len() > ctx.status.free_len as usize {
        return Err(StatusError::QueueFull);
    }
    for event in events.iter().copied() {
        submit_ready(ctx, event)?;
    }
    Ok(())
}

pub(super) fn flush_pending(ctx: &mut QueueCtx) -> Result<(), StatusError> {
    reap_used(ctx)?;
    while ctx.status.free_len != 0 {
        let Some(event) = ctx.pending_output.pop_front() else {
            break;
        };
        if let Err(error) = submit_ready(ctx, event) {
            ctx.pending_output.push_front(event);
            return Err(error);
        }
    }
    Ok(())
}

/// Submit to the exact installed virtio child queue. This does not call into
/// the input model, so callers need not tolerate a CTXS→input callback edge.
/// # C: O(N_devices + qsize)
pub fn send_status(
    device_key: virtio::VirtioChildDeviceKey,
    event: VirtioInputEvent,
) -> Result<(), StatusError> {
    let mut contexts = CTXS.lock();
    let ctx = contexts.iter_mut()
        .flatten()
        .find(|ctx| ctx.device_key == device_key)
        .ok_or(StatusError::NoDevice)?;
    submit(ctx, event)
}

/// Atomically reserve capacity, then submit one ordered output transaction to
/// the exact installed virtio child queue.
/// # C: O(N_devices + used + events)
pub fn send_status_batch(
    device_key: virtio::VirtioChildDeviceKey,
    events: &[VirtioInputEvent],
) -> Result<(), StatusError> {
    let mut contexts = CTXS.lock();
    let ctx = contexts.iter_mut()
        .flatten()
        .find(|ctx| ctx.device_key == device_key)
        .ok_or(StatusError::NoDevice)?;
    submit_batch(ctx, events)
}

/// Convert a canonical post-lock output batch into one statusq transaction.
/// # C: O(N_devices + used + events)
pub fn send_output_batch(
    device_key: virtio::VirtioChildDeviceKey,
    output: &input::OutputBatch,
) -> Result<(), StatusError> {
    let events = output.events.iter()
        .map(|event| VirtioInputEvent {
            ty: event.ev_type,
            code: event.code,
            value: event.value as u32,
        })
        .collect::<Vec<_>>();
    let mut contexts = CTXS.lock();
    let ctx = contexts.iter_mut()
        .flatten()
        .find(|ctx| ctx.device_key == device_key)
        .ok_or(StatusError::NoDevice)?;
    ctx.pending_output.extend(events);
    let _ = flush_pending(ctx);
    Ok(())
}
