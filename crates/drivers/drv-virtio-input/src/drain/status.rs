use alloc::vec::Vec;
use super::queue::{QueueCtx, CTXS};
use crate::VirtioInputEvent;

const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();
const EVENT_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / EVENT_BYTES;
const DESC_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize
    / core::mem::size_of::<virtio::queue::Desc>();
pub(super) const MAX_STATUS_DESCRIPTORS: usize =
    if DESC_FRAME_CAPACITY < EVENT_FRAME_CAPACITY {
        DESC_FRAME_CAPACITY
    } else { EVENT_FRAME_CAPACITY };

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StatusError {
    NoDevice,
    QueueFull,
    CorruptQueue,
}

/// Bounded ownership ledger for 8-byte, driver-to-device statusq buffers
/// matching virtio 1.2 §5.8.6.
pub(super) struct StatusState {
    /// Diagnostic submission/completion counters. Ring ownership remains in
    /// `VirtioSplitQueue`; these only preserve the status-slot ledger.
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
        self.last_used = self.last_used.wrapping_add(1);
        self.free[self.free_len as usize] = id as u16;
        self.free_len += 1;
        Ok(())
    }

    fn cancel(&mut self, id: u16, qsize: u16) -> Result<(), StatusError> {
        if id >= qsize || !self.in_flight[id as usize] || self.free_len >= qsize {
            return Err(StatusError::CorruptQueue);
        }
        self.in_flight[id as usize] = false;
        self.in_flight_len -= 1;
        self.free[self.free_len as usize] = id;
        self.free_len += 1;
        Ok(())
    }
}

fn reap_used(ctx: &mut QueueCtx) -> Result<(), StatusError> {
    if ctx.status.poisoned {
        return Err(StatusError::CorruptQueue);
    }
    let Some(statusq) = ctx.statusq.as_mut() else { return Err(StatusError::NoDevice); };
    let qsize = statusq.resource().size;
    loop {
        let used = match statusq.pop_used() {
            Ok(Some(used)) => used,
            Ok(None) => return Ok(()),
            Err(_) => {
                ctx.status.poisoned = true;
                return Err(StatusError::CorruptQueue);
            }
        };
        let id = ctx.status_desc_slots[used.head as usize];
        if used.len != 0 || id == u16::MAX || ctx.status.complete(u32::from(id), qsize).is_err() {
            ctx.status.poisoned = true;
            return Err(StatusError::CorruptQueue);
        }
    }
}

fn submit_ready(ctx: &mut QueueCtx, event: VirtioInputEvent) -> Result<(), StatusError> {
    let id = ctx.status.take_free().ok_or(StatusError::QueueFull)?;
    let frame = ctx.hhdm
        .wrapping_add(ctx.status_buf_pa)
        .wrapping_add(u64::from(id) * EVENT_BYTES as u64)
        as *mut VirtioInputEvent;
    // SAFETY: id was removed from the status free ledger and owns this slot.
    unsafe { core::ptr::write_volatile(frame, event); }
    let Some(statusq) = ctx.statusq.as_mut() else {
        let _ = ctx.status.cancel(id, ctx.status.free_len + ctx.status.in_flight_len);
        return Err(StatusError::NoDevice);
    };
    let qsize = statusq.resource().size;
    let head = match statusq.submit(&[virtio::SplitQueueSeg {
        dma: ctx.status_buf_dma.wrapping_add(u64::from(id) * EVENT_BYTES as u64),
        len: EVENT_BYTES as u32,
        device_writes: false,
    }]) {
        Ok(head) => head,
        Err(_) => {
            let _ = ctx.status.cancel(id, qsize);
            return Err(StatusError::CorruptQueue);
        }
    };
    ctx.status_desc_slots[head as usize] = id;
    ctx.status.avail_idx = ctx.status.avail_idx.wrapping_add(1);
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
    let mut contexts = CTXS.lock_bh::<crate::drain::queue::InputBh>();
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
    let mut contexts = CTXS.lock_bh::<crate::drain::queue::InputBh>();
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
    let mut contexts = CTXS.lock_bh::<crate::drain::queue::InputBh>();
    let ctx = contexts.iter_mut()
        .flatten()
        .find(|ctx| ctx.device_key == device_key)
        .ok_or(StatusError::NoDevice)?;
    ctx.pending_output.extend(events);
    let _ = flush_pending(ctx);
    Ok(())
}
