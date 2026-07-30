use core::sync::atomic::{fence, AtomicU64, Ordering};

use super::queue::{QueueCtx, MAX_EVENT_BUFFERS};
use crate::VirtioInputEvent;

const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();
const USED_ELEM_BYTES: usize = core::mem::size_of::<virtio::queue::UsedElem>();
const RING_INDEX_OFF: usize = core::mem::size_of::<u16>();
const RING_ENTRIES_OFF: usize = RING_INDEX_OFF + core::mem::size_of::<u16>();
const AVAIL_ENTRY_BYTES: usize = core::mem::size_of::<u16>();
const USED_ID_OFF: usize = 0;
const USED_LEN_OFF: usize = core::mem::size_of::<u32>();

pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub(super) fn deliver_event(evdev_id: u32, evt: VirtioInputEvent) -> bool {
    input::push_evdev_event(evdev_id, evt.ty, evt.code, evt.value as i32)
}

pub(super) fn drain_one(ctx: &mut QueueCtx, evdev_id: u32) {
    if ctx.eventq_failed {
        return;
    }
    let used_va = ctx.hhdm.wrapping_add(ctx.eventq.device_pa) as *mut u8;
    // SAFETY: HHDM-mapped used-ring base; aligned u16 load of device idx.
    let dev_idx = unsafe {
        core::ptr::read_volatile(used_va.add(RING_INDEX_OFF) as *const u16)
    };
    fence(Ordering::Acquire);
    let pending = dev_idx.wrapping_sub(ctx.last_used);
    if pending == 0 {
        return;
    }
    if pending > ctx.event_buffers || pending > ctx.eventq.size {
        ctx.eventq_failed = true;
        return;
    }

    let mut descriptor_ids = [0u16; MAX_EVENT_BUFFERS as usize];
    let mut seen = [false; MAX_EVENT_BUFFERS as usize];
    for pending_index in 0..pending as usize {
        let used_index = ctx.last_used.wrapping_add(pending_index as u16);
        let slot = (used_index as usize) % ctx.eventq.size as usize;
        let elem = RING_ENTRIES_OFF + slot * USED_ELEM_BYTES;
        // SAFETY: the used entry is bounded by the validated queue size.
        let (id, len) = unsafe {
            (
                core::ptr::read_volatile(
                    used_va.add(elem + USED_ID_OFF) as *const u32,
                ),
                core::ptr::read_volatile(
                    used_va.add(elem + USED_LEN_OFF) as *const u32,
                ),
            )
        };
        if id >= u32::from(ctx.event_buffers)
            || len != EVENT_BYTES as u32
            || seen[id as usize]
        {
            ctx.eventq_failed = true;
            return;
        }
        descriptor_ids[pending_index] = id as u16;
        seen[id as usize] = true;
    }

    let avail_va = ctx.hhdm.wrapping_add(ctx.eventq.driver_pa) as *mut u8;
    for desc_id in descriptor_ids.iter().copied().take(pending as usize) {
        let evt_pa = ctx.buf_pa
            .wrapping_add(u64::from(desc_id) * EVENT_BYTES as u64);
        let evt_va = ctx.hhdm.wrapping_add(evt_pa) as *const VirtioInputEvent;
        // SAFETY: validated descriptor id owns one event slot in the buffer pool.
        let evt = unsafe { core::ptr::read_volatile(evt_va) };
        DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);

        deliver_event(evdev_id, evt);

        let avail_slot = (ctx.avail_idx as usize) % ctx.eventq.size as usize;
        let avail_off = RING_ENTRIES_OFF + avail_slot * AVAIL_ENTRY_BYTES;
        // SAFETY: bounded u16 write inside the avail ring buffer.
        unsafe { core::ptr::write_volatile(avail_va.add(avail_off) as *mut u16, desc_id); }
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        ctx.last_used = ctx.last_used.wrapping_add(1);
    }

    fence(Ordering::Release);
    // SAFETY: aligned u16 store of the new avail.idx.
    unsafe {
        core::ptr::write_volatile(
            avail_va.add(RING_INDEX_OFF) as *mut u16,
            ctx.avail_idx,
        );
    }
    fence(Ordering::SeqCst);
    // SAFETY: queue notify register VA; u16 store of the queue index.
    unsafe { core::ptr::write_volatile(ctx.eventq.notify_va as *mut u16, ctx.eventq.index); }
}
