use super::*;

const VIRTQ_USED_IDX_OFF: usize = 2;
const VIRTQ_USED_RING_OFF: usize = 4;
const VIRTQ_USED_ELEM_BYTES: usize = 8;
const VIRTQ_AVAIL_IDX_OFF: usize = 2;
const VIRTQ_AVAIL_RING_OFF: usize = 4;
const VIRTQ_AVAIL_RING_ENTRY_BYTES: usize = 2;

pub fn raise_event() {
    softirq::raise(softirq::Slot::SndEvent);
}

pub(super) fn event_softirq() {
    let mut g = CTX.lock();
    for ctx in g.iter_mut() {
        drain_eventq(ctx);
    }
}

pub(super) fn drain_eventq(ctx: &mut Ctx) {
    let Some(eventq) = ctx.eventq else { return };
    let used_va = ctx.hhdm.wrapping_add(eventq.device_pa) as *mut u8;
    // SAFETY: HHDM-mapped eventq used ring (require_queue accepted device_pa
    // at install); used.idx is the aligned u16 at byte 2, loaded volatile
    // because the device advances it asynchronously.
    let dev_idx = unsafe { core::ptr::read_volatile(used_va.add(VIRTQ_USED_IDX_OFF) as *const u16) };
    if dev_idx == ctx.event_last_used {
        return;
    }

    while ctx.event_last_used != dev_idx {
        let i = (ctx.event_last_used as usize) % eventq.size as usize;
        let used_off = VIRTQ_USED_RING_OFF + i * VIRTQ_USED_ELEM_BYTES;
        // SAFETY: HHDM-mapped eventq used ring; ring[] starts at byte 4 and
        // each element is {id,len} of 8 bytes, so element i's id is the
        // aligned u32 at 4 + i*8 with i < eventq.size.
        let raw_id = unsafe { core::ptr::read_volatile(used_va.add(used_off) as *const u32) };
        let desc_id = raw_id as u16;
        // `desc_id` is DEVICE-supplied, so it bounds nothing until it is
        // checked: install refused an eventq larger than the event frame
        // holds, hence desc_id < size implies the buffer below is in-frame.
        if desc_id < eventq.size {
            let event_pa = ctx.event_buf_pa.wrapping_add((desc_id as u64) * EVENT_SIZE as u64);
            let event_va = ctx.hhdm.wrapping_add(event_pa) as *const u64;
            // SAFETY: HHDM view of this Ctx's event frame; the checked desc_id
            // keeps the EVENT_SIZE-aligned slot inside the frame, and the
            // device has finished with it (its used element was consumed).
            let raw = unsafe { core::ptr::read_volatile(event_va) };
            record_event(ctx, raw);

            let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
            let slot = (ctx.event_avail_idx as usize) % eventq.size as usize;
            let ring_off = VIRTQ_AVAIL_RING_OFF + slot * VIRTQ_AVAIL_RING_ENTRY_BYTES;
            // SAFETY: HHDM-mapped eventq avail ring; ring[slot] is the aligned
            // u16 at 4 + slot*2 with slot < eventq.size, and re-posting the
            // descriptor is legal now that its buffer has been consumed above.
            unsafe {
                core::ptr::write_volatile(avail_va.add(ring_off) as *mut u16, desc_id);
            }
            ctx.event_avail_idx = ctx.event_avail_idx.wrapping_add(1);
        }
        ctx.event_last_used = ctx.event_last_used.wrapping_add(1);
    }

    let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
    // SAFETY: HHDM-mapped eventq avail ring plus the Device-attr notify window
    // the transport mapped; the release fence publishes every re-posted ring
    // entry before the aligned u16 idx store, and the kick is one u16 store.
    unsafe {
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(avail_va.add(VIRTQ_AVAIL_IDX_OFF) as *mut u16, ctx.event_avail_idx);
        core::ptr::write_volatile(eventq.notify_va as *mut u16, eventq.index);
    }
}

pub(super) fn record_event(ctx: &mut Ctx, raw: u64) {
    ctx.event_last_raw = raw;
    ctx.event_drained = ctx.event_drained.wrapping_add(1);
    LAST_EVENT.store(raw, Ordering::Relaxed);
    DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);
}
