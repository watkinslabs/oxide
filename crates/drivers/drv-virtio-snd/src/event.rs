use super::*;

pub fn raise_event() {
    softirq::raise(softirq::Slot::SndEvent);
}

pub(super) fn event_softirq() {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    for ctx in g.iter_mut() {
        drain_eventq(ctx);
    }
}

pub(super) fn drain_eventq(ctx: &mut Ctx) {
    let Some(mut eventq) = ctx.eventq.take() else { return };
    let mut reposted = false;
    loop {
        let used = match eventq.pop_used() {
            Ok(Some(used)) => used,
            Ok(None) => break,
            Err(_) => { ctx.eventq = Some(eventq); return; }
        };
        let desc_id = used.head;
        // `desc_id` is DEVICE-supplied, so it bounds nothing until it is
        // checked: install refused an eventq larger than the event frame
        // holds, hence desc_id < size implies the buffer below is in-frame.
        if desc_id < eventq.resource().size {
            let event_pa = ctx.event_buf_pa.wrapping_add((desc_id as u64) * EVENT_SIZE as u64);
            let event_va = ctx.hhdm.wrapping_add(event_pa) as *const u64;
            // SAFETY: HHDM view of this Ctx's event frame; the checked desc_id
            // keeps the EVENT_SIZE-aligned slot inside the frame, and the
            // device has finished with it (its used element was consumed).
            let raw = unsafe { core::ptr::read_volatile(event_va) };
            record_event(ctx, raw);

            if eventq.submit_no_kick(&[virtio::SplitQueueSeg {
                dma: event_pa, len: EVENT_SIZE as u32, device_writes: true,
            }]).is_err() { ctx.eventq = Some(eventq); return; }
            reposted = true;
        }
    }
    if reposted { eventq.kick(); }
    ctx.eventq = Some(eventq);
}

pub(super) fn record_event(ctx: &mut Ctx, raw: u64) {
    ctx.event_last_raw = raw;
    ctx.event_drained = ctx.event_drained.wrapping_add(1);
    LAST_EVENT.store(raw, Ordering::Relaxed);
    DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);
}
