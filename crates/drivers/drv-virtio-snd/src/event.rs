use super::*;

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
    let dev_idx = unsafe { core::ptr::read_volatile(used_va.add(2) as *const u16) };
    if dev_idx == ctx.event_last_used {
        return;
    }

    while ctx.event_last_used != dev_idx {
        let i = (ctx.event_last_used as usize) % eventq.size as usize;
        let used_off = 4 + i * 8;
        let desc_id =
            unsafe { core::ptr::read_volatile(used_va.add(used_off) as *const u32) } as u16;
        if desc_id < eventq.size {
            let event_pa = ctx.event_buf_pa.wrapping_add((desc_id as u64) * EVENT_SIZE as u64);
            let event_va = ctx.hhdm.wrapping_add(event_pa) as *const u64;
            let raw = unsafe { core::ptr::read_volatile(event_va) };
            record_event(ctx, raw);

            let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
            let slot = (ctx.event_avail_idx as usize) % eventq.size as usize;
            unsafe {
                core::ptr::write_volatile(avail_va.add(4 + slot * 2) as *mut u16, desc_id);
            }
            ctx.event_avail_idx = ctx.event_avail_idx.wrapping_add(1);
        }
        ctx.event_last_used = ctx.event_last_used.wrapping_add(1);
    }

    let avail_va = ctx.hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
    unsafe {
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(avail_va.add(2) as *mut u16, ctx.event_avail_idx);
        core::ptr::write_volatile(eventq.notify_va as *mut u16, eventq.index);
    }
}

pub(super) fn record_event(ctx: &mut Ctx, raw: u64) {
    ctx.event_last_raw = raw;
    ctx.event_drained = ctx.event_drained.wrapping_add(1);
    LAST_EVENT.store(raw, Ordering::Relaxed);
    DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);
}
