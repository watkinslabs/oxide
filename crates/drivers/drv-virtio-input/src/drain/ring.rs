use core::sync::atomic::{AtomicU64, Ordering};

use super::key_event::handle_key_event;
use super::queue::QueueCtx;
use crate::{EV_KEY, VirtioInputEvent};

pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub(super) fn drain_one(ctx: &mut QueueCtx, evdev_id: u32) {
    let used_va = ctx.hhdm.wrapping_add(ctx.eventq.device_pa) as *mut u8;
    // SAFETY: HHDM-mapped used-ring base; aligned u16 load of device idx.
    let dev_idx = unsafe { core::ptr::read_volatile(used_va.add(2) as *const u16) };
    if dev_idx == ctx.last_used { return; }

    while ctx.last_used != dev_idx {
        let i = (ctx.last_used as usize) % ctx.eventq.size as usize;
        let off = 4 + i * 8;
        // SAFETY: bounded u32 read within used ring.
        let desc_id = unsafe { core::ptr::read_volatile(used_va.add(off) as *const u32) } as u16;
        let evt_pa = ctx.buf_pa.wrapping_add((desc_id as u64) * 8);
        let evt_va = ctx.hhdm.wrapping_add(evt_pa) as *const VirtioInputEvent;
        // SAFETY: 8-byte event slot inside our buffer pool.
        let evt = unsafe { core::ptr::read_volatile(evt_va) };
        DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);

        crate::evdev_queue::push_event(evdev_id, evt.ty, evt.code, evt.value as i32);
        if evt.ty == EV_KEY && !ctx.is_pointer {
            let pressed = evt.value == 1 || evt.value == 2;
            handle_key_event(evt.code, pressed);
        }

        let avail_va = ctx.hhdm.wrapping_add(ctx.eventq.driver_pa) as *mut u8;
        let avail_slot = (ctx.avail_idx as usize) % ctx.eventq.size as usize;
        let avail_off = 4 + avail_slot * 2;
        // SAFETY: bounded u16 write inside the avail ring buffer.
        unsafe { core::ptr::write_volatile(avail_va.add(avail_off) as *mut u16, desc_id); }
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        ctx.last_used = ctx.last_used.wrapping_add(1);
    }

    let avail_va = ctx.hhdm.wrapping_add(ctx.eventq.driver_pa) as *mut u8;
    // SAFETY: aligned u16 store of the new avail.idx.
    unsafe { core::ptr::write_volatile(avail_va.add(2) as *mut u16, ctx.avail_idx); }
    // SAFETY: queue notify register VA; u16 store of the queue index.
    unsafe { core::ptr::write_volatile(ctx.eventq.notify_va as *mut u16, ctx.eventq.index); }
}
