use core::sync::atomic::{AtomicU64, Ordering};

use super::queue::{QueueCtx, MAX_EVENT_BUFFERS};
use crate::VirtioInputEvent;

const EVENT_BYTES: usize = core::mem::size_of::<VirtioInputEvent>();

pub static DRAINED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub(super) fn deliver_event(evdev_id: u32, evt: VirtioInputEvent) -> bool {
    input::push_evdev_event(evdev_id, evt.ty, evt.code, evt.value as i32)
}

/// Retire a complete input batch and requeue its event buffers. The shared
/// queue owns descriptor/ring bookkeeping; this layer retains only event-slot
/// ownership, as Linux's virtio-input keeps the event buffer token.
pub(super) fn drain_one(ctx: &mut QueueCtx, evdev_id: u32) {
    if ctx.eventq_failed { return; }
    let Some(eventq) = ctx.eventq.as_mut() else {
        ctx.eventq_failed = true;
        return;
    };
    let mut slots = [u16::MAX; MAX_EVENT_BUFFERS as usize];
    let mut seen = [false; MAX_EVENT_BUFFERS as usize];
    let mut completed = 0usize;
    loop {
        let used = match eventq.pop_used() {
            Ok(Some(used)) => used,
            Ok(None) => break,
            Err(_) => {
                ctx.eventq_failed = true;
                return;
            }
        };
        let slot = ctx.event_desc_slots[used.head as usize];
        if completed == slots.len() || slot >= ctx.event_buffers
            || used.len != EVENT_BYTES as u32 || seen[slot as usize]
        {
            ctx.eventq_failed = true;
            return;
        }
        slots[completed] = slot;
        seen[slot as usize] = true;
        completed += 1;
    }
    if completed == 0 { return; }

    for slot in slots.iter().copied().take(completed) {
        let evt_pa = ctx.buf_pa.wrapping_add(u64::from(slot) * EVENT_BYTES as u64);
        let evt_va = ctx.hhdm.wrapping_add(evt_pa) as *const VirtioInputEvent;
        // SAFETY: the completion's descriptor token names this input buffer slot.
        let evt = unsafe { core::ptr::read_volatile(evt_va) };
        DRAINED_EVENTS.fetch_add(1, Ordering::Relaxed);
        let _ = deliver_event(evdev_id, evt);
    }
    for slot in slots.iter().copied().take(completed) {
        let head = match eventq.submit_no_kick(&[virtio::SplitQueueSeg {
            dma: ctx.buf_dma.wrapping_add(u64::from(slot) * EVENT_BYTES as u64),
            len: EVENT_BYTES as u32,
            device_writes: true,
        }]) {
            Ok(head) => head,
            Err(_) => {
                ctx.eventq_failed = true;
                return;
            }
        };
        ctx.event_desc_slots[head as usize] = slot;
    }
    eventq.kick();
}
