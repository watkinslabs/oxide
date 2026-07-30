use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use super::{ring, status};

const DESC_BYTES: usize = core::mem::size_of::<virtio::queue::Desc>();
const EVENT_BYTES: usize = core::mem::size_of::<crate::VirtioInputEvent>();
const DESC_LEN_OFF: usize = core::mem::size_of::<u64>();
const DESC_FLAGS_OFF: usize = DESC_LEN_OFF + core::mem::size_of::<u32>();
const DESC_NEXT_OFF: usize = DESC_FLAGS_OFF + core::mem::size_of::<u16>();
const RING_INDEX_OFF: usize = core::mem::size_of::<u16>();
const RING_ENTRIES_OFF: usize = RING_INDEX_OFF + core::mem::size_of::<u16>();
const AVAIL_ENTRY_BYTES: usize = core::mem::size_of::<u16>();
const DESC_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / DESC_BYTES;
const EVENT_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / EVENT_BYTES;
pub(super) const MAX_EVENT_BUFFERS: u16 =
    if DESC_FRAME_CAPACITY < EVENT_FRAME_CAPACITY {
        DESC_FRAME_CAPACITY as u16
    } else {
        EVENT_FRAME_CAPACITY as u16
    };

/// Per-virtio-input-device runtime state. Captured at boot via
/// `install_eventq`; consumed by the softirq drain.
pub(super) struct QueueCtx {
    pub(super) device_key:  virtio::VirtioChildDeviceKey,
    pub(super) cfg_va:      u64,
    pub(super) hhdm:        u64,
    pub(super) eventq:      virtio::VirtQueueResource,
    pub(super) buf_pa:      u64,
    pub(super) event_buffers: u16,
    pub(super) statusq:     virtio::VirtQueueResource,
    pub(super) status_buf_pa: u64,
    pub(super) status:      status::StatusState,
    pub(super) pending_output: VecDeque<crate::VirtioInputEvent>,
    pub(super) last_used:   u16,
    pub(super) avail_idx:   u16,
    pub(super) eventq_failed: bool,
}

/// All installed input devices share one drain.
pub(super) static CTXS:
    Spinlock<[Option<QueueCtx>; crate::MAX_INPUT_DEVICES], DriverLockClass> =
    Spinlock::new([const { None }; crate::MAX_INPUT_DEVICES]);

pub(super) static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

pub(super) fn required_queues(
    resources: &virtio::VirtioResources,
) -> Option<(virtio::VirtQueueResource, virtio::VirtQueueResource)> {
    if !resources.common_cfg_valid() || resources.device_cfg_va == 0 {
        return None;
    }
    Some((resources.require_queue(0)?, resources.require_queue(1)?))
}

fn zero_frame(hhdm: u64, pa: u64) {
    // SAFETY: caller exclusively owns this HHDM-mapped frame.
    unsafe {
        let va = hhdm.wrapping_add(pa) as *mut u8;
        for i in 0..hal::PAGE_SIZE_BYTES as usize {
            core::ptr::write_volatile(va.add(i), 0);
        }
    }
}

pub(super) fn initialize_eventq(
    hhdm: u64,
    eventq: virtio::VirtQueueResource,
    buf_pa: u64,
) -> u16 {
    let supplied = eventq.size.min(MAX_EVENT_BUFFERS);
    let desc_va = hhdm.wrapping_add(eventq.desc_pa) as *mut u8;
    let avail_va = hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
    // SAFETY: supplied entries fit the defined event-buffer pool and rings.
    unsafe {
        for i in 0..supplied as usize {
            let off = i * DESC_BYTES;
            core::ptr::write_volatile(
                desc_va.add(off) as *mut u64,
                buf_pa.wrapping_add((i * EVENT_BYTES) as u64),
            );
            core::ptr::write_volatile(
                desc_va.add(off + DESC_LEN_OFF) as *mut u32,
                EVENT_BYTES as u32,
            );
            core::ptr::write_volatile(
                desc_va.add(off + DESC_FLAGS_OFF) as *mut u16,
                virtio::queue::VRING_DESC_F_WRITE,
            );
            core::ptr::write_volatile(desc_va.add(off + DESC_NEXT_OFF) as *mut u16, 0);
        }
        core::ptr::write_volatile(avail_va as *mut u16, 0);
        for i in 0..supplied as usize {
            core::ptr::write_volatile(
                avail_va.add(RING_ENTRIES_OFF + i * AVAIL_ENTRY_BYTES) as *mut u16,
                i as u16,
            );
        }
        core::ptr::write_volatile(
            avail_va.add(RING_INDEX_OFF) as *mut u16,
            supplied,
        );
    }
    supplied
}

/// Install per-device queue context after DRIVER_OK. Pre-fills the event ring.
/// Statusq starts empty and receives driver-readable buffers on demand.
/// # C: O(q0.size + q1.size)
pub fn install_eventq(
    device_key: virtio::VirtioChildDeviceKey,
    evdev_id: u32,
    resources: virtio::VirtioResources,
) -> Result<(), ()> {
    let slot_idx = evdev_id as usize;
    let Some((eventq, statusq)) = required_queues(&resources) else { return Err(()); };
    if slot_idx >= crate::MAX_INPUT_DEVICES
        || eventq.size > MAX_EVENT_BUFFERS
        || statusq.size as usize > status::MAX_STATUS_DESCRIPTORS
        || !eventq.size.is_power_of_two()
        || !statusq.size.is_power_of_two()
    {
        return Err(());
    }
    let hhdm = resources.hhdm;
    let Some(buf_pa) = pmm::setup::alloc_raw_frame() else { return Err(()) };
    let Some(status_buf_pa) = pmm::setup::alloc_raw_frame() else {
        // SAFETY: buf_pa was allocated above and has not been published.
        unsafe { pmm::setup::free_one_frame(buf_pa); }
        return Err(());
    };
    zero_frame(hhdm, buf_pa);
    zero_frame(hhdm, status_buf_pa);
    let mut installed = false;
    {
        let mut g = CTXS.lock();
        if g[slot_idx].is_none()
            && !g.iter().flatten().any(|ctx| ctx.device_key == device_key)
        {
            let event_buffers = initialize_eventq(hhdm, eventq, buf_pa);
            if let Some(status_state) =
                status::initialize(hhdm, statusq, status_buf_pa)
            {
                g[slot_idx] = Some(QueueCtx {
                    device_key,
                    cfg_va: resources.cfg_va,
                    hhdm,
                    eventq,
                    buf_pa,
                    event_buffers,
                    statusq,
                    status_buf_pa,
                    status: status_state,
                    pending_output: VecDeque::new(),
                    last_used: 0,
                    avail_idx: event_buffers,
                    eventq_failed: false,
                });
                installed = true;
            }
        }
    }
    if !installed {
        // SAFETY: neither frame was retained in CTXS.
        unsafe {
            pmm::setup::free_one_frame(status_buf_pa);
            pmm::setup::free_one_frame(buf_pa);
        }
        return Err(());
    }
    if !HANDLER_INSTALLED.swap(true, Ordering::AcqRel) {
        softirq::set_handler(softirq::Slot::InputDrain, drain_softirq);
    }
    // SAFETY: per-queue notification register VA; aligned u16 queue index store.
    unsafe { core::ptr::write_volatile(eventq.notify_va as *mut u16, eventq.index); }
    Ok(())
}

pub(super) fn take_eventq(device_key: virtio::VirtioChildDeviceKey) -> Option<(QueueCtx, bool)> {
    let mut g = CTXS.lock();
    let slot = g.iter_mut()
        .find(|slot| slot.as_ref().is_some_and(|ctx| ctx.device_key == device_key))?;
    let ctx = slot.take()?;
    let last_queue = g.iter().all(|slot| slot.is_none());
    Some((ctx, last_queue))
}

pub(super) fn owned_frames(ctx: &QueueCtx) -> [u64; 2] {
    [ctx.buf_pa, ctx.status_buf_pa]
}

fn free_owned_frames(ctx: &QueueCtx) {
    for pa in owned_frames(ctx) {
        // SAFETY: reset confirmed DMA quiescence and CTXS no longer owns pa.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}

/// Quiesce an installed queue context, reset the device, and release owned
/// buffer frames. If reset cannot confirm DMA quiescence, returns false and
/// deliberately leaks both frames rather than freeing device-reachable memory.
/// # C: O(1)
pub fn shutdown_eventq(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some((ctx, last_queue)) = take_eventq(device_key) else { return false; };
    let reset = virtio::reset_device(ctx.cfg_va);
    release_handler_if_last(last_queue);
    if !reset {
        return false;
    }
    free_owned_frames(&ctx);
    true
}

pub(super) fn release_handler_if_last(last_queue: bool) {
    if last_queue && HANDLER_INSTALLED.swap(false, Ordering::AcqRel) {
        let _ = softirq::clear_handler(softirq::Slot::InputDrain);
    }
}

/// Remove an installed queue context, reset the device, and release owned
/// buffer frames. Returns false when absent or reset cannot confirm quiescence.
/// # C: O(1)
pub fn uninstall_eventq(device_key: virtio::VirtioChildDeviceKey) -> bool {
    shutdown_eventq(device_key)
}

/// Raise the InputDrain softirq.
/// # C: O(1)
pub fn raise_drain() { softirq::raise(softirq::Slot::InputDrain); }

/// Poll all installed event queues from process context.
/// # C: O(n_pending × n_devices)
pub fn poll_all() { drain_softirq(); }

/// Softirq handler — walks every installed virtio-input queue.
/// # Ctx: process / softirq, IRQs enabled.
/// # C: O(n_pending × n_devices)
fn drain_softirq() {
    let mut g = CTXS.lock();
    for (id, slot) in g.iter_mut().enumerate() {
        let ctx = match slot.as_mut() { Some(c) => c, None => continue };
        ring::drain_one(ctx, id as u32);
        let _ = status::flush_pending(ctx);
    }
}
