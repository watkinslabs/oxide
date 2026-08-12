use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use super::{ring, status};

const EVENT_BYTES: usize = core::mem::size_of::<crate::VirtioInputEvent>();
const DESC_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize
    / core::mem::size_of::<virtio::queue::Desc>();
const EVENT_FRAME_CAPACITY: usize = hal::PAGE_SIZE_BYTES as usize / EVENT_BYTES;
pub(super) const MAX_EVENT_BUFFERS: u16 =
    if DESC_FRAME_CAPACITY < EVENT_FRAME_CAPACITY {
        DESC_FRAME_CAPACITY as u16
    } else { EVENT_FRAME_CAPACITY as u16 };

/// Per-virtio-input-device runtime state. Captured at boot via
/// `install_eventq`; consumed by the softirq drain.
pub(super) struct QueueCtx {
    pub(super) device_key:  virtio::VirtioChildDeviceKey,
    pub(super) bdf:         pci::Bdf,
    pub(super) cfg_va:      u64,
    pub(super) hhdm:        u64,
    pub(super) eventq:      Option<virtio::VirtioSplitQueue>,
    pub(super) buf_pa:      u64,
    pub(super) buf_dma:     u64,
    pub(super) event_buffers: u16,
    pub(super) event_desc_slots: [u16; MAX_EVENT_BUFFERS as usize],
    pub(super) statusq:     Option<virtio::VirtioSplitQueue>,
    pub(super) status_buf_pa: u64,
    pub(super) status_buf_dma: u64,
    pub(super) status:      status::StatusState,
    pub(super) status_desc_slots: [u16; status::MAX_STATUS_DESCRIPTORS],
    pub(super) pending_output: VecDeque<crate::VirtioInputEvent>,
    pub(super) eventq_failed: bool,
}

/// All installed input devices share one drain.
pub(super) static CTXS:
    Spinlock<[Option<QueueCtx>;
 crate::MAX_INPUT_DEVICES], DriverLockClass> =
    Spinlock::new([const { None }; crate::MAX_INPUT_DEVICES]);

/// Bottom-half gate for the completion/drain-softirq-shared lock: real
/// exclusion in the kernel, a no-op under hosted tests. Every acquisition of
/// the lock goes through `lock_bh`, softirq context included — the disable
/// counts and the enable drains only at the outermost level outside IRQ, i.e.
/// the reference `spin_lock_bh` nesting. A bare process-context hold is the
/// one-CPU deadlock B2007/B2008 fixed: the softirq spins on an owner it
/// interrupted.
#[cfg(target_os = "oxide-kernel")]
pub(crate) type InputBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type InputBh = sync::NoopBh;

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

pub(super) fn post_event_buffers(
    eventq: &mut virtio::VirtioSplitQueue,
    buf_dma: u64,
    slots: &mut [u16; MAX_EVENT_BUFFERS as usize],
) -> Result<u16, virtio::SplitQueueError> {
    let supplied = eventq.resource().size.min(MAX_EVENT_BUFFERS);
    for slot in 0..supplied {
        let head = eventq.submit_no_kick(&[virtio::SplitQueueSeg {
            dma: buf_dma.wrapping_add(u64::from(slot) * EVENT_BYTES as u64),
            len: EVENT_BYTES as u32,
            device_writes: true,
        }])?;
        slots[head as usize] = slot;
    }
    eventq.kick();
    Ok(supplied)
}

/// Install per-device queue context after DRIVER_OK. Pre-fills the event ring.
/// Statusq starts empty and receives driver-readable buffers on demand.
/// # C: O(q0.size + q1.size)
pub fn install_eventq(
    device_key: virtio::VirtioChildDeviceKey,
    evdev_id: u32,
    bdf: pci::Bdf,
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
    let Some(buf_dma) = iommu::map_dma(bdf, buf_pa, hal::PAGE_SIZE_BYTES as usize) else {
        unsafe { pmm::setup::free_one_frame(status_buf_pa); pmm::setup::free_one_frame(buf_pa); }
        return Err(());
    };
    let Some(status_buf_dma) = iommu::map_dma(bdf, status_buf_pa, hal::PAGE_SIZE_BYTES as usize) else {
        let _ = iommu::unmap_dma(bdf, buf_dma, hal::PAGE_SIZE_BYTES as usize);
        unsafe { pmm::setup::free_one_frame(status_buf_pa); pmm::setup::free_one_frame(buf_pa); }
        return Err(());
    };
    zero_frame(hhdm, buf_pa);
    zero_frame(hhdm, status_buf_pa);
    let mut installed = false;
    {
        let mut g = CTXS.lock_bh::<crate::drain::queue::InputBh>();
        if g[slot_idx].is_none()
            && !g.iter().flatten().any(|ctx| ctx.device_key == device_key)
        {
            let mut event_queue = virtio::VirtioSplitQueue::new(eventq, hhdm).ok();
            let status_size = statusq.size;
            let status_queue = virtio::VirtioSplitQueue::new(statusq, hhdm).ok();
            let mut event_desc_slots = [u16::MAX; MAX_EVENT_BUFFERS as usize];
            let event_buffers = event_queue.as_mut().and_then(|queue| {
                post_event_buffers(queue, buf_dma, &mut event_desc_slots).ok()
            });
            if let (Some(eventq), Some(statusq), Some(event_buffers), Some(status_state)) =
                (event_queue, status_queue, event_buffers, status::StatusState::new(status_size))
            {
                g[slot_idx] = Some(QueueCtx {
                    device_key,
                    bdf,
                    cfg_va: resources.cfg_va,
                    hhdm,
                    eventq: Some(eventq),
                    buf_pa,
                    buf_dma,
                    event_buffers,
                    event_desc_slots,
                    statusq: Some(statusq),
                    status_buf_pa,
                    status_buf_dma,
                    status: status_state,
                    status_desc_slots: [u16::MAX; status::MAX_STATUS_DESCRIPTORS],
                    pending_output: VecDeque::new(),
                    eventq_failed: false,
                });
                installed = true;
            }
        }
    }
    if !installed {
        let _ = iommu::unmap_dma(bdf, status_buf_dma, hal::PAGE_SIZE_BYTES as usize);
        let _ = iommu::unmap_dma(bdf, buf_dma, hal::PAGE_SIZE_BYTES as usize);
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
    Ok(())
}

pub(super) fn take_eventq(device_key: virtio::VirtioChildDeviceKey) -> Option<(QueueCtx, bool)> {
    let mut g = CTXS.lock_bh::<crate::drain::queue::InputBh>();
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
    if !iommu::unmap_dma(ctx.bdf, ctx.status_buf_dma, hal::PAGE_SIZE_BYTES as usize) {
        return;
    }
    if !iommu::unmap_dma(ctx.bdf, ctx.buf_dma, hal::PAGE_SIZE_BYTES as usize) {
        return;
    }
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
    let mut g = CTXS.lock_bh::<crate::drain::queue::InputBh>();
    for (id, slot) in g.iter_mut().enumerate() {
        let ctx = match slot.as_mut() { Some(c) => c, None => continue };
        ring::drain_one(ctx, id as u32);
        let _ = status::flush_pending(ctx);
    }
}
