use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use super::ring;

/// Per-virtio-input-device runtime state. Captured at boot via
/// `install_eventq`; consumed by the softirq drain.
pub(super) struct QueueCtx {
    pub(super) device_key:  virtio::VirtioChildDeviceKey,
    pub(super) cfg_va:      u64,
    pub(super) hhdm:        u64,
    pub(super) eventq:      virtio::VirtQueueResource,
    pub(super) buf_pa:      u64,
    pub(super) last_used:   u16,
    pub(super) avail_idx:   u16,
    pub(super) is_pointer:  bool,
}

/// Up to 8 input devices share one drain (kbd + mouse + ...).
pub(super) static CTXS: Spinlock<[Option<QueueCtx>; 8], DriverLockClass> =
    Spinlock::new([const { None }; 8]);

pub(super) static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install per-device queue context after DRIVER_OK. Pre-fills the event ring.
/// # C: O(qsize)
pub fn install_eventq(
    device_key: virtio::VirtioChildDeviceKey,
    evdev_id: u32,
    resources: virtio::VirtioResources,
) -> Result<(), ()> {
    let Some(eventq) = resources.require_queue(0) else { return Err(()); };
    let slot_idx = evdev_id as usize;
    if slot_idx >= crate::MAX_INPUT_DEVICES || !resources.common_cfg_valid() {
        return Err(());
    }
    let qsize = eventq.size;
    let hhdm = resources.hhdm;
    let buf_pa = match pmm::setup::alloc_one_frame() { Some(pa) => pa, None => return Err(()) };
    // SAFETY: HHDM-mapped contiguous frame; bounded writes within 4 KiB.
    unsafe {
        let buf_va = hhdm.wrapping_add(buf_pa) as *mut u8;
        for i in 0..hal::PAGE_SIZE_BYTES as usize { core::ptr::write_volatile(buf_va.add(i), 0); }
    }
    let desc_va = hhdm.wrapping_add(eventq.desc_pa) as *mut u8;
    // SAFETY: HHDM-mapped queue desc array; qsize * 16 fits in queue frame.
    unsafe {
        for i in 0..qsize as usize {
            let entry_pa = buf_pa.wrapping_add((i as u64) * 8);
            let off = i * 16;
            core::ptr::write_volatile(desc_va.add(off)      as *mut u64, entry_pa);
            core::ptr::write_volatile(desc_va.add(off + 8)  as *mut u32, 8u32);
            core::ptr::write_volatile(desc_va.add(off + 12) as *mut u16, virtio::queue::VRING_DESC_F_WRITE);
            core::ptr::write_volatile(desc_va.add(off + 14) as *mut u16, 0u16);
        }
    }
    let avail_va = hhdm.wrapping_add(eventq.driver_pa) as *mut u8;
    // SAFETY: bounded writes within driver ring frame.
    unsafe {
        core::ptr::write_volatile(avail_va as *mut u16, 0u16);
        for i in 0..qsize as usize {
            core::ptr::write_volatile(avail_va.add(4 + i * 2) as *mut u16, i as u16);
        }
        core::ptr::write_volatile(avail_va.add(2) as *mut u16, qsize);
    }
    {
        let mut g = CTXS.lock();
        if g[slot_idx].is_some() || g.iter().flatten().any(|ctx| ctx.device_key == device_key) {
            // SAFETY: buf_pa is the frame allocated here and no queue context kept it.
            unsafe { pmm::setup::free_one_frame(buf_pa); }
            return Err(());
        }
        g[slot_idx] = Some(QueueCtx {
            device_key,
            cfg_va: resources.cfg_va,
            hhdm,
            eventq,
            buf_pa,
            last_used: 0,
            avail_idx: qsize,
            is_pointer: crate::is_pointer(evdev_id),
        });
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

/// Quiesce an installed queue context, reset the device, and release owned
/// buffer frames. Returns false if no queue was installed for `device_key`.
/// # C: O(1)
pub fn shutdown_eventq(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some((ctx, last_queue)) = take_eventq(device_key) else { return false; };
    virtio::reset_device(ctx.cfg_va);
    release_handler_if_last(last_queue);
    // SAFETY: this frame was allocated for this driver's event buffer.
    unsafe { pmm::setup::free_one_frame(ctx.buf_pa); }
    true
}

pub(super) fn release_handler_if_last(last_queue: bool) {
    if last_queue && HANDLER_INSTALLED.swap(false, Ordering::AcqRel) {
        let _ = softirq::clear_handler(softirq::Slot::InputDrain);
    }
}

/// Remove an installed queue context, reset the device, and release owned
/// buffer frames. Returns false if no queue was installed for `device_key`.
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
    }
}
