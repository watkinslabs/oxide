//! Deferred GPU probe ownership and IRQ-to-wait handoff.

use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use sched::live::WaitList;

/// One published GPU whose probe waits in process context.
struct DeferredInit {
    key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    parent: Arc<drv::Device>,
    features: u64,
    resources: virtio::VirtioResources,
    ctrl_wait: WaitList,
    done_wait: WaitList,
    cancelled: AtomicBool,
    running: AtomicBool,
    completion_queued: AtomicBool,
}

static INIT: Spinlock<Vec<Arc<DeferredInit>>, DriverLockClass> = Spinlock::new(Vec::new());

/// `INIT` is shared by hard queue interrupts and process-context teardown.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type InitIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type InitIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type InitIrq = sync::NoopIrq;

fn find(key: virtio::VirtioChildDeviceKey) -> Option<Arc<DeferredInit>> {
    INIT.lock_irqsave::<InitIrq>().iter().find(|init| init.key == key).cloned()
}

fn forget(key: virtio::VirtioChildDeviceKey, init: &Arc<DeferredInit>) {
    INIT.lock_irqsave::<InitIrq>().retain(|candidate|
        candidate.key != key || !Arc::ptr_eq(candidate, init));
}

/// Retain a published child’s process-context GPU initialization inputs.
/// # C: O(N_devices)
pub fn prepare_deferred_init(
    key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    parent: &Arc<drv::Device>,
    features: u64,
    resources: virtio::VirtioResources,
) -> bool {
    let init = Arc::new(DeferredInit {
        key, bdf, parent: parent.clone(), features, resources,
        ctrl_wait: WaitList::new(), done_wait: WaitList::new(),
        cancelled: AtomicBool::new(false), running: AtomicBool::new(false),
        completion_queued: AtomicBool::new(false),
    });
    let mut inits = INIT.lock_irqsave::<InitIrq>();
    if inits.iter().any(|candidate| candidate.key == key) { return false; }
    inits.push(init);
    true
}

/// Queue deferred initialization only after the transport state is published.
/// # C: O(1)
pub fn start_deferred_init(key: virtio::VirtioChildDeviceKey) {
    let Some(init) = find(key) else { return };
    if init.cancelled.load(Ordering::Acquire) { return; }
    if sched::live::workqueue::queue_work(init_work, key.raw() as usize) {
        #[cfg(feature = "debug-boot")]
        { klog::write_raw(b"[VGPU] init queued\n"); }
        return;
    }
    init.cancelled.store(true, Ordering::Release);
    forget(key, &init);
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[VGPU] init workqueue full\n");
}

/// Queue a boot completion wake from the hard CTRLQ callback. The IRQ only
/// records process work; the work item wakes the sleeping probe owner.
/// # C: O(N_devices)
pub(super) fn queue_ctrl_completion(key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(init) = find(key) else { return false };
    if init.completion_queued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return true;
    }
    if sched::live::workqueue::queue_work(completion_work, key.raw() as usize) { return true; }
    init.completion_queued.store(false, Ordering::Release);
    // The bounded workqueue refusal cannot strand a device completion. This
    // generic wake is allocation-free and leaves ring retirement to init_work.
    init.ctrl_wait.wake_all();
    true
}

fn completion_work(raw_key: usize) {
    let key = virtio::VirtioChildDeviceKey::from_raw(raw_key as u32);
    let Some(init) = find(key) else { return };
    init.completion_queued.store(false, Ordering::Release);
    init.ctrl_wait.wake_all();
}

/// Cancel an unstarted or sleeping initialization before transport teardown.
/// # C: O(N_devices + N_waiters)
pub fn cancel_deferred_init(key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(init) = find(key) else { return false };
    init.cancelled.store(true, Ordering::Release);
    init.ctrl_wait.wake_all();
    // SAFETY: child removal is process context and holds no lock needed by the
    // worker; cancellation publishes the predicate before waking this list.
    unsafe {
        let _ = sched::live::wait_event_uninterruptible(&init.done_wait,
            || !init.running.load(Ordering::Acquire));
    }
    forget(key, &init);
    true
}

fn init_work(raw_key: usize) {
    let key = virtio::VirtioChildDeviceKey::from_raw(raw_key as u32);
    let Some(init) = find(key) else { return };
    if init.cancelled.load(Ordering::Acquire) { forget(key, &init); return; }
    if init.running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    #[cfg(feature = "debug-boot")]
    klog::write_raw(b"[VGPU] init start\n");
    let waits = super::probe::CompletionWaits {
        wake: &init.ctrl_wait, cancelled: &init.cancelled,
    };
    let ok = if init.cancelled.load(Ordering::Acquire) { false } else {
        super::probe::get_display_info(
            key, init.bdf, &init.parent, init.features, init.resources, &waits,
        )
    };
    #[cfg(not(feature = "debug-boot"))]
    let _ = ok;
    #[cfg(feature = "debug-boot")]
    { klog::write_raw(if ok { b"[VGPU] init done\n" } else { b"[VGPU] init failed\n" }); }
    init.running.store(false, Ordering::Release);
    init.done_wait.wake_all();
    forget(key, &init);
}
