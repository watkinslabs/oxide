use alloc::vec::Vec;
use sync::{Spinlock, TaskList as VirtioTransportLockClass};

use super::{TransportMappings, VIRTIO_PCI_PAGE_BASE_MASK, VIRTIO_PCI_PAGE_SIZE};

pub(crate) struct MsixBinding {
    pub(crate) queue_vector: u16,
    group: Option<pci_irq::MsixGroup>,
    shared_slot: Option<usize>,
}

const SHARED_MSIX_SLOTS: usize = 32;
const SHARED_MSIX_HANDLERS: usize = virtio::MAX_RESOURCE_QUEUES + 1;

const LEGACY_SLOTS: usize = 32;

#[derive(Copy, Clone)]
struct LegacySlot {
    used: bool,
    isr_va: u64,
    config: Option<virtio::VirtioQueueIrq>,
    queues: [Option<virtio::VirtioQueueIrq>; virtio::MAX_RESOURCE_QUEUES],
}

impl LegacySlot {
    const fn empty() -> Self {
        Self { used: false, isr_va: 0, config: None, queues: [None; virtio::MAX_RESOURCE_QUEUES] }
    }
}

static LEGACY_DISPATCH: Spinlock<[LegacySlot; LEGACY_SLOTS], VirtioTransportLockClass> =
    Spinlock::new([const { LegacySlot::empty() }; LEGACY_SLOTS]);

#[derive(Copy, Clone)]
pub(crate) struct LegacyBinding {
    binding: pci_irq::Binding,
    slot: usize,
}

impl LegacyBinding {
    pub(crate) fn release(self) {
        if let Some(entry) = LEGACY_DISPATCH.lock().get_mut(self.slot) {
            *entry = LegacySlot::empty();
        }
        self.binding.release();
    }
}

const fn legacy_interrupt_sources(isr: u8) -> (bool, bool) {
    (
        isr & virtio::VIRTIO_PCI_ISR_QUEUE != 0,
        isr & virtio::VIRTIO_PCI_ISR_CONFIG != 0,
    )
}

fn dispatch_legacy(slot: usize) {
    let (isr, config_handler, queues) = {
        let mut slots = LEGACY_DISPATCH.lock();
        let Some(entry) = slots.get_mut(slot).filter(|entry| entry.used) else { return; };
        // SAFETY: the transport retains this mapping until the binding is
        // released; virtio's ISR is a read-to-clear byte.
        let isr = unsafe { core::ptr::read_volatile(entry.isr_va as *const u8) };
        (isr, entry.config, entry.queues)
    };
    if isr == 0 { return; }
    let (queue, config) = legacy_interrupt_sources(isr);
    if config {
        if let Some(handler) = config_handler { handler.call(); }
    }
    if queue {
        for handler in queues.into_iter().flatten() { handler.call(); }
    }
}

macro_rules! legacy_dispatchers {
    ($($name:ident:$slot:literal),+ $(,)?) => {
        $(fn $name() { dispatch_legacy($slot); })+
        const LEGACY_DISPATCHERS: [fn(); LEGACY_SLOTS] = [$($name),+];
    };
}

legacy_dispatchers!(
    legacy_0:0, legacy_1:1, legacy_2:2, legacy_3:3, legacy_4:4, legacy_5:5, legacy_6:6, legacy_7:7,
    legacy_8:8, legacy_9:9, legacy_10:10, legacy_11:11, legacy_12:12, legacy_13:13, legacy_14:14, legacy_15:15,
    legacy_16:16, legacy_17:17, legacy_18:18, legacy_19:19, legacy_20:20, legacy_21:21, legacy_22:22, legacy_23:23,
    legacy_24:24, legacy_25:25, legacy_26:26, legacy_27:27, legacy_28:28, legacy_29:29, legacy_30:30, legacy_31:31,
);

pub(crate) fn bind_legacy_intx(
    bdf: pci::Bdf,
    isr_va: u64,
    profile: &virtio::VirtioTransportProfile,
) -> Option<LegacyBinding> {
    if isr_va == 0 { return None; }
    let mut queues = [None; virtio::MAX_RESOURCE_QUEUES];
    for (index, plan) in profile.queue_plans.iter().enumerate() {
        queues[index] = plan.and_then(|plan| plan.msix_handler);
    }
    let mut slots = LEGACY_DISPATCH.lock();
    let slot = slots.iter().position(|entry| !entry.used)?;
    slots[slot] = LegacySlot { used: true, isr_va, config: profile.config_handler, queues };
    drop(slots);
    let Some(binding) = pci_irq::request_intx_resolved(
        bdf, arch_irq::DeviceAction::VirtioPci, LEGACY_DISPATCHERS[slot],
    ) else {
        LEGACY_DISPATCH.lock()[slot] = LegacySlot::empty();
        return None;
    };
    Some(LegacyBinding { binding, slot })
}

#[cfg(test)]
mod tests {
    use super::legacy_interrupt_sources;

    #[test]
    fn legacy_isr_separates_queue_and_configuration_sources() {
        assert_eq!(legacy_interrupt_sources(0), (false, false));
        assert_eq!(legacy_interrupt_sources(1), (true, false));
        assert_eq!(legacy_interrupt_sources(2), (false, true));
        assert_eq!(legacy_interrupt_sources(3), (true, true));
    }
}

#[derive(Clone, Copy)]
struct SharedMsixSlot {
    used: bool,
    handlers: [Option<virtio::VirtioQueueIrq>; SHARED_MSIX_HANDLERS],
}

impl SharedMsixSlot {
    const fn empty() -> Self { Self { used: false, handlers: [None; SHARED_MSIX_HANDLERS] } }
}

static SHARED_DISPATCH: Spinlock<[SharedMsixSlot; SHARED_MSIX_SLOTS], VirtioTransportLockClass> =
    Spinlock::new([const { SharedMsixSlot::empty() }; SHARED_MSIX_SLOTS]);

/// `SHARED_DISPATCH` is read from the hard MSI-X path.  Process-context
/// installation and removal must therefore disable local IRQ delivery while
/// acquiring it; the hard handler itself arrives with IRQs already masked.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type SharedDispatchIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type SharedDispatchIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type SharedDispatchIrq = sync::NoopIrq;

fn dispatch_shared(slot: usize) {
    let handlers = SHARED_DISPATCH.lock()[slot].handlers;
    for handler in handlers.into_iter().flatten() { handler.call(); }
}

macro_rules! shared_dispatchers {
    ($($name:ident:$slot:literal),+ $(,)?) => {
        $(fn $name() { dispatch_shared($slot); })+
        const SHARED_DISPATCHERS: [fn(); SHARED_MSIX_SLOTS] = [$($name),+];
    };
}

shared_dispatchers!(
    shared_0:0, shared_1:1, shared_2:2, shared_3:3, shared_4:4, shared_5:5, shared_6:6, shared_7:7,
    shared_8:8, shared_9:9, shared_10:10, shared_11:11, shared_12:12, shared_13:13, shared_14:14, shared_15:15,
    shared_16:16, shared_17:17, shared_18:18, shared_19:19, shared_20:20, shared_21:21, shared_22:22, shared_23:23,
    shared_24:24, shared_25:25, shared_26:26, shared_27:27, shared_28:28, shared_29:29, shared_30:30, shared_31:31,
);

fn reserve_shared_dispatch(handlers: &[Option<virtio::VirtioQueueIrq>]) -> Option<usize> {
    if handlers.len() > SHARED_MSIX_HANDLERS || !handlers.iter().any(Option::is_some) { return None; }
    let mut slots = SHARED_DISPATCH.lock_irqsave::<SharedDispatchIrq>();
    let slot = slots.iter().position(|slot| !slot.used)?;
    slots[slot].used = true;
    slots[slot].handlers[..handlers.len()].copy_from_slice(handlers);
    Some(slot)
}

fn release_shared_dispatch(slot: usize) {
    let mut slots = SHARED_DISPATCH.lock_irqsave::<SharedDispatchIrq>();
    if let Some(entry) = slots.get_mut(slot) { *entry = SharedMsixSlot::empty(); }
}

#[path = "msix_records.rs"]
mod records;
pub(crate) use records::{
    bind_msix_vector, bind_shared_msix_vector, disable_pci_command,
    publish_transport_record, release_failed_probe_frames, release_msix_bindings,
    reset_failed_probe, restore_pci_command, restore_transport_record,
    unmask_msix_bindings, unpublish_transport_record, unpublish_transport_record_by_bdf,
};
