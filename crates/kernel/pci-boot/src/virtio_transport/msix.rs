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

struct TransportRecord {
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    command_orig: u16,
    cfg_va: u64,
    hhdm: u64,
    drv_features: u64,
    config_msix: u16,
    queue_resources: [virtio::VirtQueueResource; virtio::MAX_RESOURCE_QUEUES],
    queue_msix: [u16; virtio::MAX_RESOURCE_QUEUES],
    mappings: TransportMappings,
    vring_frames: Vec<virtio::VirtioDmaFrame>,
    msix: Vec<MsixBinding>,
}

static TRANSPORT_MMIO: Spinlock<Vec<TransportRecord>, VirtioTransportLockClass> =
    Spinlock::new(Vec::new());

/// Whether the model still admits MSI/MSI-X for this function. Userspace
/// clears it through the function's `msi_bus` attribute, which only binds
/// drivers that have not yet requested a vector. # C: O(N_devices)
fn msi_admitted(bdf: pci::Bdf) -> bool {
    let addr = alloc::format!("{:04x}:{:02x}:{:02x}.{}",
        bdf.segment, bdf.bus, bdf.device, bdf.function);
    drv::devices().into_iter()
        .find(|dev| dev.bus == "pci" && dev.addr == addr)
        .is_none_or(|dev| dev.msi_allowed())
}

pub(crate) fn bind_msix_vector(
    d: &pci::PciDevice,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    bindings: &mut Vec<MsixBinding>,
    queue_vector: u16,
    handler: virtio::VirtioQueueIrq,
) -> Option<u16> {
    bind_msix_vector_with_slot(d, bars, mappings, bindings, queue_vector, handler, None)
}

pub(crate) fn bind_shared_msix_vector(
    d: &pci::PciDevice,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    bindings: &mut Vec<MsixBinding>,
    queue_vector: u16,
    handlers: &[Option<virtio::VirtioQueueIrq>],
) -> Option<u16> {
    let slot = reserve_shared_dispatch(handlers)?;
    let bound = bind_msix_vector_with_slot(
        d, bars, mappings, bindings, queue_vector,
        virtio::VirtioQueueIrq::Bare(SHARED_DISPATCHERS[slot]), Some(slot),
    );
    if bound.is_none() { release_shared_dispatch(slot); }
    bound
}

fn bind_msix_vector_with_slot(
    d: &pci::PciDevice,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    bindings: &mut Vec<MsixBinding>,
    queue_vector: u16,
    handler: virtio::VirtioQueueIrq,
    shared_slot: Option<usize>,
) -> Option<u16> {
    if !msi_admitted(d.bdf) { return None; }
    let new_group = bindings.is_empty();
    let mut group = if new_group { pci_irq::begin_msix(d.bdf)? } else {
        bindings.first_mut()?.group.take()?
    };
    let (bar, entry_off) = match group.entry_offset(queue_vector) {
        Some(entry) => entry,
        None => { if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); } return None; }
    };
    let tbar_pa = match bars.get(bar as usize).and_then(|bar| bar.mem_base()) {
        Some(pa) => pa,
        None => { if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); } return None; }
    };
    let entry_pa = match tbar_pa.checked_add(entry_off) {
        Some(pa) => pa,
        None => { if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); } return None; }
    };
    let page_pa = entry_pa & VIRTIO_PCI_PAGE_BASE_MASK;
    let page_off = entry_pa - page_pa;
    let base_va = mappings.map_page(page_pa);
    let entry_va = match base_va.checked_add(page_off) {
        Some(va) => va,
        None => { if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); } return None; }
    };
    let bound = match handler {
        virtio::VirtioQueueIrq::Bare(handler) => group.bind(
            pci_irq::MsixEntry { bar, vector: queue_vector, entry_va },
            arch_irq::DeviceAction::VirtioPci, handler,
        ),
        virtio::VirtioQueueIrq::Context { handler, arg } => group.bind_context(
            pci_irq::MsixEntry { bar, vector: queue_vector, entry_va },
            arch_irq::DeviceAction::VirtioPci, handler, arg,
        ),
    };
    if bound.is_none() {
        if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); }
        return None;
    }
    if new_group { bindings.push(MsixBinding { queue_vector, group: Some(group), shared_slot }); }
    else {
        bindings.first_mut()?.group = Some(group);
        bindings.push(MsixBinding { queue_vector, group: None, shared_slot });
    }
    Some(queue_vector)
}

pub(crate) fn unmask_msix_bindings(bindings: &[MsixBinding]) {
    if let Some(group) = bindings.first().and_then(|binding| binding.group.as_ref()) { group.unmask(); }
}

pub(crate) fn release_msix_bindings(bindings: &mut Vec<MsixBinding>) {
    let mut bindings = core::mem::take(bindings);
    for binding in bindings.iter().filter_map(|binding| binding.shared_slot) {
        release_shared_dispatch(binding);
    }
    if let Some(group) = bindings.first_mut().and_then(|binding| binding.group.take()) { group.release(); }
}

pub(crate) fn publish_transport_record(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    command_orig: u16,
    cfg_va: u64,
    hhdm: u64,
    drv_features: u64,
    queue_resources: [virtio::VirtQueueResource; virtio::MAX_RESOURCE_QUEUES],
    mappings: TransportMappings,
    vring_frames: Vec<virtio::VirtioDmaFrame>,
    msix: Vec<MsixBinding>,
) {
    // SAFETY: cfg_va is the retained Device-attr common-cfg mapping from the
    // successful probe and the config-vector field is an aligned u16.
    let config_msix = unsafe {
        core::ptr::read_volatile(
            (cfg_va + virtio::common_cfg::CFG_MSIX_CONFIG_NUMQ) as *const u16,
        )
    };
    let queue_msix = core::array::from_fn(|index| {
        let queue = queue_resources[index];
        if queue.is_runtime_valid() {
            virtio::read_queue_msix_vector(cfg_va, queue.index)
        } else {
            virtio::VIRTIO_MSI_NO_VECTOR
        }
    });
    let rec = TransportRecord {
        device_key,
        bdf,
        command_orig,
        cfg_va,
        hhdm,
        drv_features,
        config_msix,
        queue_resources,
        queue_msix,
        mappings,
        vring_frames,
        msix,
    };
    let mut records = TRANSPORT_MMIO.lock();
    if let Some(idx) = records.iter().position(|old| old.device_key == device_key) {
        let old = records.remove(idx);
        release_transport_record(old);
    }
    records.push(rec);
}

#[derive(Clone, Copy)]
struct RestoreQueue {
    resource: virtio::VirtQueueResource,
    desc_dma: u64,
    driver_dma: u64,
    device_dma: u64,
    msix: u16,
}

#[derive(Clone, Copy)]
struct RestoreFacts {
    cfg_va: u64,
    hhdm: u64,
    drv_features: u64,
    config_msix: u16,
    queues: [Option<RestoreQueue>; virtio::MAX_RESOURCE_QUEUES],
}

fn restore_facts(rec: &TransportRecord) -> Option<RestoreFacts> {
    let mut queues = [None; virtio::MAX_RESOURCE_QUEUES];
    for (index, resource) in rec.queue_resources.iter().copied().enumerate() {
        if !resource.is_runtime_valid() { continue; }
        let dma = |pa| rec.vring_frames.iter().find(|frame| frame.pa == pa).map(|frame| frame.dma);
        queues[index] = Some(RestoreQueue {
            resource,
            desc_dma: dma(resource.desc_pa)?,
            driver_dma: dma(resource.driver_pa)?,
            device_dma: dma(resource.device_pa)?,
            msix: rec.queue_msix[index],
        });
    }
    Some(RestoreFacts {
        cfg_va: rec.cfg_va,
        hhdm: rec.hhdm,
        drv_features: rec.drv_features,
        config_msix: rec.config_msix,
        queues,
    })
}

fn wait_restore_poll() {
    #[cfg(target_os = "oxide-kernel")]
    {
        let deadline = sched::deadline::clock::now_ns().saturating_add(1_000_000);
        // SAFETY: device restore runs from the normal DPM process-context walk.
        unsafe { sched::live::sleep_uninterruptible_until(deadline, sched::deadline::clock::now_ns); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    sync::spin_relax::relax();
}

fn zero_restore_page(hhdm: u64, pa: u64) {
    let va = hhdm.wrapping_add(pa) as *mut u64;
    // SAFETY: pa is a retained transport-owned ring frame reachable through
    // the established HHDM; reset completion proves the device cannot access
    // it while the exact page is cleared and republished.
    unsafe {
        for index in 0..(VIRTIO_PCI_PAGE_SIZE as usize / core::mem::size_of::<u64>()) {
            core::ptr::write_volatile(va.add(index), 0);
        }
    }
    virtio::dma::clean_to_device(hhdm.wrapping_add(pa), VIRTIO_PCI_PAGE_SIZE as usize);
}

/// Reset and rebuild one retained virtio transport from its sole runtime
/// resource record. Queue frames and DMA mappings remain owned by that record;
/// no replacement transport or second child publication is created.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(retained queues + reset latency)
pub(crate) fn restore_transport_record(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let facts = {
        let records = TRANSPORT_MMIO.lock();
        records.iter().find(|rec| rec.device_key == device_key).and_then(restore_facts)
    };
    let Some(facts) = facts else { return false };
    if facts.hhdm == 0 { return false; }
    let negotiated = virtio::negotiate_features_with_wait(
        facts.cfg_va, facts.drv_features, wait_restore_poll,
    );
    if !negotiated.features_ok || negotiated.drv_features != facts.drv_features
        || virtio::set_config_msix_vector(facts.cfg_va, facts.config_msix) != facts.config_msix
    {
        virtio::set_failed(facts.cfg_va);
        return false;
    }
    for queue in facts.queues.into_iter().flatten() {
        zero_restore_page(facts.hhdm, queue.resource.desc_pa);
        zero_restore_page(facts.hhdm, queue.resource.driver_pa);
        zero_restore_page(facts.hhdm, queue.resource.device_pa);
        if !virtio::restore_queue(
            facts.cfg_va, queue.resource, queue.desc_dma, queue.driver_dma,
            queue.device_dma, queue.msix,
        ) {
            virtio::set_failed(facts.cfg_va);
            return false;
        }
    }
    virtio::set_driver_ok(facts.cfg_va) & virtio::VIRTIO_STATUS_DRIVER_OK != 0
}

pub(crate) fn unpublish_transport_record(device_key: virtio::VirtioChildDeviceKey) {
    let rec = {
        let mut records = TRANSPORT_MMIO.lock();
        records
            .iter()
            .position(|rec| rec.device_key == device_key)
            .map(|idx| records.remove(idx))
    };
    if let Some(rec) = rec {
        release_transport_record(rec);
    }
}

pub(crate) fn unpublish_transport_record_by_bdf(bdf: pci::Bdf) {
    let rec = {
        let mut records = TRANSPORT_MMIO.lock();
        records
            .iter()
            .position(|rec| rec.bdf == bdf)
            .map(|idx| records.remove(idx))
    };
    if let Some(rec) = rec {
        release_transport_record(rec);
    }
}

fn release_transport_record(rec: TransportRecord) {
    let TransportRecord {
        bdf,
        command_orig,
        mut mappings,
        vring_frames,
        msix,
        ..
    } = rec;
    let mut msix = msix;
    release_msix_bindings(&mut msix);
    restore_pci_command(bdf, command_orig);
    mappings.unmap_all();
    for frame in vring_frames.iter().copied() {
        if !iommu::unmap_dma(bdf, frame.dma, VIRTIO_PCI_PAGE_SIZE as usize) {
            continue;
        }
        debug_assert!(frame.pa != 0);
        // SAFETY: these frames were allocated and programmed by the virtio-pci
        // transport for the child device. Child remove resets/quiesces the
        // device before unpublishing this transport record.
        unsafe {
            pmm::setup::free_one_frame(frame.pa);
        }
    }
}

/// `true` once the device confirmed status readback 0 (quiesced). The caller
/// must not free this probe's DMA frames on `false` — see
/// `virtio::reset_device`'s contract.
pub(crate) fn reset_failed_probe(cfg_va: u64) -> bool {
    virtio::reset_device_with_wait(cfg_va, super::wait_one_ms)
}

pub(crate) fn release_failed_probe_frames(bdf: pci::Bdf, frames: &virtio::VirtioProbeFrameSet) {
    for frame in frames.vring_frames.iter().copied() {
        if !iommu::unmap_dma(bdf, frame.dma, VIRTIO_PCI_PAGE_SIZE as usize) {
            continue;
        }
        debug_assert!(frame.pa != 0);
        // SAFETY: frames passed here were allocated by the failed virtio probe
        // and have not been retained by runtime driver state.
        unsafe {
            pmm::setup::free_one_frame(frame.pa);
        }
    }
    for frame in frames.payload_frames.iter().copied() {
        if !iommu::unmap_dma(bdf, frame.dma, VIRTIO_PCI_PAGE_SIZE as usize) {
            continue;
        }
        debug_assert!(frame.pa != 0);
        // SAFETY: failed-probe payload mappings have been retired and are not
        // retained by any child runtime.
        unsafe {
            pmm::setup::free_one_frame(frame.pa);
        }
    }
}

pub(crate) fn restore_pci_command(bdf: pci::Bdf, command_orig: u16) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
            let _ = pci::restore_mem_bus_master(&r, bdf, command_orig);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let _ = pci::restore_mem_bus_master(&r, bdf, command_orig);
        }
    }
}


pub(crate) fn disable_pci_command(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
            let _ = pci::disable_mem_bus_master(&r, bdf);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let _ = pci::disable_mem_bus_master(&r, bdf);
        }
    }
}
