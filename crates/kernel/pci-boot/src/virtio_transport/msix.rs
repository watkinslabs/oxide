use alloc::vec::Vec;
use sync::{Spinlock, TaskList as VirtioTransportLockClass};

use super::{TransportMappings, VIRTIO_PCI_PAGE_BASE_MASK, VIRTIO_PCI_PAGE_SIZE};

pub(crate) struct MsixBinding {
    pub(crate) queue_vector: u16,
    group: Option<pci_irq::MsixGroup>,
}

struct TransportRecord {
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    command_orig: u16,
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
    handler: fn(),
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
    if group.bind(pci_irq::MsixEntry { bar, vector: queue_vector, entry_va },
        arch_irq::DeviceAction::VirtioPci, handler).is_none() {
        if new_group { group.release(); } else { bindings.first_mut()?.group = Some(group); }
        return None;
    }
    if new_group { bindings.push(MsixBinding { queue_vector, group: Some(group) }); }
    else {
        bindings.first_mut()?.group = Some(group);
        bindings.push(MsixBinding { queue_vector, group: None });
    }
    Some(queue_vector)
}

pub(crate) fn unmask_msix_bindings(bindings: &[MsixBinding]) {
    if let Some(group) = bindings.first().and_then(|binding| binding.group.as_ref()) { group.unmask(); }
}

pub(crate) fn release_msix_bindings(bindings: &mut Vec<MsixBinding>) {
    let mut bindings = core::mem::take(bindings);
    if let Some(group) = bindings.first_mut().and_then(|binding| binding.group.take()) { group.release(); }
}

pub(crate) fn publish_transport_record(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    command_orig: u16,
    mappings: TransportMappings,
    vring_frames: Vec<virtio::VirtioDmaFrame>,
    msix: Vec<MsixBinding>,
) {
    let rec = TransportRecord {
        device_key,
        bdf,
        command_orig,
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
    virtio::reset_device(cfg_va)
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
        debug_assert!(frame != 0);
        // SAFETY: payload frames are not mapped by this transport path and
        // have not been retained by a child runtime after failed probe.
        unsafe {
            pmm::setup::free_one_frame(frame);
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
