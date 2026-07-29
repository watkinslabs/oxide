use alloc::vec::Vec;
use sync::{Spinlock, TaskList as VirtioTransportLockClass};

use super::{TransportMappings, VIRTIO_PCI_PAGE_BASE_MASK};

mod arch;
mod log;

const MSI_MESSAGE_ADDRESS_LOW_MASK: u64 = 0xFFFF_FFFF;
const MSI_MESSAGE_ADDRESS_HIGH_SHIFT: u32 = 32;
const MSIX_VECTOR_CONTROL_UNMASKED: u32 = 0;
const PCI_BDF_BUS_SHIFT: u32 = 8;
const PCI_BDF_DEVICE_SHIFT: u32 = 3;

#[derive(Clone, Copy)]
pub(crate) struct MsixBinding {
    id: u32,
    entry_va: u64,
    cap_off: u8,
    pub(crate) queue_vector: u16,
}

struct TransportRecord {
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    command_orig: u16,
    mappings: TransportMappings,
    vring_frames: Vec<u64>,
    msix: Vec<MsixBinding>,
}

static TRANSPORT_MMIO: Spinlock<Vec<TransportRecord>, VirtioTransportLockClass> =
    Spinlock::new(Vec::new());

pub(crate) fn bind_msix_vector(
    d: &pci::PciDevice,
    caps: &pci::heapless_caps::CapVec,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    queue_vector: u16,
    handler: fn(),
) -> Option<MsixBinding> {
    let c = caps.find(pci::CAP_ID_MSIX)?;
    let m = arch::decode_cap(d.bdf, c.cfg_off)?;
    let entry_off = pci::msix_table_entry_offset(m, queue_vector)?;
    let tbar_pa = bars.get(m.table_bir as usize).and_then(|b| b.mem_base())?;
    let entry_pa = tbar_pa.checked_add(entry_off)?;
    let page_pa = entry_pa & VIRTIO_PCI_PAGE_BASE_MASK;
    let page_off = entry_pa - page_pa;

    let message = arch_irq::alloc_pci_msi(pci_requester_id(d.bdf), queue_vector as u32)?;
    if !arch_irq::register_pci_msi_handler(message.irq, handler) {
        arch_irq::free_pci_msi(message.irq);
        return None;
    }
    let base_va = mappings.map_page(page_pa);
    let entry_va = base_va + page_off;

    arch::set_enabled_masked(d.bdf, c.cfg_off);
    write_msix_entry(entry_va, message.address, message.data);
    log::binding(d.bdf, queue_vector, entry_va, message.address, message.data);
    Some(MsixBinding {
        id: message.irq,
        entry_va,
        cap_off: c.cfg_off,
        queue_vector,
    })
}

fn write_msix_entry(entry_va: u64, msg_addr: u64, msg_data: u32) {
    // SAFETY: entry_va addresses the requested 16-byte MSI-X table entry. The
    // caller validated the entry index against the decoded table size.
    unsafe {
        core::ptr::write_volatile(
            (entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32,
            pci::MSIX_VECTOR_CONTROL_MASKED,
        );
        let _ = core::ptr::read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
        core::ptr::write_volatile(
            (entry_va + pci::MSIX_MESSAGE_ADDR_LOW_OFF) as *mut u32,
            (msg_addr & MSI_MESSAGE_ADDRESS_LOW_MASK) as u32,
        );
        core::ptr::write_volatile(
            (entry_va + pci::MSIX_MESSAGE_ADDR_HIGH_OFF) as *mut u32,
            (msg_addr >> MSI_MESSAGE_ADDRESS_HIGH_SHIFT) as u32,
        );
        core::ptr::write_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *mut u32, msg_data);
        let _ = core::ptr::read_volatile((entry_va + pci::MSIX_MESSAGE_DATA_OFF) as *const u32);
        core::ptr::write_volatile(
            (entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32,
            MSIX_VECTOR_CONTROL_UNMASKED,
        );
        let _ = core::ptr::read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32);
    }
    arch::mmio_flush();
}

fn mask_msix_binding(binding: MsixBinding) {
    // SAFETY: entry_va was recorded from the MSI-X table mapping while the
    // transport was bound and is still mapped until the caller releases the
    // transport MMIO mappings.
    unsafe {
        core::ptr::write_volatile(
            (binding.entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *mut u32,
            pci::MSIX_VECTOR_CONTROL_MASKED,
        );
        let _ = core::ptr::read_volatile(
            (binding.entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32,
        );
    }
    arch::mmio_flush();
}

fn disable_bound_msix_caps(bdf: pci::Bdf, bindings: &[MsixBinding]) {
    let mut cap_offs = Vec::new();
    for binding in bindings {
        if !cap_offs.iter().any(|cap_off| *cap_off == binding.cap_off) {
            cap_offs.push(binding.cap_off);
        }
    }
    for cap_off in cap_offs {
        arch::set_enabled(bdf, cap_off, false);
    }
}

pub(crate) fn unmask_msix_bindings(bdf: pci::Bdf, bindings: &[MsixBinding]) {
    let mut cap_offs = Vec::new();
    for binding in bindings {
        if !cap_offs.iter().any(|cap_off| *cap_off == binding.cap_off) {
            cap_offs.push(binding.cap_off);
        }
    }
    for cap_off in cap_offs {
        arch::clear_function_mask(bdf, cap_off);
    }
}

pub(crate) fn release_msix_bindings(bdf: pci::Bdf, bindings: &mut Vec<MsixBinding>) {
    let bindings = core::mem::take(bindings);
    pci::emit_msix_teardown_steps(bindings.len(), |step| match step {
        pci::MsixTeardownStep::MaskEntry(idx) => mask_msix_binding(bindings[idx]),
        pci::MsixTeardownStep::DisableFunction => disable_bound_msix_caps(bdf, &bindings),
        pci::MsixTeardownStep::DisableMemBusMaster => {}
    });
    for binding in bindings {
        arch_irq::free_pci_msi(binding.id);
    }
}

pub(crate) fn publish_transport_record(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    command_orig: u16,
    mappings: TransportMappings,
    vring_frames: Vec<u64>,
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

pub(crate) fn unpublish_transport_record_by_bdf(bdf: u32) {
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
    let bdf = bdf_from_word(bdf);
    let mut msix = msix;
    release_msix_bindings(bdf, &mut msix);
    restore_pci_command(bdf, command_orig);
    mappings.unmap_all();
    for frame in vring_frames.iter().copied() {
        debug_assert!(frame != 0);
        // SAFETY: these frames were allocated and programmed by the virtio-pci
        // transport for the child device. Child remove resets/quiesces the
        // device before unpublishing this transport record.
        unsafe {
            pmm::setup::free_one_frame(frame);
        }
    }
}

/// `true` once the device confirmed status readback 0 (quiesced). The caller
/// must not free this probe's DMA frames on `false` — see
/// `virtio::reset_device`'s contract.
pub(crate) fn reset_failed_probe(cfg_va: u64) -> bool {
    virtio::reset_device(cfg_va)
}

pub(crate) fn release_failed_probe_frames(frames: &[u64]) {
    for frame in frames.iter().copied() {
        debug_assert!(frame != 0);
        // SAFETY: frames passed here were allocated by the failed virtio probe
        // and have not been retained by runtime driver state.
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

fn bdf_from_word(word: u32) -> pci::Bdf {
    pci::Bdf {
        bus: ((word >> 16) & 0xFF) as u8,
        device: ((word >> 8) & 0xFF) as u8,
        function: (word & 0xFF) as u8,
    }
}

fn pci_requester_id(bdf: pci::Bdf) -> u32 {
    ((bdf.bus as u32) << PCI_BDF_BUS_SHIFT)
        | ((bdf.device as u32) << PCI_BDF_DEVICE_SHIFT)
        | bdf.function as u32
}
