//! Virtio-pci transport MMIO mapping and notify helpers.
//!
//! This module owns BAR-derived transport mappings used by virtio-pci probe
//! and runtime records. It keeps mapping lifetime separate from device-specific
//! child probe logic.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as VirtioTransportLockClass};

struct MappedTransportPage {
    page_pa: u64,
    mapping: mmio_map::Mapping,
}

#[derive(Default)]
pub(super) struct TransportMappings {
    pages: Vec<MappedTransportPage>,
}

impl TransportMappings {
    pub(super) fn map_page(&mut self, page_pa: u64) -> u64 {
        if page_pa == 0 {
            return 0;
        }
        for page in &self.pages {
            if page.page_pa == page_pa {
                return page.mapping.base_va();
            }
        }
        // SAFETY: virtio-pci decoded this page from a BAR capability owned by
        // the bound transport. The owned Mapping is kept until probe failure or
        // child remove quiesces the device.
        let mapping = unsafe { mmio_map::map_owned(page_pa, 1) };
        let base_va = mapping.base_va();
        self.pages.push(MappedTransportPage { page_pa, mapping });
        base_va
    }

    pub(super) fn unmap_all(&mut self) {
        self.pages.clear();
    }

    pub(super) fn map_queue_notify_va(
        &mut self,
        notify_cap: Option<&virtio::VirtioPciCap>,
        bars: &[pci::Bar; 6],
        notify_off: u16,
    ) -> u64 {
        let Some(notify_cap) = notify_cap else {
            return 0;
        };
        let Some(nfy_pa) = virtio::notify_pa(notify_cap, bars, notify_off) else {
            return 0;
        };
        let n_page_pa = nfy_pa & !0xFFF;
        let n_page_off = nfy_pa - n_page_pa;
        self.map_page(n_page_pa) + n_page_off
    }
}

pub(super) fn kick_queue_notify(notify_va: u64, queue_index: u16) -> bool {
    if notify_va == 0 {
        return false;
    }
    // SAFETY: notify_va is a Device-attr virtio notify location decoded from
    // the transport NOTIFY cap. Modern virtio-pci notify stores are u16 queue
    // indexes at the per-queue notify address.
    unsafe {
        core::ptr::write_volatile(notify_va as *mut u16, queue_index);
    }
    true
}

#[derive(Clone, Copy)]
pub(super) struct MsixBinding {
    id: u32,
    entry_va: u64,
    cap_off: u8,
    pub(super) queue_vector: u16,
}

struct TransportRecord {
    bdf: u32,
    _mappings: TransportMappings,
    vring_frames: Vec<u64>,
    msix: Vec<MsixBinding>,
}

static TRANSPORT_MMIO: Spinlock<Vec<TransportRecord>, VirtioTransportLockClass> =
    Spinlock::new(Vec::new());

pub(super) fn bind_msix_vector(
    d: &pci::PciDevice,
    caps: &pci::heapless_caps::CapVec,
    bars: &[pci::Bar; 6],
    mappings: &mut TransportMappings,
    queue_vector: u16,
    handler: fn(),
) -> Option<MsixBinding> {
    let c = caps.find(pci::CAP_ID_MSIX)?;
    let m = decode_msix_cap_arch(d.bdf, c.cfg_off)?;
    if queue_vector >= m.table_size {
        return None;
    }
    let tbar_pa = bars.get(m.table_bir as usize).and_then(|b| b.mem_base())?;
    let entry_pa = tbar_pa
        .wrapping_add(m.table_offset as u64)
        .wrapping_add((queue_vector as u64) * 16);
    let page_pa = entry_pa & !0xFFF;
    let page_off = entry_pa - page_pa;

    let (id, msg_addr, msg_data) = alloc_msi_message()?;
    if !register_msi_handler(id, handler) {
        free_msi_id(id);
        return None;
    }
    let base_va = mappings.map_page(page_pa);
    let entry_va = base_va + page_off;

    // SAFETY: entry_va addresses the requested 16-byte MSI-X table entry. The
    // entry index was validated against the decoded table size, and each field
    // is naturally aligned within the MSI-X entry.
    unsafe {
        core::ptr::write_volatile(entry_va as *mut u32, (msg_addr & 0xFFFF_FFFF) as u32);
        core::ptr::write_volatile((entry_va + 4) as *mut u32, (msg_addr >> 32) as u32);
        core::ptr::write_volatile((entry_va + 8) as *mut u32, msg_data);
        core::ptr::write_volatile((entry_va + 12) as *mut u32, 0);
    }
    set_msix_enabled_arch(d.bdf, c.cfg_off, true);
    Some(MsixBinding {
        id,
        entry_va,
        cap_off: c.cfg_off,
        queue_vector,
    })
}

pub(super) fn release_msix_binding(bdf: pci::Bdf, binding: MsixBinding) {
    // SAFETY: entry_va was recorded from the MSI-X table mapping while the
    // transport was bound and is still mapped until the caller releases the
    // transport MMIO mappings.
    unsafe {
        core::ptr::write_volatile((binding.entry_va + 12) as *mut u32, 1);
    }
    set_msix_enabled_arch(bdf, binding.cap_off, false);
    free_msi_id(binding.id);
}

pub(super) fn release_msix_bindings(bdf: pci::Bdf, bindings: &mut Vec<MsixBinding>) {
    let bindings = core::mem::take(bindings);
    for binding in bindings {
        release_msix_binding(bdf, binding);
    }
}

pub(super) fn publish_transport_record(
    bdf: u32,
    mappings: TransportMappings,
    vring_frames: Vec<u64>,
    msix: Vec<MsixBinding>,
) {
    let rec = TransportRecord {
        bdf,
        _mappings: mappings,
        vring_frames,
        msix,
    };
    let mut records = TRANSPORT_MMIO.lock();
    if let Some(idx) = records.iter().position(|old| old.bdf == bdf) {
        let old = records.remove(idx);
        release_transport_record(old);
    }
    records.push(rec);
}

pub(super) fn unpublish_transport_record(bdf: u32) {
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
    let bdf = bdf_from_word(rec.bdf);
    for binding in rec.msix {
        release_msix_binding(bdf, binding);
    }
    disable_pci_command(bdf);
    for frame in rec.vring_frames.iter().copied() {
        if frame == 0 {
            continue;
        }
        // SAFETY: these frames were allocated and programmed by the virtio-pci
        // transport for the child device. Child remove resets/quiesces the
        // device before unpublishing this transport record.
        unsafe {
            pmm::setup::free_one_frame(frame);
        }
    }
}

pub(super) fn release_failed_probe(cfg_va: u64, frames: &[u64]) {
    virtio::reset_device(cfg_va);
    for frame in frames.iter().copied() {
        if frame == 0 {
            continue;
        }
        // SAFETY: non-zero frames passed here were allocated by the failed
        // virtio probe and have not been retained by runtime driver state.
        unsafe {
            pmm::setup::free_one_frame(frame);
        }
    }
}

pub(super) fn disable_pci_command(bdf: pci::Bdf) {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        let cur = pci::read_command(&r, bdf);
        let restored = cur & !(pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER);
        if restored != cur {
            pci::write_command(&r, bdf, restored);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur = pci::read_command(&r, bdf);
            let restored = cur & !(pci::COMMAND_MEMORY | pci::COMMAND_BUS_MASTER);
            if restored != cur {
                pci::write_command(&r, bdf, restored);
            }
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

fn decode_msix_cap_arch(bdf: pci::Bdf, cfg_off: u8) -> Option<pci::MsixCap> {
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        pci::decode_msix_cap(&r, bdf, cfg_off)
    }
    #[cfg(target_arch = "aarch64")]
    {
        hal_aarch64::pci::EcamPci::from_published()
            .and_then(|r| pci::decode_msix_cap(&r, bdf, cfg_off))
    }
}

fn set_msix_enabled_arch(bdf: pci::Bdf, cfg_off: u8, enabled: bool) {
    let off = cfg_off & 0xFC;
    const MSIX_ENABLE: u32 = 1u32 << 31;
    const MSIX_FUNCTION_MASK: u32 = 1u32 << 30;
    #[cfg(target_arch = "x86_64")]
    {
        let r = hal_x86_64::pci::LegacyPci;
        use pci::ConfigSpaceReader as _;
        let cur = r.read32(bdf, off);
        let new = if enabled {
            (cur | MSIX_ENABLE) & !MSIX_FUNCTION_MASK
        } else {
            (cur & !MSIX_ENABLE) | MSIX_FUNCTION_MASK
        };
        r.write32(bdf, off, new);
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
            let cur =
                <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::read32(&r, bdf, off);
            let new = if enabled {
                (cur | MSIX_ENABLE) & !MSIX_FUNCTION_MASK
            } else {
                (cur & !MSIX_ENABLE) | MSIX_FUNCTION_MASK
            };
            <hal_aarch64::pci::EcamPci as pci::ConfigSpaceReader>::write32(&r, bdf, off, new);
        }
    }
}

fn alloc_msi_message() -> Option<(u32, u64, u32)> {
    #[cfg(target_arch = "x86_64")]
    {
        arch_irq::alloc_x86_vector().map(|vec| (vec as u32, 0xFEE0_0000u64, vec as u32))
    }
    #[cfg(target_arch = "aarch64")]
    {
        let spi = arch_irq::alloc_arm_spi()?;
        // SAFETY: SPI was allocated from arch-irq's GICv2m MSI range.
        unsafe {
            arch_irq::gic::enable_intid(spi);
        }
        let v2m_pa = firmware::acpi::GIC_MSI_FRAME_PA
            .load(core::sync::atomic::Ordering::Acquire);
        if v2m_pa == 0 {
            let _ = arch_irq::free_arm_spi(spi);
            return None;
        }
        Some((spi, v2m_pa + 0x40, spi))
    }
}

fn register_msi_handler(id: u32, handler: fn()) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        arch_irq::register_msi_handler(id as u8, handler).is_ok()
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch_irq::register_msi_handler(id, handler).is_ok()
    }
}

fn free_msi_id(id: u32) {
    if id == 0 {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let _ = arch_irq::free_x86_vector(id as u8);
    #[cfg(target_arch = "aarch64")]
    let _ = arch_irq::free_arm_spi(id);
}
