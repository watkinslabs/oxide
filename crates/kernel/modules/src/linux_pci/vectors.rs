use super::types::*;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use pci::{Bdf, ConfigSpaceReader};

/// Adapter that makes the live Linux KPI configuration path use the shared
/// PCI capability programming helpers.  It deliberately holds the ABI pointer
/// as an integer: PCI config access is serialized by the caller's device
/// lifetime, and the adapter never retains or dereferences it after the call.
struct LinuxPciConfig { dev: usize }

impl ConfigSpaceReader for LinuxPciConfig {
    fn read32(&self, _bdf: Bdf, off: u8) -> u32 {
        super::config::read32(self.dev as *mut LinuxPciDev, off)
    }

    fn write32(&self, _bdf: Bdf, off: u8, value: u32) {
        super::config::write32(self.dev as *mut LinuxPciDev, off, value);
    }
}

/// Allocate Linux PCI IRQ vectors.
/// # C: O(max_vecs)
pub(super) fn alloc_irq_vectors(dev: *mut LinuxPciDev, min_vecs: i32, max_vecs: i32, flags: u32) -> i32 {
    if dev.is_null() || min_vecs <= 0 || max_vecs < min_vecs { return -LINUX_EINVAL; }
    if (flags & (PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)) == 0 { return -LINUX_EINVAL; }
    if super::registry::irq_vectors(dev).is_some_and(|(_, count, _)| count != 0) {
        return -LINUX_EBUSY;
    }

    // Linux attempts MSI-X before MSI.  The table is function state, not a
    // driver-private feature: retain its mapping until free, mask delivery,
    // populate each entry from the architecture/IOMMU message owner, then
    // unmask the function only after registry publication succeeds.
    if flags & PCI_IRQ_MSIX != 0 {
        if let Some(count) = alloc_msix_vectors(dev, min_vecs, max_vecs) { return count; }
    }

    // Linux falls back from MSI-X to MSI when the caller allowed both. This
    // compatibility layer currently supports the one-message MSI form;
    // multi-message MSI must not be faked with bare APIC vectors.
    if flags & PCI_IRQ_MSI != 0 && min_vecs == 1 {
        // SAFETY: dev was checked non-NULL and is caller-owned for this ABI call.
        let cap = unsafe { (*dev).msi_cap };
        if cap != 0 {
            let bdf = super::config::bdf(dev);
            if let Some(message) = arch_irq::alloc_pci_msi(bdf, 0) {
                let config = LinuxPciConfig { dev: dev as usize };
                if pci::program_msi_single(&config, bdf, cap, message.address, message.data) {
                    if super::registry::set_irq_vectors(dev, message.irq, 1, PCI_IRQ_MSI) {
                        return 1;
                    }
                    let _ = pci::disable_msi(&config, bdf, cap);
                }
                arch_irq::free_pci_msi(message.irq);
            }
        }
    }
    if (flags & PCI_IRQ_LEGACY) == 0 || min_vecs > 1 { return -LINUX_ENOSPC; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    let irq = unsafe { (*dev).irq };
    if irq == 0 { return -LINUX_ENOSPC; }
    if !super::registry::set_irq_vectors(dev, irq, 1, PCI_IRQ_LEGACY) { return -LINUX_EINVAL; }
    1
}

/// Release Linux PCI IRQ vectors.
/// # C: O(N_vec)
pub(super) fn free_irq_vectors(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    let Some((ids, flags, mapping)) = super::registry::take_irq_vector_list(dev) else { return; };
    if flags & PCI_IRQ_MSI != 0 {
        // SAFETY: the runtime record belongs to this live PCI ABI object.
        let cap = unsafe { (*dev).msi_cap };
        let bdf = super::config::bdf(dev);
        if cap != 0 {
            let config = LinuxPciConfig { dev: dev as usize };
            let _ = pci::disable_msi(&config, bdf, cap);
        }
    }
    if flags & PCI_IRQ_MSIX != 0 {
        // SAFETY: the PCI capability byte and mapping came from this live
        // binding; each entry address was range-checked before publication.
        let cap = unsafe { (*dev).msix_cap };
        if cap != 0 {
            let bdf = super::config::bdf(dev);
            let config = LinuxPciConfig { dev: dev as usize };
            let cfg = cap & 0xfc;
            if let Some(layout) = pci::decode_msix_cap(&config, bdf, cap) {
                for index in 0..ids.len() {
                    mask_msix_entry(mapping, layout.table_offset as u64, index);
                }
            }
            config.write32(bdf, cfg, pci::msix_control_value(config.read32(bdf, cfg), false));
            let _ = config.read32(bdf, cfg);
        }
        if mapping != 0 { super::maps::iounmap(mapping as *mut core::ffi::c_void); }
    }
    for irq in ids { arch_irq::free_pci_msi(irq); }
}

fn alloc_msix_vectors(dev: *mut LinuxPciDev, min_vecs: i32, max_vecs: i32) -> Option<i32> {
    // SAFETY: dev was checked non-NULL by the caller and remains owned through this call.
    let cap_off = unsafe { (*dev).msix_cap };
    if cap_off == 0 { return None; }
    let bdf = super::config::bdf(dev);
    let config = LinuxPciConfig { dev: dev as usize };
    let cap = pci::decode_msix_cap(&config, bdf, cap_off)?;
    let wanted = core::cmp::min(max_vecs, i32::from(cap.table_size));
    if wanted < min_vecs { return None; }
    let table_bytes = (cap.table_size as u64).checked_mul(pci::MSIX_TABLE_ENTRY_BYTES)?;
    let table_end = (cap.table_offset as u64).checked_add(table_bytes)?;
    let resource = super::core::resource(dev, cap.table_bir as i32)?;
    if table_end > super::core::resource_len(resource) { return None; }
    let mapping = super::maps::iomap_resource(resource, table_end)? as usize;

    if unsafe { (*dev).msi_cap } != 0 {
        let _ = pci::disable_msi(&config, bdf, unsafe { (*dev).msi_cap });
    }
    let cfg = cap_off & 0xfc;
    config.write32(bdf, cfg, pci::msix_control_enable_masked(config.read32(bdf, cfg)));
    let _ = config.read32(bdf, cfg);

    let mut ids = Vec::new();
    for index in 0..wanted as usize {
        let Some(message) = arch_irq::alloc_pci_msi(bdf, index as u32) else { break; };
        if !write_msix_entry(mapping, cap.table_offset as u64, index, message.address, message.data) {
            arch_irq::free_pci_msi(message.irq);
            break;
        }
        ids.push(message.irq);
    }
    if ids.len() < min_vecs as usize {
        teardown_msix_unpublished(&config, bdf, cfg, mapping, cap.table_offset as u64, &ids);
        return None;
    }
    let count = ids.len() as i32;
    if !super::registry::set_irq_vector_list(dev, ids.clone(), PCI_IRQ_MSIX, mapping) {
        // The registry did not take ownership, so recover it from the local
        // vector list before unmapping the table.
        teardown_msix_unpublished(&config, bdf, cfg, mapping, cap.table_offset as u64, &ids);
        return None;
    }
    config.write32(bdf, cfg, pci::msix_control_value(config.read32(bdf, cfg), true));
    let _ = config.read32(bdf, cfg);
    Some(count)
}

fn teardown_msix_unpublished(config: &LinuxPciConfig, bdf: Bdf, cfg: u8, mapping: usize, table_offset: u64, ids: &[u32]) {
    for index in 0..ids.len() { mask_msix_entry(mapping, table_offset, index); }
    config.write32(bdf, cfg, pci::msix_control_value(config.read32(bdf, cfg), false));
    let _ = config.read32(bdf, cfg);
    if mapping != 0 { super::maps::iounmap(mapping as *mut core::ffi::c_void); }
    for &irq in ids { arch_irq::free_pci_msi(irq); }
}

fn write_msix_entry(mapping: usize, table_offset: u64, index: usize, address: u64, data: u32) -> bool {
    let Some(entry_off) = (index as u64).checked_mul(pci::MSIX_TABLE_ENTRY_BYTES)
        .and_then(|bytes| table_offset.checked_add(bytes)) else { return false; };
    let Some(entry) = mapping.checked_add(entry_off as usize) else { return false; };
    // SAFETY: alloc_msix_vectors bounds the full table inside a PCI BAR mapping
    // retained by the PCI runtime. PCI requires vector control masking before
    // replacing an entry's message fields.
    unsafe {
        write_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED);
        let _ = read_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *const u32);
        write_volatile((entry + pci::MSIX_MESSAGE_ADDR_LOW_OFF as usize) as *mut u32, address as u32);
        write_volatile((entry + pci::MSIX_MESSAGE_ADDR_HIGH_OFF as usize) as *mut u32, (address >> 32) as u32);
        write_volatile((entry + pci::MSIX_MESSAGE_DATA_OFF as usize) as *mut u32, data);
        let _ = read_volatile((entry + pci::MSIX_MESSAGE_DATA_OFF as usize) as *const u32);
        write_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *mut u32, 0);
        let _ = read_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *const u32);
    }
    true
}

fn mask_msix_entry(mapping: usize, table_offset: u64, index: usize) {
    if mapping == 0 { return; }
    let Some(entry_off) = (index as u64).checked_mul(pci::MSIX_TABLE_ENTRY_BYTES)
        .and_then(|bytes| table_offset.checked_add(bytes)) else { return; };
    let Some(entry) = mapping.checked_add(entry_off as usize) else { return; };
    // SAFETY: only a table entry installed by alloc_msix_vectors is masked.
    unsafe {
        write_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *mut u32, pci::MSIX_VECTOR_CONTROL_MASKED);
        let _ = read_volatile((entry + pci::MSIX_VECTOR_CONTROL_OFF as usize) as *const u32);
    }
}
