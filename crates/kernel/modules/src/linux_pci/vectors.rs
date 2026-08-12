use super::types::*;
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

    // Do not claim an MSI-X allocation until the device table has actually
    // been mapped, masked, populated, and enabled.  Returning CPU vectors here
    // used to make a driver believe MSI-X was live while its function was
    // still unable to deliver any interrupt.
    // Linux falls back from MSI-X to MSI when the caller allowed both.  This
    // compatibility layer currently supports the universally-used one-message
    // MSI form; multi-message MSI needs the same non-contiguous IRQ ownership
    // as the MSI-X table path and must not be faked with bare APIC vectors.
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
    let Some((base, count, flags)) = super::registry::irq_vectors(dev) else { return; };
    if flags & PCI_IRQ_MSI != 0 {
        // SAFETY: the runtime record belongs to this live PCI ABI object.
        let cap = unsafe { (*dev).msi_cap };
        let bdf = super::config::bdf(dev);
        if cap != 0 {
            let config = LinuxPciConfig { dev: dev as usize };
            let _ = pci::disable_msi(&config, bdf, cap);
        }
        if count == 1 { arch_irq::free_pci_msi(base); }
    }
    let _ = super::registry::set_irq_vectors(dev, 0, 0, 0);
}
