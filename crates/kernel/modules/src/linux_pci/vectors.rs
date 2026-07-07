use super::types::*;

/// Allocate Linux PCI IRQ vectors.
/// # C: O(max_vecs)
pub(super) fn alloc_irq_vectors(dev: *mut LinuxPciDev, min_vecs: i32, max_vecs: i32, flags: u32) -> i32 {
    if dev.is_null() || min_vecs <= 0 || max_vecs < min_vecs { return -LINUX_EINVAL; }
    if (flags & (PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)) == 0 { return -LINUX_EINVAL; }
    if (flags & (PCI_IRQ_MSI | PCI_IRQ_MSIX)) != 0 {
        if let Some((base, count)) = alloc_arch_vectors(min_vecs, max_vecs) {
            // SAFETY: dev points at a caller-owned Linux struct pci_dev.
            unsafe {
                (*dev).irq_vector_base = base;
                (*dev).irq_vectors = count;
                (*dev).irq_vector_flags = flags & (PCI_IRQ_MSI | PCI_IRQ_MSIX);
            }
            return count;
        }
    }
    if (flags & PCI_IRQ_LEGACY) == 0 || min_vecs > 1 { return -LINUX_ENOSPC; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe {
        if (*dev).irq == 0 { return -LINUX_ENOSPC; }
        (*dev).irq_vector_base = (*dev).irq;
        (*dev).irq_vectors = 1;
        (*dev).irq_vector_flags = PCI_IRQ_LEGACY;
    }
    1
}

/// Release Linux PCI IRQ vectors.
/// # C: O(N_vec)
pub(super) fn free_irq_vectors(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe {
        if ((*dev).irq_vector_flags & (PCI_IRQ_MSI | PCI_IRQ_MSIX)) != 0 {
            free_arch_vectors((*dev).irq_vector_base, (*dev).irq_vectors);
        }
        (*dev).irq_vector_base = 0;
        (*dev).irq_vectors = 0;
        (*dev).irq_vector_flags = 0;
    }
}

fn alloc_arch_vectors(min_vecs: i32, max_vecs: i32) -> Option<(u32, i32)> {
    let mut base = 0u32;
    let mut count = 0i32;
    while count < max_vecs {
        let vector = match alloc_one_vector() {
            Some(v) => v,
            None => break,
        };
        if count == 0 {
            base = vector;
            count = 1;
            continue;
        }
        if vector != base + count as u32 {
            free_one_vector(vector);
            break;
        }
        count += 1;
    }
    if count >= min_vecs { Some((base, count)) } else {
        free_arch_vectors(base, count);
        None
    }
}

fn free_arch_vectors(base: u32, count: i32) {
    if count <= 0 { return; }
    for off in 0..count { free_one_vector(base + off as u32); }
}

#[cfg(target_arch = "x86_64")]
fn alloc_one_vector() -> Option<u32> {
    arch_irq::alloc_x86_vector().map(u32::from)
}

#[cfg(target_arch = "x86_64")]
fn free_one_vector(vector: u32) {
    let _ = arch_irq::free_x86_vector(vector as u8);
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn alloc_one_vector() -> Option<u32> {
    arch_irq::alloc_arm_lpi().or_else(arch_irq::alloc_arm_spi)
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn free_one_vector(vector: u32) {
    let _ = arch_irq::free_arm_spi(vector);
}

#[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "oxide-kernel"))))]
fn alloc_one_vector() -> Option<u32> { None }

#[cfg(not(any(target_arch = "x86_64", all(target_arch = "aarch64", target_os = "oxide-kernel"))))]
fn free_one_vector(_vector: u32) {}
