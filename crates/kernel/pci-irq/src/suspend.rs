//! PCI MSI/MSI-X source masking adapter for the architecture IRQ owner.

use core::ptr::{read_volatile, write_volatile};
use pci::ConfigSpaceReader;

const MSI_ENABLE: u32 = 1 << 16;

fn pack_bdf(bdf: pci::Bdf) -> u64 {
    (u64::from(bdf.segment) << 16) | (u64::from(bdf.bus) << 8)
        | (u64::from(bdf.device) << 3) | u64::from(bdf.function)
}

fn unpack_bdf(raw: u64) -> pci::Bdf {
    pci::Bdf { segment: (raw >> 16) as u16, bus: (raw >> 8) as u8,
        device: ((raw >> 3) & 0x1f) as u8, function: (raw & 7) as u8 }
}

fn msi_control(value: u32, masked: bool) -> u32 {
    if masked { value & !MSI_ENABLE } else { value | MSI_ENABLE }
}

fn mask_msi(raw_bdf: u64, raw_cap: u64, masked: bool) {
    let bdf = unpack_bdf(raw_bdf);
    let cap = raw_cap as u8 & 0xfc;
    #[cfg(target_arch = "x86_64")]
    let reader = hal_x86_64::pci::EcamPci::from_published();
    #[cfg(target_arch = "aarch64")]
    let reader = hal_aarch64::pci::EcamPci::from_published();
    if let Some(reader) = reader {
        reader.write32(bdf, cap, msi_control(reader.read32(bdf, cap), masked));
        let _ = reader.read32(bdf, cap);
    }
}

fn mask_msix(entry_va: u64, _: u64, masked: bool) {
    let control = entry_va + pci::MSIX_VECTOR_CONTROL_OFF;
    // SAFETY: the Binding or MsixGroup retains this validated table mapping
    // for at least as long as its architecture IRQ descriptor is installed.
    unsafe {
        let old = read_volatile(control as *const u32);
        let value = if masked { old | pci::MSIX_VECTOR_CONTROL_MASKED }
            else { old & !pci::MSIX_VECTOR_CONTROL_MASKED };
        write_volatile(control as *mut u32, value);
        let _ = read_volatile(control as *const u32);
    }
}

/// Bind one MSI capability's source mask. # C: O(1)
pub(crate) fn bind_msi(irq: u32, bdf: pci::Bdf, cap_off: u8) -> bool {
    arch_irq::set_msi_source_mask(irq, mask_msi, pack_bdf(bdf), u64::from(cap_off))
}

/// Bind one MSI-X table entry's source mask. # C: O(1)
pub(crate) fn bind_msix(irq: u32, entry_va: u64) -> bool {
    arch_irq::set_msi_source_mask(irq, mask_msix, entry_va, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_cookie_preserves_segment_and_requester_id() {
        let bdf = pci::Bdf { segment: 0x1234, bus: 0xab, device: 0x1d, function: 6 };
        assert_eq!(unpack_bdf(pack_bdf(bdf)), bdf);
    }

    #[test]
    fn msi_suspend_clears_only_enable_and_resume_restores_it() {
        let original = 0xa5a5_ffff | MSI_ENABLE;
        let suspended = msi_control(original, true);
        assert_eq!(suspended & MSI_ENABLE, 0);
        assert_eq!(suspended & !MSI_ENABLE, original & !MSI_ENABLE);
        assert_eq!(msi_control(suspended, false), original);
    }
}
