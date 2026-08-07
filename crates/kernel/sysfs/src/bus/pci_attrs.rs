// PCI device attribute group (Linux `pci_dev_attrs` + the hotplug, VGA and
// bridge groups). A PCI function's directory carries the whole identity
// surface userspace reads: libdrm walks `/sys/dev/char/<maj>:<min>/device`
// and needs `revision`, `subsystem_vendor` and `subsystem_device` (falling
// back to the raw `config` blob) before it will report a device at all.
//
// Module manifest:
// - `show`:   attribute bodies rendered from live model + config-space state.
// - `store`:  writable attributes, their parsing and their privilege ladder.
// - `config`: the `config` binary attribute's window and access rules.

pub(super) mod config;
pub(super) mod show;
pub(super) mod store;

use crate::kobject::Attribute;
use crate::{RO_PERM, RW_PERM, WO_PERM};

/// `remove` is writable by owner and group (Linux `0220`).
const REMOVE_PERM: u16 = 0o220;
/// `config` is readable by everyone, writable by owner (Linux `0644`); the
/// window each reader observes is decided per access, not by the mode.
const CONFIG_PERM: u16 = 0o644;

/// Attribute name of the raw config-space blob.
pub(super) const CONFIG_ATTR: &str = "config";

/// Attributes every PCI function publishes. # C: n/a
pub(super) const PCI_DEV_ATTRS: &[Attribute] = &[
    Attribute { name: "power_state", mode: RO_PERM },
    Attribute { name: "resource", mode: RO_PERM },
    Attribute { name: "vendor", mode: RO_PERM },
    Attribute { name: "device", mode: RO_PERM },
    Attribute { name: "subsystem_vendor", mode: RO_PERM },
    Attribute { name: "subsystem_device", mode: RO_PERM },
    Attribute { name: "revision", mode: RO_PERM },
    Attribute { name: "class", mode: RO_PERM },
    Attribute { name: "irq", mode: RO_PERM },
    Attribute { name: "local_cpus", mode: RO_PERM },
    Attribute { name: "local_cpulist", mode: RO_PERM },
    Attribute { name: "modalias", mode: RO_PERM },
    Attribute { name: "numa_node", mode: RW_PERM },
    Attribute { name: "dma_mask_bits", mode: RO_PERM },
    Attribute { name: "consistent_dma_mask_bits", mode: RO_PERM },
    Attribute { name: "enable", mode: RW_PERM },
    Attribute { name: "broken_parity_status", mode: RW_PERM },
    Attribute { name: "msi_bus", mode: RW_PERM },
    Attribute { name: "ari_enabled", mode: RO_PERM },
    Attribute { name: CONFIG_ATTR, mode: CONFIG_PERM },
    Attribute { name: "remove", mode: REMOVE_PERM },
    Attribute { name: "rescan", mode: WO_PERM },
    Attribute { name: "driver_override", mode: RW_PERM },
    Attribute { name: "uevent", mode: RW_PERM },
];

/// Attribute published only by a VGA-class function. # C: n/a
const BOOT_VGA_ATTR: Attribute = Attribute { name: "boot_vga", mode: RO_PERM };
/// DSN exists only when the function's PCIe extended-capability chain carries it.
const SERIAL_NUMBER_ATTR: Attribute = Attribute { name: "serial_number", mode: RO_PERM };

/// Attributes published only by a PCI-to-PCI bridge. # C: n/a
const BRIDGE_ATTRS: &[Attribute] = &[
    Attribute { name: "secondary_bus_number", mode: RO_PERM },
    Attribute { name: "subordinate_bus_number", mode: RO_PERM },
];

/// Whether a class code names a VGA device (Linux `pci_is_vga`). # C: O(1)
pub(super) fn is_vga(class: u32) -> bool {
    let high = class >> 8;
    high == pci::uapi::CLASS_DISPLAY_VGA || high == pci::uapi::CLASS_NOT_DEFINED_VGA
}

/// Whether a function is a PCI-to-PCI bridge. # C: O(1)
pub(super) fn is_bridge(dev: &drv::Device) -> bool {
    dev.pci.is_some_and(|p| {
        p.header_type & pci::uapi::HEADER_TYPE_MASK == pci::uapi::HEADER_TYPE_BRIDGE
    })
}

/// Every attribute visible on this function, default group plus the
/// conditional VGA and bridge groups. # C: O(1)
pub(super) fn visible_attrs(dev: &drv::Device) -> alloc::vec::Vec<&'static Attribute> {
    let mut attrs: alloc::vec::Vec<&'static Attribute> = PCI_DEV_ATTRS.iter().collect();
    if is_vga(dev.class) { attrs.push(&BOOT_VGA_ATTR); }
    if dev.pci.is_some_and(|p| p.serial_number.is_some_and(|n| n != 0)) {
        attrs.push(&SERIAL_NUMBER_ATTR);
    }
    if is_bridge(dev) { attrs.extend(BRIDGE_ATTRS.iter()); }
    attrs
}

/// Look up a visible attribute by name. # C: O(1)
pub(super) fn find_attr(dev: &drv::Device, name: &str) -> Option<&'static Attribute> {
    visible_attrs(dev).into_iter().find(|a| a.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vga_classes_match_the_display_and_undefined_encodings() {
        assert!(is_vga(0x03_00_00));
        assert!(is_vga(0x03_00_01));
        assert!(is_vga(0x00_01_00));
        assert!(!is_vga(0x03_80_00));
        assert!(!is_vga(0x01_00_00));
    }

    #[test]
    fn identity_attributes_libdrm_reads_are_all_published() {
        for name in ["revision", "subsystem_vendor", "subsystem_device", "vendor",
                     "device", "class", CONFIG_ATTR] {
            assert!(PCI_DEV_ATTRS.iter().any(|a| a.name == name), "missing {name}");
        }
    }

    #[test]
    fn attribute_modes_match_the_linux_group() {
        let mode = |n: &str| PCI_DEV_ATTRS.iter().find(|a| a.name == n).map(|a| a.mode);
        assert_eq!(mode("revision"), Some(0o444));
        assert_eq!(mode("subsystem_vendor"), Some(0o444));
        assert_eq!(mode(CONFIG_ATTR), Some(0o644));
        assert_eq!(mode("enable"), Some(0o644));
        assert_eq!(mode("numa_node"), Some(0o644));
        assert_eq!(mode("remove"), Some(0o220));
        assert_eq!(mode("rescan"), Some(0o200));
        assert_eq!(mode("msi_bus"), Some(0o644));
    }
}
