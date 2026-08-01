// Attribute bodies for a PCI function. Every value is rendered fresh from the
// live model object (and, for the bridge bus numbers, from config space) so a
// read never serves a boot-time snapshot.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use super::{is_bridge, is_vga};

/// Node a device without NUMA reports (Linux `NUMA_NO_NODE`).
pub(crate) const NUMA_NODE_NONE: i32 = drv::NUMA_NODE_NONE;
/// Highest node id + 1 on a single-node system.
pub(crate) const MAX_NUMNODES: i32 = 1;
/// Addressing width of the DMA mask a PCI function is set up with.
const DEFAULT_DMA_MASK_BITS: u32 = 32;
/// Power state of a function with no runtime-PM transitions.
const POWER_STATE_D0: &str = "D0";
/// Hex digits per cpumask group in the `%*pb` cpumask format.
const CPUMASK_GROUP_DIGITS: usize = 8;
/// CPUs one hex digit of a cpumask covers.
const CPUS_PER_HEX_DIGIT: usize = 4;

/// Live online-CPU count, clamped to a real range. # C: O(1)
fn ncpu() -> usize {
    (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS)
}

/// Linux cpumask hex form: zero-padded to the CPU count, in comma-separated
/// 32-bit groups, most significant first. # C: O(n)
pub(crate) fn cpumask_hex(ncpu: usize) -> String {
    let bits = if ncpu >= u64::BITS as usize { u64::MAX } else { (1u64 << ncpu) - 1 };
    let width = ncpu.div_ceil(CPUS_PER_HEX_DIGIT);
    let mut digits = String::new();
    let _ = write!(digits, "{bits:0width$x}");
    let mut out = String::new();
    let head = digits.len() % CPUMASK_GROUP_DIGITS;
    let mut idx = 0;
    if head != 0 {
        out.push_str(&digits[..head]);
        idx = head;
    }
    while idx < digits.len() {
        if !out.is_empty() { out.push(','); }
        out.push_str(&digits[idx..idx + CPUMASK_GROUP_DIGITS]);
        idx += CPUMASK_GROUP_DIGITS;
    }
    out
}

/// Linux cpumask list form: `0` for one CPU, `0-N` for N+1. # C: O(1)
pub(crate) fn cpumask_list(ncpu: usize) -> String {
    let mut s = String::new();
    if ncpu <= 1 { s.push('0'); } else { let _ = write!(s, "0-{}", ncpu - 1); }
    s
}

/// One resource row of the `resource` table. # C: O(1)
pub(crate) fn resource_row(r: Option<&drv::Resource>) -> String {
    let (start, end, flags) = match r { Some(r) => (r.start, r.end, r.flags), None => (0, 0, 0) };
    let mut s = String::new();
    let _ = write!(s, "0x{start:016x} 0x{end:016x} 0x{flags:016x}\n");
    s
}

/// The `resource` table: one row per standard BAR plus the expansion ROM,
/// zero-filled where the function decodes nothing. # C: O(n)
pub(crate) fn resource_table(resources: &[drv::Resource]) -> String {
    let mut s = String::new();
    for idx in 0..pci::uapi::NUM_RESOURCE_ROWS {
        s.push_str(&resource_row(resources.iter().find(|r| r.bar as usize == idx)));
    }
    s
}

/// Whether `dev` is the VGA device the system booted on: the first VGA-class
/// function in enumeration order (Linux `vga_default_device`). # C: O(N_devices)
fn is_boot_vga(dev: &drv::Device) -> bool {
    drv::devices().into_iter()
        .find(|d| d.bus == "pci" && is_vga(d.class))
        .is_some_and(|d| d.addr == dev.addr)
}

/// One byte of config space, or 0 when no accessor is published. # C: O(1)
fn config_byte(dev: &drv::Device, off: u8) -> u8 {
    let mut byte = [0u8; 1];
    drv::pci_config_read(&dev.addr, off as usize, &mut byte);
    byte[0]
}

/// Whether the function currently decodes its I/O or memory windows —
/// the enable count userspace observes. # C: O(1)
pub(crate) fn enable_count(dev: &drv::Device) -> u32 {
    let command = super::store::read_command(dev);
    u32::from(command & (pci::COMMAND_IO | pci::COMMAND_MEMORY) != 0)
}

/// Render `leaf` for a PCI function. `None` = not a PCI attribute. # C: O(n)
pub(crate) fn body(dev: &drv::Device, leaf: &str) -> Option<Vec<u8>> {
    let ident = dev.pci.unwrap_or_default();
    let mut s = String::new();
    match leaf {
        "vendor" => { let _ = write!(s, "0x{:04x}", dev.vendor_id); }
        "device" => { let _ = write!(s, "0x{:04x}", dev.device_id); }
        "subsystem_vendor" => { let _ = write!(s, "0x{:04x}", ident.subsystem_vendor); }
        "subsystem_device" => { let _ = write!(s, "0x{:04x}", ident.subsystem_device); }
        "revision" => { let _ = write!(s, "0x{:02x}", ident.revision); }
        "class" => { let _ = write!(s, "0x{:06x}", dev.class); }
        "irq" => { let _ = write!(s, "{}", ident.interrupt_line); }
        "power_state" => { s.push_str(POWER_STATE_D0); }
        "resource" => { return Some(resource_table(&dev.resources).into_bytes()); }
        "local_cpus" => { s.push_str(&cpumask_hex(ncpu())); }
        "local_cpulist" => { s.push_str(&cpumask_list(ncpu())); }
        "numa_node" => { let _ = write!(s, "{}", dev.numa_node()); }
        "dma_mask_bits" | "consistent_dma_mask_bits" => {
            let _ = write!(s, "{DEFAULT_DMA_MASK_BITS}");
        }
        "enable" => { let _ = write!(s, "{}", enable_count(dev)); }
        "broken_parity_status" => { let _ = write!(s, "{}", u32::from(dev.broken_parity_status())); }
        "msi_bus" => { let _ = write!(s, "{}", u32::from(dev.msi_allowed())); }
        // No ARI-forwarding bridge is programmed, so no function ever runs
        // with ARI enabled.
        "ari_enabled" => { s.push('0'); }
        "boot_vga" if is_vga(dev.class) => { let _ = write!(s, "{}", u32::from(is_boot_vga(dev))); }
        "secondary_bus_number" if is_bridge(dev) => {
            let _ = write!(s, "{}", config_byte(dev, pci::uapi::SECONDARY_BUS_OFF));
        }
        "subordinate_bus_number" if is_bridge(dev) => {
            let _ = write!(s, "{}", config_byte(dev, pci::uapi::SUBORDINATE_BUS_OFF));
        }
        _ => return None,
    }
    s.push('\n');
    Some(s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn pci_dev() -> drv::Device {
        drv::Device::new("pci", "0000:00:03.0".to_string(), 0x1AF4, 0x1050, 0x03_00_00)
            .with_pci_ident(drv::PciIdent {
                revision: 0x01,
                header_type: pci::uapi::HEADER_TYPE_NORMAL,
                subsystem_vendor: 0x1AF4,
                subsystem_device: 0x1100,
                interrupt_line: 11,
            })
    }

    fn read(dev: &drv::Device, leaf: &str) -> String {
        String::from_utf8(body(dev, leaf).expect("attribute body")).expect("utf8")
    }

    #[test]
    fn identity_attributes_use_the_linux_widths() {
        let dev = pci_dev();
        assert_eq!(read(&dev, "vendor"), "0x1af4\n");
        assert_eq!(read(&dev, "device"), "0x1050\n");
        assert_eq!(read(&dev, "subsystem_vendor"), "0x1af4\n");
        assert_eq!(read(&dev, "subsystem_device"), "0x1100\n");
        assert_eq!(read(&dev, "revision"), "0x01\n");
        assert_eq!(read(&dev, "class"), "0x030000\n");
        assert_eq!(read(&dev, "irq"), "11\n");
    }

    #[test]
    fn a_function_without_captured_identity_reads_zeroes_not_enoent() {
        let dev = drv::Device::new("pci", "0000:00:04.0".to_string(), 0x1AF4, 0x1041, 0x02_00_00);
        assert_eq!(read(&dev, "subsystem_vendor"), "0x0000\n");
        assert_eq!(read(&dev, "revision"), "0x00\n");
        assert_eq!(read(&dev, "irq"), "0\n");
    }

    #[test]
    fn resource_table_is_one_row_per_bar_plus_rom() {
        let resources = alloc::vec![
            drv::Resource { bar: 1, start: 0xc000, end: 0xc07f, flags: drv::IORESOURCE_IO },
        ];
        let table = resource_table(&resources);
        assert_eq!(table.lines().count(), pci::uapi::NUM_RESOURCE_ROWS);
        let mut lines = table.lines();
        assert_eq!(lines.next().unwrap(), "0x0000000000000000 0x0000000000000000 0x0000000000000000");
        assert_eq!(lines.next().unwrap(), "0x000000000000c000 0x000000000000c07f 0x0000000000000100");
        assert!(lines.all(|l| l == "0x0000000000000000 0x0000000000000000 0x0000000000000000"));
    }

    #[test]
    fn cpumask_hex_pads_to_the_cpu_count_and_groups_by_32_bits() {
        assert_eq!(cpumask_hex(1), "1");
        assert_eq!(cpumask_hex(4), "f");
        assert_eq!(cpumask_hex(8), "ff");
        assert_eq!(cpumask_hex(32), "ffffffff");
        assert_eq!(cpumask_hex(36), "f,ffffffff");
        assert_eq!(cpumask_hex(64), "ffffffff,ffffffff");
    }

    #[test]
    fn cpumask_list_collapses_a_single_cpu() {
        assert_eq!(cpumask_list(1), "0");
        assert_eq!(cpumask_list(4), "0-3");
    }

    #[test]
    fn unmodelled_leaf_is_not_a_pci_attribute() {
        assert!(body(&pci_dev(), "does_not_exist").is_none());
    }

    #[test]
    fn bridge_only_and_vga_only_leaves_stay_hidden_off_their_devices() {
        let dev = drv::Device::new("pci", "0000:00:05.0".to_string(), 0x1AF4, 0x1041, 0x02_00_00);
        assert!(body(&dev, "boot_vga").is_none());
        assert!(body(&dev, "secondary_bus_number").is_none());
        assert!(body(&pci_dev(), "boot_vga").is_some());
    }

    #[test]
    fn single_node_system_reports_no_numa_node() {
        assert_eq!(read(&pci_dev(), "numa_node"), "-1\n");
    }
}
