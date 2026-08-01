// Writable PCI attributes: value parsing, the privilege ladder, and the
// config-space or model action each write performs.

use alloc::sync::Arc;
use vfs::{KResult, VfsError};

use super::show::{MAX_NUMNODES, NUMA_NODE_NONE};

/// Parse a `kstrtoul`-style unsigned value: optional `0x`/`0` base prefix, an
/// optional trailing newline, nothing else. # C: O(n)
pub(crate) fn parse_ulong(buf: &[u8]) -> Option<u64> {
    let text = core::str::from_utf8(buf).ok()?.trim_end_matches(['\n', '\0']);
    let text = text.trim_start_matches('+');
    if text.is_empty() { return None; }
    let (digits, radix) = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (hex, 16)
    } else if text.len() > 1 && text.starts_with('0') {
        (&text[1..], 8)
    } else {
        (text, 10)
    };
    u64::from_str_radix(digits, radix).ok()
}

/// Parse a `kstrtoint`-style signed value. # C: O(n)
pub(crate) fn parse_int(buf: &[u8]) -> Option<i32> {
    let text = core::str::from_utf8(buf).ok()?.trim_end_matches(['\n', '\0']);
    match text.strip_prefix('-') {
        Some(rest) => {
            let magnitude = parse_ulong(rest.as_bytes())?;
            i64::try_from(magnitude).ok()?.checked_neg()?.try_into().ok()
        }
        None => i64::try_from(parse_ulong(text.as_bytes())?).ok()?.try_into().ok(),
    }
}

/// Validate a NUMA-node override. # C: O(1)
pub(crate) fn validate_numa_node(node: i32) -> KResult<i32> {
    if node < 0 && node != NUMA_NODE_NONE { return Err(VfsError::Einval); }
    if node >= MAX_NUMNODES { return Err(VfsError::Einval); }
    Ok(node)
}

/// Whether writing `leaf` demands `CAP_SYS_ADMIN` (Linux gates the writes
/// that can wedge the machine or lie to the allocator). # C: O(1)
pub(crate) fn store_needs_admin(leaf: &str) -> bool {
    matches!(leaf, "enable" | "numa_node" | "msi_bus")
}

/// Read the 16-bit command register. # C: O(1)
pub(crate) fn read_command(dev: &drv::Device) -> u16 {
    let mut raw = [0u8; 2];
    if !drv::pci_config_read(&dev.addr, pci::uapi::COMMAND_OFF as usize, &mut raw) { return 0; }
    u16::from_le_bytes(raw)
}

/// Write the 16-bit command register. # C: O(1)
fn write_command(dev: &drv::Device, command: u16) -> bool {
    drv::pci_config_write(&dev.addr, pci::uapi::COMMAND_OFF as usize, &command.to_le_bytes())
}

/// Command bits a function needs to decode the windows it actually has.
/// # C: O(n)
pub(crate) fn decode_bits(resources: &[drv::Resource]) -> u16 {
    let mut bits = 0;
    if resources.iter().any(|r| r.flags & drv::IORESOURCE_IO != 0) { bits |= pci::COMMAND_IO; }
    if resources.iter().any(|r| r.flags & drv::IORESOURCE_MEM != 0) { bits |= pci::COMMAND_MEMORY; }
    bits
}

/// Turn a function's window decoding on or off. # C: O(n)
fn set_decode(dev: &drv::Device, on: bool) -> KResult<()> {
    let mut raw = [0u8; 2];
    if !drv::pci_config_read(&dev.addr, pci::uapi::COMMAND_OFF as usize, &mut raw) {
        return Err(VfsError::Eio);
    }
    let command = u16::from_le_bytes(raw);
    let bits = decode_bits(&dev.resources);
    let next = if on { command | bits } else { command & !(pci::COMMAND_IO | pci::COMMAND_MEMORY) };
    if next != command && !write_command(dev, next) { return Err(VfsError::Eio); }
    Ok(())
}

/// Consume a write to a PCI attribute. `privileged` is the opener's
/// `CAP_SYS_ADMIN` in the initial user namespace. `None` = `leaf` is not a
/// writable PCI attribute and the caller's generic path owns it. # C: O(n)
pub(crate) fn store(
    dev: &Arc<drv::Device>, leaf: &str, buf: &[u8], privileged: bool,
) -> Option<KResult<usize>> {
    if !matches!(leaf, "enable" | "numa_node" | "broken_parity_status" | "msi_bus"
                     | "remove" | "rescan") {
        return None;
    }
    if store_needs_admin(leaf) && !privileged { return Some(Err(VfsError::Eperm)); }
    if leaf == "numa_node" {
        let node = match parse_int(buf) { Some(v) => v, None => return Some(Err(VfsError::Einval)) };
        return Some(match validate_numa_node(node) {
            Ok(node) => { dev.set_numa_node(node); Ok(buf.len()) }
            Err(e) => Err(e),
        });
    }
    let val = match parse_ulong(buf) { Some(v) => v, None => return Some(Err(VfsError::Einval)) };
    Some(match leaf {
        "enable" => {
            if dev.bound().is_some() {
                Err(VfsError::Ebusy)
            } else if val != 0 {
                set_decode(dev, true).map(|()| buf.len())
            } else if super::show::enable_count(dev) != 0 {
                set_decode(dev, false).map(|()| buf.len())
            } else {
                Err(VfsError::Eio)
            }
        }
        "broken_parity_status" => { dev.set_broken_parity_status(val != 0); Ok(buf.len()) }
        "msi_bus" => { dev.set_msi_allowed(val != 0); Ok(buf.len()) }
        "remove" => {
            if val != 0 { drv::device_del(dev); }
            Ok(buf.len())
        }
        "rescan" => {
            if val != 0 && !drv::pci_rescan() { return Some(Err(VfsError::Eio)); }
            Ok(buf.len())
        }
        _ => Err(VfsError::Erofs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn dev() -> Arc<drv::Device> {
        Arc::new(drv::Device::new("pci", "0000:00:09.0".to_string(), 0x1AF4, 0x1041, 0x02_00_00))
    }

    #[test]
    fn ulong_parsing_takes_the_base_from_the_prefix() {
        assert_eq!(parse_ulong(b"1\n"), Some(1));
        assert_eq!(parse_ulong(b"0"), Some(0));
        assert_eq!(parse_ulong(b"0x10"), Some(16));
        assert_eq!(parse_ulong(b"010"), Some(8));
        assert_eq!(parse_ulong(b"255"), Some(255));
        assert_eq!(parse_ulong(b""), None);
        assert_eq!(parse_ulong(b"\n"), None);
        assert_eq!(parse_ulong(b"yes"), None);
        assert_eq!(parse_ulong(b"1 2"), None);
    }

    #[test]
    fn int_parsing_accepts_the_negative_node_sentinel() {
        assert_eq!(parse_int(b"-1\n"), Some(-1));
        assert_eq!(parse_int(b"0"), Some(0));
        assert_eq!(parse_int(b"-0x2"), Some(-2));
        assert_eq!(parse_int(b"-"), None);
    }

    #[test]
    fn numa_node_override_accepts_only_real_or_absent_nodes() {
        assert_eq!(validate_numa_node(-1), Ok(-1));
        assert_eq!(validate_numa_node(0), Ok(0));
        assert_eq!(validate_numa_node(1), Err(VfsError::Einval));
        assert_eq!(validate_numa_node(-2), Err(VfsError::Einval));
    }

    #[test]
    fn machine_wedging_writes_require_cap_sys_admin() {
        assert!(store_needs_admin("enable"));
        assert!(store_needs_admin("numa_node"));
        assert!(store_needs_admin("msi_bus"));
        assert!(!store_needs_admin("broken_parity_status"));
        assert!(!store_needs_admin("remove"));
        assert!(!store_needs_admin("rescan"));
    }

    #[test]
    fn unprivileged_write_to_a_gated_attribute_is_eperm() {
        let d = dev();
        assert_eq!(store(&d, "enable", b"1\n", false), Some(Err(VfsError::Eperm)));
        assert_eq!(store(&d, "msi_bus", b"0\n", false), Some(Err(VfsError::Eperm)));
        // The ungated writes stay reachable without the capability.
        assert_eq!(store(&d, "broken_parity_status", b"1\n", false), Some(Ok(2)));
        assert!(d.broken_parity_status());
    }

    #[test]
    fn msi_admission_flips_with_the_written_value() {
        let d = dev();
        assert!(d.msi_allowed());
        assert_eq!(store(&d, "msi_bus", b"0\n", true), Some(Ok(2)));
        assert!(!d.msi_allowed());
        assert_eq!(store(&d, "msi_bus", b"1\n", true), Some(Ok(2)));
        assert!(d.msi_allowed());
    }

    #[test]
    fn numa_node_write_is_visible_to_the_next_read() {
        let d = dev();
        assert_eq!(d.numa_node(), NUMA_NODE_NONE);
        assert_eq!(store(&d, "numa_node", b"0\n", true), Some(Ok(2)));
        assert_eq!(d.numa_node(), 0);
        assert_eq!(store(&d, "numa_node", b"7\n", true), Some(Err(VfsError::Einval)));
        assert_eq!(store(&d, "numa_node", b"junk", true), Some(Err(VfsError::Einval)));
    }

    #[test]
    fn enable_write_on_a_bound_function_is_ebusy_before_any_parsing() {
        let d = dev();
        d.driver.lock().replace("test-driver");
        assert_eq!(store(&d, "enable", b"0\n", true), Some(Err(VfsError::Ebusy)));
    }

    #[test]
    fn decode_bits_follow_the_windows_the_function_owns() {
        assert_eq!(decode_bits(&[]), 0);
        let io = alloc::vec![drv::Resource { bar: 0, start: 1, end: 2, flags: drv::IORESOURCE_IO }];
        assert_eq!(decode_bits(&io), pci::COMMAND_IO);
        let mem = alloc::vec![drv::Resource { bar: 1, start: 1, end: 2, flags: drv::IORESOURCE_MEM }];
        assert_eq!(decode_bits(&mem), pci::COMMAND_MEMORY);
        let both = alloc::vec![io[0].clone(), mem[0].clone()];
        assert_eq!(decode_bits(&both), pci::COMMAND_IO | pci::COMMAND_MEMORY);
    }

    #[test]
    fn read_only_attributes_are_left_to_the_generic_path() {
        let d = dev();
        assert!(store(&d, "vendor", b"1\n", true).is_none());
        assert!(store(&d, "uevent", b"add\n", true).is_none());
    }
}
