//! Boot root-device grammar and lookup over the canonical disk registry.

use alloc::sync::Arc;

use crate::BlockDevice;

use super::{by_dev, by_name, decode_root_dev};
#[cfg(test)]
use super::encode_dev;

/// One supported boot root-device spelling.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RootSpec<'a> {
    /// Exact block-device node name without its `/dev/` prefix.
    Name(&'a str),
    /// Packed block device number.
    DevNum(u32),
}

/// Parse a boot `root=` value into a canonical block lookup key.
///
/// Exact `/dev/<name>`, `<major>:<minor>`, and packed hexadecimal device
/// numbers are accepted. Partition identifiers require a partition registry
/// and are deliberately refused until that owner exists; silently choosing a
/// different disk would mount the wrong root.
/// # C: O(value length)
pub fn parse_root_spec(value: &[u8]) -> Option<RootSpec<'_>> {
    if let Some(name) = value.strip_prefix(b"/dev/") {
        let name = core::str::from_utf8(name).ok()?;
        if name.is_empty() || name.as_bytes().contains(&b'/') { return None; }
        return Some(RootSpec::Name(name));
    }
    if value.starts_with(b"PARTUUID=") || value.starts_with(b"PARTLABEL=") { return None; }
    parse_devnum(value).map(RootSpec::DevNum)
}

/// Resolve a boot `root=` value only through the published block registry.
/// # C: O(N_disks)
pub fn resolve_root_spec(value: &[u8]) -> Option<Arc<dyn BlockDevice>> {
    match parse_root_spec(value)? {
        RootSpec::Name(name) => by_name(name).map(|disk| disk.dev.clone()),
        RootSpec::DevNum(dev) => by_dev(dev).map(|disk| disk.dev.clone()),
    }
}

fn parse_devnum(value: &[u8]) -> Option<u32> {
    if let Some(colon) = value.iter().position(|b| *b == b':') {
        let major = decimal(&value[..colon])?;
        let minor = decimal(&value[colon + 1..])?;
        return decode_root_dev(major, minor);
    }
    hexadecimal(value)
}

fn decimal(value: &[u8]) -> Option<u32> {
    if value.is_empty() { return None; }
    let mut out = 0u32;
    for byte in value {
        if !byte.is_ascii_digit() { return None; }
        out = out.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))?;
    }
    Some(out)
}

fn hexadecimal(value: &[u8]) -> Option<u32> {
    if value.is_empty() { return None; }
    let mut out = 0u32;
    for byte in value {
        let digit = match byte {
            b'0'..=b'9' => u32::from(*byte - b'0'),
            b'a'..=b'f' => u32::from(*byte - b'a' + 10),
            b'A'..=b'F' => u32::from(*byte - b'A' + 10),
            _ => return None,
        };
        out = out.checked_mul(16)?.checked_add(digit)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemDisk;
    use sync::TaskList;

    #[test]
    fn exact_dev_node_is_a_name() {
        assert_eq!(parse_root_spec(b"/dev/nvme0n1"), Some(RootSpec::Name("nvme0n1")));
        assert_eq!(parse_root_spec(b"/dev/sda"), Some(RootSpec::Name("sda")));
    }

    #[test]
    fn device_number_forms_are_exact() {
        assert_eq!(parse_root_spec(b"259:0"), Some(RootSpec::DevNum(encode_dev(259, 0))));
        assert_eq!(parse_root_spec(b"10300"), Some(RootSpec::DevNum(0x10300)));
    }

    #[test]
    fn unsupported_or_malformed_forms_never_fallback() {
        for value in [b"PARTUUID=1234".as_slice(), b"PARTLABEL=root", b"/dev/", b"/dev/a/b", b"8:", b":1", b"8:1x", b"0x800"] {
            assert_eq!(parse_root_spec(value), None, "{value:?}");
        }
    }

    #[test]
    fn lookup_uses_the_requested_registry_identity() {
        const NAME: &str = "root-resolution-fixture";
        let index = super::super::register(NAME, MemDisk::<TaskList>::new(512, 8));
        let disk = super::super::by_name(NAME).expect("published fixture");
        assert!(resolve_root_spec(b"/dev/root-resolution-fixture").is_some());
        let dev = encode_dev(disk.number.major, disk.number.minor);
        assert!(resolve_root_spec(format_devnum(disk.number.major, disk.number.minor).as_bytes()).is_some());
        assert!(resolve_root_spec(alloc::format!("{dev:x}").as_bytes()).is_some());
        assert!(super::super::unregister(NAME));
        assert_ne!(index, 0);
    }

    fn format_devnum(major: u32, minor: u32) -> alloc::string::String {
        alloc::format!("{major}:{minor}")
    }
}
