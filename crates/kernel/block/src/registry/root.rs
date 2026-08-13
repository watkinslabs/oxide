//! Boot root-device grammar and lookup over the canonical disk registry.

use alloc::sync::Arc;

use crate::BlockDevice;

use super::{by_dev, by_name, decode_root_dev, partition_by_label, partition_by_name, partition_by_uuid_offset};
#[cfg(test)]
use super::encode_dev;

/// One supported boot root-device spelling.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RootSpec<'a> {
    /// Exact block-device node name without its `/dev/` prefix.
    Name(&'a str),
    /// On-media partition UUID, optionally shifted by a partition-number offset.
    PartUuid { uuid: &'a str, offset: i32 },
    /// On-media GPT partition label.
    PartLabel(&'a str),
    /// Packed block device number.
    DevNum(u32),
}

/// Parse a boot `root=` value into a canonical block lookup key.
///
/// Exact `/dev/<name>`, partition UUID/label, `<major>:<minor>`, and packed
/// hexadecimal device numbers are accepted. Every partition form resolves
/// only through the disk-owned published table.
/// # C: O(value length)
pub fn parse_root_spec(value: &[u8]) -> Option<RootSpec<'_>> {
    if let Some(name) = value.strip_prefix(b"/dev/") {
        let name = core::str::from_utf8(name).ok()?;
        if name.is_empty() || name.as_bytes().contains(&b'/') { return None; }
        return Some(RootSpec::Name(name));
    }
    if let Some(uuid) = value.strip_prefix(b"PARTUUID=") { return parse_part_uuid(uuid); }
    if let Some(label) = value.strip_prefix(b"PARTLABEL=") {
        let label = core::str::from_utf8(label).ok()?;
        return (!label.is_empty()).then_some(RootSpec::PartLabel(label));
    }
    parse_devnum(value).map(RootSpec::DevNum)
}

/// Resolve a boot `root=` value only through the published block registry.
/// # C: O(N_disks)
pub fn resolve_root_spec(value: &[u8]) -> Option<Arc<dyn BlockDevice>> {
    match parse_root_spec(value)? {
        RootSpec::Name(name) => by_name(name).map(|disk| disk.dev.clone())
            .or_else(|| partition_by_name(name).map(|part| part.dev.clone())),
        RootSpec::PartUuid { uuid, offset } => partition_by_uuid_offset(uuid, offset).map(|part| part.dev.clone()),
        RootSpec::PartLabel(label) => partition_by_label(label).map(|part| part.dev.clone()),
        RootSpec::DevNum(dev) => by_dev(dev).map(|disk| disk.dev.clone()),
    }
}

fn parse_part_uuid(value: &[u8]) -> Option<RootSpec<'_>> {
    let (uuid, offset) = match value.iter().position(|byte| *byte == b'/') {
        Some(slash) => (value.get(..slash)?, parse_part_offset(value.get(slash + 1..)?)?),
        None => (value, 0),
    };
    let uuid = core::str::from_utf8(uuid).ok()?;
    (!uuid.is_empty()).then_some(RootSpec::PartUuid { uuid, offset })
}

fn parse_part_offset(value: &[u8]) -> Option<i32> {
    let value = value.strip_prefix(b"PARTNROFF=")?;
    let (negative, digits) = match value.first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let magnitude = decimal(digits)?;
    let magnitude = i32::try_from(magnitude).ok()?;
    negative.then(|| magnitude.checked_neg()).unwrap_or(Some(magnitude))
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
    fn supported_partition_forms_are_exact() {
        assert_eq!(parse_root_spec(b"PARTUUID=1234abcd-01"), Some(RootSpec::PartUuid { uuid: "1234abcd-01", offset: 0 }));
        assert_eq!(parse_root_spec(b"PARTUUID=1234abcd-01/PARTNROFF=-2"), Some(RootSpec::PartUuid { uuid: "1234abcd-01", offset: -2 }));
        assert_eq!(parse_root_spec(b"PARTLABEL=root"), Some(RootSpec::PartLabel("root")));
    }

    #[test]
    fn malformed_forms_never_fallback() {
        for value in [b"PARTUUID=".as_slice(), b"PARTUUID=id/PARTNROFF=", b"PARTUUID=id/WRONG=1", b"PARTLABEL=", b"/dev/", b"/dev/a/b", b"8:", b":1", b"8:1x", b"0x800"] {
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

    #[test]
    fn partition_root_forms_use_published_disk_children() {
        use alloc::sync::Arc;
        use crate::Partition;
        use crate::partitions::PartitionDevice;

        const NAME: &str = "partition-root-fixture";
        let dev: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 8);
        assert_ne!(super::super::register(NAME, dev), 0);
        let disk = super::super::by_name(NAME).expect("published fixture");
        let part = Arc::new(Partition {
            name: "partition-root-fixture1".into(), number: 1, start_lba: 2, sectors: 4,
            uuid: Some("1234abcd-01".into()), label: Some("rootfs".into()),
            dev: PartitionDevice::new(Arc::clone(&disk.dev), 2, 4).expect("bounded fixture partition"),
        });
        let next = Arc::new(Partition {
            name: "partition-root-fixture2".into(), number: 2, start_lba: 6, sectors: 2,
            uuid: Some("1234abcd-02".into()), label: Some("rescue".into()),
            dev: PartitionDevice::new(Arc::clone(&disk.dev), 6, 2).expect("bounded fixture partition"),
        });
        disk.publish_partitions(alloc::vec![part, next]);

        assert_eq!(resolve_root_spec(b"/dev/partition-root-fixture1").expect("partition node").capacity_blocks(), 4);
        assert_eq!(resolve_root_spec(b"PARTUUID=1234ABCD-01").expect("partition uuid").capacity_blocks(), 4);
        assert_eq!(resolve_root_spec(b"PARTLABEL=rootfs").expect("partition label").capacity_blocks(), 4);
        assert_eq!(resolve_root_spec(b"PARTUUID=1234abcd-01/PARTNROFF=1").expect("partition offset").capacity_blocks(), 2);
        assert!(resolve_root_spec(b"PARTUUID=1234abcd-01/PARTNROFF=-1").is_none());
        assert!(super::super::unregister(NAME));
    }

    fn format_devnum(major: u32, minor: u32) -> alloc::string::String {
        alloc::format!("{major}:{minor}")
    }
}
