use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn parse_flowtable_devices(blob: &[u8]) -> Option<Vec<::net::FlowtableDevice>> {
    let mut devices = Vec::new();
    let mut off = 0usize;
    while off + 4 <= blob.len() {
        let len = u16::from_ne_bytes([blob[off], blob[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([blob[off + 2], blob[off + 3]]) & 0x3fff;
        if len < 4 || off + len > blob.len() || !matches!(ty, 1 | 2) { return None; }
        let raw = &blob[off + 4..off + len];
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        let name = String::from(core::str::from_utf8(&raw[..end]).ok()?);
        devices.push(match ty {
            1 => ::net::FlowtableDevice::Name(name),
            2 => ::net::FlowtableDevice::Prefix(name),
            _ => return None,
        });
        off += netlink::nlmsg_align(len);
    }
    (off == blob.len()).then_some(devices)
}
