// SMBIOS / DMI decode (`docs/35`). Linux exposes firmware system identity under
// `/sys/class/dmi/id/*`; systemd-detect-virt reads these attributes to identify
// QEMU/KVM/VMware as a VM rather than falling through to container checks.
//
// x86: the SMBIOS entry point anchor (`_SM_` 2.x / `_SM3_` 3.x) lives in the
// legacy BIOS ROM area 0xF0000..0x100000, which qemu/SeaBIOS populates on the
// multiboot2 (legacy) boot path. aarch64 has no such region; it gets SMBIOS via
// the EFI SMBIOS3 config table (wired separately by the arm boot handoff).

use alloc::vec::Vec;
use sync::Spinlock;
use sync::TaskList as DmiLock;

/// Cached DMI system-identity bytes. Empty vector means field absent.
#[derive(Default, Clone)]
pub struct DmiId {
    pub sys_vendor: Vec<u8>,       // type 1 manufacturer
    pub product_name: Vec<u8>,     // type 1 product name
    pub product_version: Vec<u8>,  // type 1 version
    pub product_serial: Vec<u8>,   // type 1 serial
    pub product_uuid: Vec<u8>,     // type 1 UUID (formatted)
    pub bios_vendor: Vec<u8>,      // type 0 vendor
    pub bios_version: Vec<u8>,     // type 0 version
    pub bios_date: Vec<u8>,        // type 0 release date
    pub board_vendor: Vec<u8>,     // type 2 manufacturer
    pub board_name: Vec<u8>,       // type 2 product
    pub board_version: Vec<u8>,    // type 2 version
    pub chassis_vendor: Vec<u8>,   // type 3 manufacturer
    pub chassis_version: Vec<u8>,  // type 3 version
    /// Set once tables were located & decoded (Linux "DMI present").
    pub present: bool,
}

static DMI: Spinlock<Option<DmiId>, DmiLock> = Spinlock::new(None);

/// Snapshot the decoded DMI identity for the sysfs `dmi` class. # C: O(1) clone
pub fn dmi() -> Option<DmiId> { DMI.lock().clone() }

/// True once SMBIOS tables were located and decoded. # C: O(1)
pub fn present() -> bool { DMI.lock().as_ref().map(|d| d.present).unwrap_or(false) }

const LEGACY_LO: u64 = 0x000F_0000;
const LEGACY_LEN: usize = 0x0001_0000; // 0xF0000..0x100000
const SMBIOS_MAX_TABLE_LEN: usize = 0x20_0000;
const MAX_STRUCTURES: usize = 1024;

/// Scan the legacy BIOS area for the SMBIOS entry point and decode the identity
/// tables (x86). `hhdm` is the HHDM offset that linearly maps physical memory.
///
/// # Safety
/// Caller asserts `hhdm + [0xF0000, 0x100000)` is HHDM-mapped readable physical
/// memory (the bootloader identity-maps the low ROM area). The single raw view
/// below is the only unsafe access; all decode works on bounded slices.
/// # C: O(scan + tables)
pub unsafe fn init_x86(hhdm: u64) {
    // SAFETY: caller asserts [hhdm+0xF0000, +0x10000) is mapped readable ROM.
    let rom: &[u8] = unsafe {
        core::slice::from_raw_parts((hhdm + LEGACY_LO) as *const u8, LEGACY_LEN)
    };
    // 16-byte-aligned anchor scan: prefer `_SM3_` (3.x) then `_SM_` (2.x).
    let mut i = 0usize;
    while i + 5 <= rom.len() {
        if &rom[i..i + 5] == b"_SM3_" {
            if let Some(id) = decode_ep3(hhdm, &rom[i..]) { store(id); return; }
        } else if &rom[i..i + 4] == b"_SM_" {
            if let Some(id) = decode_ep2(hhdm, &rom[i..]) { store(id); return; }
        }
        i += 16;
    }
}

/// Decode from an SMBIOS 3.0 (`_SM3_`) 64-bit entry point.
fn decode_ep3(hhdm: u64, ep: &[u8]) -> Option<DmiId> {
    if ep.len() < 0x18 { return None; }
    let ep_len = ep[0x06] as usize;
    if ep_len < 0x18 || ep_len > ep.len() || !checksum_ok(&ep[..ep_len]) { return None; }
    let max_len = u32::from_le_bytes(ep[0x0C..0x10].try_into().ok()?) as usize; // table max size
    let table_pa = u64::from_le_bytes(ep[0x10..0x18].try_into().ok()?);         // table address
    decode_at(hhdm, table_pa, max_len)
}

/// Decode from an SMBIOS 2.1 (`_SM_`) 32-bit entry point.
fn decode_ep2(hhdm: u64, ep: &[u8]) -> Option<DmiId> {
    if ep.len() < 0x1C { return None; }
    let ep_len = ep[0x05] as usize;
    if ep_len < 0x1F || ep_len > ep.len() || !checksum_ok(&ep[..ep_len]) { return None; }
    if &ep[0x10..0x15] != b"_DMI_" || !checksum_ok(&ep[0x10..0x1F]) { return None; }
    let table_len = u16::from_le_bytes(ep[0x16..0x18].try_into().ok()?) as usize; // table length
    let table_pa = u32::from_le_bytes(ep[0x18..0x1C].try_into().ok()?) as u64;    // table address
    decode_at(hhdm, table_pa, table_len)
}

/// View the SMBIOS structure table via the HHDM and decode it.
fn decode_at(hhdm: u64, table_pa: u64, max_len: usize) -> Option<DmiId> {
    if table_pa == 0 || max_len == 0 || max_len > SMBIOS_MAX_TABLE_LEN { return None; }
    // SAFETY: table_pa/max_len come from the validated entry point; the table
    // lies in the same HHDM-mapped firmware region as the anchor (GRUB
    // map physical RAM linearly at `hhdm`). Bounded by max_len; parsing is safe.
    let tbl: &[u8] = unsafe {
        core::slice::from_raw_parts((hhdm + table_pa) as *const u8, max_len)
    };
    Some(decode_tables(tbl))
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

/// Walk the SMBIOS structure table (safe over `tbl`), extracting the DMI
/// identity structures: type 0 BIOS, 1 System, 2 Baseboard, 3 Chassis.
fn decode_tables(tbl: &[u8]) -> DmiId {
    let mut out = DmiId::default();
    let mut off = 0usize;
    for _ in 0..MAX_STRUCTURES {
        if off + 4 > tbl.len() { break; }
        let stype = tbl[off];
        let flen = tbl[off + 1] as usize; // formatted-area length (incl header)
        if flen < 4 || off + flen > tbl.len() { break; }
        let fmt = &tbl[off..off + flen];
        let strset = &tbl[off + flen..];
        let strset_len = strset_span(strset);
        let s = |field: usize| -> Vec<u8> {
            if field < fmt.len() { smbios_string(strset, fmt[field]) } else { Vec::new() }
        };
        match stype {
            0 => { out.bios_vendor = s(0x04); out.bios_version = s(0x05); out.bios_date = s(0x08); }
            1 => {
                out.sys_vendor = s(0x04); out.product_name = s(0x05);
                out.product_version = s(0x06); out.product_serial = s(0x07);
                if flen >= 0x18 { out.product_uuid = fmt_uuid(&fmt[0x08..0x18]); }
            }
            2 => { out.board_vendor = s(0x04); out.board_name = s(0x05); out.board_version = s(0x06); }
            3 => { out.chassis_vendor = s(0x04); out.chassis_version = s(0x06); }
            127 => break, // End-of-table
            _ => {}
        }
        off += flen + strset_len;
    }
    out.present = true;
    out
}

/// Byte length of an SMBIOS string set including the terminating double-NUL.
fn strset_span(set: &[u8]) -> usize {
    if set.len() >= 2 && set[0] == 0 && set[1] == 0 { return 2; } // empty set
    let mut i = 0usize;
    while i < set.len() {
        if set[i] == 0 && i + 1 < set.len() && set[i + 1] == 0 { return i + 2; }
        i += 1;
    }
    set.len()
}

/// 1-based `idx`th NUL-separated string bytes from an SMBIOS string set. `0` is none.
fn smbios_string(set: &[u8], idx: u8) -> Vec<u8> {
    if idx == 0 { return Vec::new(); }
    let mut cur: u8 = 1;
    for chunk in set.split(|&b| b == 0) {
        if cur == idx {
            return chunk.to_vec();
        }
        if chunk.is_empty() { break; } // hit the double-NUL terminator
        cur += 1;
    }
    Vec::new()
}

/// Format a 16-byte SMBIOS UUID as Linux does (little-endian first three fields).
fn fmt_uuid(b: &[u8]) -> Vec<u8> {
    if b.len() < 16 { return Vec::new(); }
    alloc::format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ).into_bytes()
}

fn store(id: DmiId) { *DMI.lock() = Some(id); }

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{checksum_ok, decode_tables, fmt_uuid, smbios_string, strset_span};

    #[test]
    fn string_set_indexes_are_one_based() {
        let set = b"QEMU\0Standard PC\0\0";
        assert_eq!(smbios_string(set, 0), b"");
        assert_eq!(smbios_string(set, 1), b"QEMU");
        assert_eq!(smbios_string(set, 2), b"Standard PC");
        assert_eq!(smbios_string(set, 3), b"");
        assert_eq!(strset_span(set), set.len());
    }

    #[test]
    fn string_set_preserves_non_utf8_bytes() {
        let set = b"raw-\xff\0\0";
        assert_eq!(smbios_string(set, 1), b"raw-\xff");
    }

    #[test]
    fn checksum_requires_zero_sum() {
        assert!(checksum_ok(&[1, 2, 253]));
        assert!(!checksum_ok(&[1, 2, 3]));
    }

    #[test]
    fn uuid_uses_smbios_byte_order() {
        let uuid = [0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(fmt_uuid(&uuid), b"12345678-9abc-def0-1122-334455667788");
    }

    #[test]
    fn decodes_bios_system_and_board_identity() {
        let mut table = Vec::new();
        table.extend_from_slice(&[0, 0x09, 0, 0, 1, 2, 0, 0, 3]);
        table.extend_from_slice(b"SeaBIOS\x00rel-1\x0001/01/2026\x00\x00");
        table.extend_from_slice(&[1, 0x18, 1, 0, 1, 2, 3, 4,
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        table.extend_from_slice(b"QEMU\0Standard PC\0pc-q35\0serial\0\0");
        table.extend_from_slice(&[2, 0x08, 2, 0, 1, 2, 3, 0]);
        table.extend_from_slice(b"QEMU\0Board\0v1\0\0");
        table.extend_from_slice(&[127, 4, 3, 0, 0, 0]);

        let id = decode_tables(&table);
        assert!(id.present);
        assert_eq!(id.bios_vendor, b"SeaBIOS");
        assert_eq!(id.sys_vendor, b"QEMU");
        assert_eq!(id.product_name, b"Standard PC");
        assert_eq!(id.product_uuid, b"12345678-9abc-def0-1122-334455667788");
        assert_eq!(id.board_vendor, b"QEMU");
        assert_eq!(id.board_name, b"Board");
    }
}
