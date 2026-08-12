use alloc::vec;
use alloc::vec::Vec;

use super::{IommuError, IommuKind, parse_dmar, parse_ivrs};

fn le16(t: &mut [u8], off: usize, v: u16) {
    t[off] = v as u8;
    t[off + 1] = (v >> 8) as u8;
}

fn le32(t: &mut [u8], off: usize, v: u32) {
    for i in 0..4 { t[off + i] = (v >> (i * 8)) as u8; }
}

fn le64(t: &mut [u8], off: usize, v: u64) {
    for i in 0..8 { t[off + i] = (v >> (i * 8)) as u8; }
}

fn finish(t: &mut [u8]) {
    t[9] = 0;
    let mut sum = 0u8;
    for b in t.iter() { sum = sum.wrapping_add(*b); }
    t[9] = 0u8.wrapping_sub(sum);
}

fn dmar() -> Vec<u8> {
    let mut t = vec![0u8; 104];
    t[..4].copy_from_slice(b"DMAR");
    le32(&mut t, 4, 104);
    t[36] = 47;
    le16(&mut t, 48, 0);
    le16(&mut t, 50, 24);
    t[52] = 1;
    le16(&mut t, 54, 2);
    le64(&mut t, 56, 0xfed9_0000);
    t[64] = 1;
    t[65] = 8;
    t[68] = 7;
    t[69] = 8;
    t[70] = 9;
    t[71] = 0;
    le16(&mut t, 72, 1);
    le16(&mut t, 74, 32);
    le16(&mut t, 78, 2);
    le64(&mut t, 80, 0x7f00_0000);
    le64(&mut t, 88, 0x7f00_0fff);
    t[96] = 1;
    t[97] = 8;
    t[100] = 7;
    t[101] = 8;
    t[102] = 9;
    t[103] = 0;
    finish(&mut t);
    t
}

fn ivrs() -> Vec<u8> {
    let mut t = vec![0u8; 72];
    t[..4].copy_from_slice(b"IVRS");
    le32(&mut t, 4, 72);
    t[48] = 0x10;
    le16(&mut t, 50, 24);
    le64(&mut t, 56, 0xfed8_0000);
    le16(&mut t, 64, 3);
    finish(&mut t);
    t
}

fn scoped_ivrs() -> Vec<u8> {
    let mut t = vec![0u8; 84];
    t[..4].copy_from_slice(b"IVRS");
    le32(&mut t, 4, 84);
    t[48] = 0x10;
    le16(&mut t, 50, 36);
    le64(&mut t, 56, 0xfed8_0000);
    le16(&mut t, 64, 3);
    t[72] = 0x02;
    le16(&mut t, 74, 0x1234);
    t[76] = 0x03;
    le16(&mut t, 78, 0x2000);
    t[80] = 0x04;
    le16(&mut t, 82, 0x20ff);
    finish(&mut t);
    t
}

fn aliased_ivrs() -> Vec<u8> {
    let mut t = vec![0u8; 80];
    t[..4].copy_from_slice(b"IVRS");
    le32(&mut t, 4, 80);
    t[48] = 0x10;
    le16(&mut t, 50, 32);
    le64(&mut t, 56, 0xfed8_0000);
    le16(&mut t, 64, 3);
    t[72] = 0x42;
    le16(&mut t, 74, 0x1234);
    le16(&mut t, 78, 0x4321);
    finish(&mut t);
    t
}

#[test]
fn dmar_drhd_preserves_the_linux_device_ownership_keys() {
    let inv = parse_dmar(&dmar()).expect("valid DRHD");
    assert_eq!(inv.kind, IommuKind::IntelVtd);
    assert_eq!(inv.unit_count, 1);
    assert_eq!(inv.units[0].segment, 2);
    assert_eq!(inv.units[0].register_base, 0xfed9_0000);
    assert_eq!(inv.units[0].register_pages, 1);
    assert!(inv.units[0].include_all);
    assert!(!inv.dmar_x2apic_opt_out);
    assert_eq!(inv.dmar_scope_count, 1);
    assert_eq!(inv.dmar_scopes[0].unit_index, 0);
    assert_eq!(inv.dmar_scopes[0].start_bus, 8);
    assert_eq!(inv.dmar_scopes[0].path_len, 2);
    assert_eq!(&inv.dmar_scopes[0].path[..2], &[9, 0]);
    assert_eq!(inv.dmar_rmrr_count, 1);
    assert_eq!(inv.dmar_rmrrs[0].segment, 2);
    assert_eq!(inv.dmar_rmrrs[0].base, 0x7f00_0000);
    assert_eq!(inv.dmar_rmrrs[0].end, 0x7f00_0fff);
    assert_eq!(inv.dmar_rmrrs[0].scope_count, 1);
    assert_eq!(inv.dmar_rmrrs[0].scopes[0].start_bus, 8);
}

#[test]
fn dmar_preserves_x2apic_opt_out_policy() {
    let mut table = dmar();
    table[37] = 1 << 1;
    finish(&mut table);
    assert!(parse_dmar(&table).expect("valid DMAR").dmar_x2apic_opt_out);
}

#[test]
fn ivrs_ivhd_preserves_segment_and_register_base() {
    let inv = parse_ivrs(&ivrs()).expect("valid IVHD");
    assert_eq!(inv.kind, IommuKind::AmdVi);
    assert_eq!(inv.unit_count, 1);
    assert_eq!(inv.units[0].segment, 3);
    assert_eq!(inv.units[0].register_base, 0xfed8_0000);
}

#[test]
fn ivrs_ivhd_preserves_requester_ownership_ranges() {
    let inv = parse_ivrs(&scoped_ivrs()).expect("valid IVHD scopes");
    assert_eq!(inv.amd_scope_count, 2);
    assert_eq!(inv.amd_scopes[0].unit_index, 0);
    assert_eq!(inv.amd_scopes[0].first_requester, 0x1234);
    assert_eq!(inv.amd_scopes[0].last_requester, 0x1234);
    assert_eq!(inv.amd_scopes[1].first_requester, 0x2000);
    assert_eq!(inv.amd_scopes[1].last_requester, 0x20ff);
}

#[test]
fn ivrs_ivhd_preserves_canonical_requester_aliases() {
    let inv = parse_ivrs(&aliased_ivrs()).expect("valid IVHD alias");
    assert_eq!(inv.amd_scope_count, 1);
    assert_eq!(inv.amd_alias_count, 1);
    assert_eq!(inv.amd_aliases[0].unit_index, 0);
    assert_eq!(inv.amd_aliases[0].first_requester, 0x1234);
    assert_eq!(inv.amd_aliases[0].last_requester, 0x1234);
    assert_eq!(inv.amd_aliases[0].canonical_requester, 0x4321);
}

#[test]
fn ivrs_range_end_without_start_is_rejected() {
    let mut t = scoped_ivrs();
    t[76] = 0x04;
    finish(&mut t);
    assert_eq!(parse_ivrs(&t), Err(IommuError::BadRecord));
}

#[test]
fn checksum_failure_cannot_publish_a_dmar_unit() {
    let mut t = dmar();
    t[56] ^= 1;
    assert_eq!(parse_dmar(&t), Err(IommuError::BadChecksum));
}

#[test]
fn ivhd_device_entry_cannot_run_past_its_record() {
    let mut t = ivrs();
    t[50] = 28;
    t[72 - 1] = 0;
    finish(&mut t);
    assert_eq!(parse_ivrs(&t), Err(IommuError::BadRecord));
}
