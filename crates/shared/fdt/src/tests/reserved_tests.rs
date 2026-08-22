use alloc::vec::Vec;

use super::Fdt;
use crate::reserved_regions;

fn with_memreserve(mut blob: Vec<u8>, base: u64, len: u64) -> Vec<u8> {
    let insert = crate::FDT_HEADER_LEN;
    let entry: Vec<u8> = base.to_be_bytes().into_iter().chain(len.to_be_bytes()).collect();
    blob.splice(insert..insert, entry);
    for off in [4usize, 8, 12] {
        let old = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());
        blob[off..off + 4].copy_from_slice(&(old + 16).to_be_bytes());
    }
    blob
}

#[test]
fn reservation_map_and_reserved_memory_are_one_owner_list() {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4800_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x0020_0000u64.to_be_bytes());
    let blob = Fdt::new().begin("").prop_u32("#address-cells", 2).prop_u32("#size-cells", 2)
        .begin("reserved-memory").begin("firmware@48000000").prop("reg", &reg).end().end().end().finish();
    let blob = with_memreserve(blob, 0x4700_0000, 0x1000);
    let mut out = [(0u64, 0u64); 4];
    assert_eq!(reserved_regions(&blob, &mut out), 2);
    assert_eq!(&out[..2], &[(0x4700_0000, 0x1000), (0x4800_0000, 0x0020_0000)]);
}

#[test]
fn reserved_memory_uses_root_cell_widths_and_all_reg_tuples() {
    let mut reg = Vec::new();
    for (base, len) in [(0x8100_0000u32, 0x1000u32), (0x8200_0000, 0x2000)] {
        reg.extend_from_slice(&base.to_be_bytes());
        reg.extend_from_slice(&len.to_be_bytes());
    }
    let blob = Fdt::new().begin("").prop_u32("#address-cells", 1).prop_u32("#size-cells", 1)
        .begin("reserved-memory").begin("pool").prop("reg", &reg).end().end().end().finish();
    let mut out = [(0u64, 0u64); 2];
    assert_eq!(reserved_regions(&blob, &mut out), 2);
    assert_eq!(out, [(0x8100_0000, 0x1000), (0x8200_0000, 0x2000)]);
}
