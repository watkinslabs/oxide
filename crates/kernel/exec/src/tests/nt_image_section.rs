use super::*;
use alloc::{sync::Arc, vec};
use pe::{image_section as build, ImageSection};
use vmm::{MmapPlacement, VmaBacking, VmaFlags};

const OPT: usize = 0x98;
const SEC: usize = 0x188;
const SEC2: usize = SEC + 40;
const DYNAMIC_BASE: u16 = 0x0040;

/// `.text` (R+X, 0x200 file bytes claiming 0x1800 of address space) followed by
/// `.data` (R+W, no file bytes at all).
fn image(preferred: u64) -> alloc::vec::Vec<u8> {
    let mut b = vec![0u8; 0x800];
    b[..2].copy_from_slice(b"MZ"); b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0"); b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    b[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    b[OPT + 16..OPT + 20].copy_from_slice(&0x1010u32.to_le_bytes());
    b[OPT + 24..OPT + 32].copy_from_slice(&preferred.to_le_bytes());
    b[OPT + 32..OPT + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    b[OPT + 36..OPT + 40].copy_from_slice(&0x200u32.to_le_bytes());
    b[OPT + 56..OPT + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    b[OPT + 60..OPT + 64].copy_from_slice(&0x400u32.to_le_bytes());
    b[OPT + 70..OPT + 72].copy_from_slice(&DYNAMIC_BASE.to_le_bytes());
    b[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
    b[SEC..SEC + 8].copy_from_slice(b".text\0\0\0");
    b[SEC + 8..SEC + 12].copy_from_slice(&0x1800u32.to_le_bytes());
    b[SEC + 12..SEC + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    b[SEC + 16..SEC + 20].copy_from_slice(&0x200u32.to_le_bytes());
    b[SEC + 20..SEC + 24].copy_from_slice(&0x400u32.to_le_bytes());
    b[SEC + 36..SEC + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    b[SEC2..SEC2 + 8].copy_from_slice(b".data\0\0\0");
    b[SEC2 + 8..SEC2 + 12].copy_from_slice(&0x800u32.to_le_bytes());
    b[SEC2 + 12..SEC2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    b[SEC2 + 36..SEC2 + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());
    b[0x410] = 0xcc; b[0x7ff] = 0xa5;
    b
}

fn mapped(as_: &AddressSpace, section: &ImageSection, base: UserVirtAddr) -> UserVirtAddr {
    let placed = as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(base), section.size(),
        VmaProt::READ, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data: Arc::clone(&section.bytes), off: 0 }).unwrap();
    protect_view(as_, placed, &section.spans).unwrap();
    placed
}

#[test]
fn an_image_section_is_the_image_extent_not_the_file_extent() {
    let blob = image(0x1000_0000);
    let section = build(&blob, blob.len() as u64).unwrap();
    assert_eq!(section.size(), 0x4000, "the section spans SizeOfImage, not the 0x800-byte file");
    assert_eq!(section.preferred_base, 0x1000_0000);
    assert_eq!(section.information.file_size, 0x800);
}

#[test]
fn each_section_lands_at_its_own_relative_address_with_its_own_protection() {
    let blob = image(0x1000_0000);
    let section = build(&blob, blob.len() as u64).unwrap();
    let as_ = AddressSpace::new(0x20_000).unwrap();
    let base = mapped(&as_, &section, UserVirtAddr::new(0x2000_0000).unwrap());
    let at = |offset: u64| as_.find_vma(UserVirtAddr::new(base.as_u64() + offset).unwrap()).unwrap().prot;
    assert_eq!(at(0), VmaProt::READ, "the headers stay read-only");
    assert_eq!(at(0x1000), VmaProt::READ | VmaProt::EXEC);
    assert_eq!(at(0x2000), VmaProt::READ | VmaProt::EXEC, "the zero tail belongs to its own section");
    assert_eq!(at(0x3000), VmaProt::READ | VmaProt::WRITE);
    // A flat data view would carry one protection across the whole mapping.
    assert_ne!(at(0x1000), at(0x3000));
}

#[test]
fn a_section_tail_past_its_file_bytes_is_readable_zero_filled_address_space() {
    let blob = image(0x1000_0000);
    let section = build(&blob, blob.len() as u64).unwrap();
    assert_eq!(section.bytes[0x1010], 0xcc, "file bytes land at the section's relative address");
    assert!(section.bytes[0x1200..0x3000].iter().all(|byte| *byte == 0));
    assert!(section.bytes[0x3000..0x4000].iter().all(|byte| *byte == 0));
    // The file's own trailing byte is outside every section and must not leak
    // into the view the way a flat mapping of the file would place it.
    assert!(!section.bytes.contains(&0xa5));
}

#[test]
fn a_view_reports_whether_it_reached_the_preferred_base() {
    let blob = image(0x1000_0000);
    let section = build(&blob, blob.len() as u64).unwrap();
    assert!(section.at_preferred_base(0x1000_0000));
    assert!(!section.at_preferred_base(0x2000_0000));
    assert!(section.information.dynamically_relocated(), "so the loader may relocate it");
    let moved = section.information_at(0x2000_0000);
    assert_eq!(moved.transfer_address, 0x2000_0000 + 0x1010);
    assert_eq!(section.information_at(0x1000_0000).transfer_address, 0x1000_0000 + 0x1010);
}

#[test]
fn a_relocated_view_is_what_the_shared_relocation_owner_consumes() {
    let blob = image(0x1000_0000);
    let section = build(&blob, blob.len() as u64).unwrap();
    let mut copy = section.bytes.to_vec();
    let parsed = pe::parse(&blob).unwrap();
    assert_eq!(pe::apply_relocations(&mut copy, &parsed, 0x2000_0000), Ok(()));
}

#[test]
fn a_file_that_is_not_an_image_builds_no_image_section() {
    assert!(build(b"not a pe file at all, just bytes", 32).is_err());
}
