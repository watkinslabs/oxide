// The extended-numbering escape. A process with tens of thousands of mappings
// overflows the 16-bit program-header count, and the real count moves into the
// section header at index 0.

use alloc::vec::Vec;

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::build::CORE_PAGE_SIZE;
use crate::coredump::elf::input::{CoreImageInput, CoreSegment, SEG_READ};
use crate::coredump::elf::layout::CoreArch;
use crate::coredump::elf::uapi::{PN_XNUM, PT_LOAD, PT_NOTE, SHDR64_BYTES, SHT_NULL};

/// `n` mappings, none of whose contents are written, so the case measures the
/// header table rather than memory.
fn many(n: usize) -> Vec<CoreSegment<'static>> {
    (0..n).map(|i| {
        let start = (i as u64 + 1) * 2 * CORE_PAGE_SIZE;
        CoreSegment { start, end: start + CORE_PAGE_SIZE, prot: SEG_READ, dump_size: 0, file: None }
    }).collect()
}

fn build(segs: &[CoreSegment<'_>]) -> Vec<u8> {
    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 5);
    let threads = [fixture::thread(fixture::TID_MAIN, &r, None)];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: segs, auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    crate::coredump::elf::build::build_core_image(&input, &mut mem).expect("image builds")
}

#[test]
fn just_below_the_escape_the_count_is_plain() {
    let segs = many(PN_XNUM as usize - 2);
    let img = build(&segs);
    let i = Image::new(&img);
    assert_eq!(i.e_phnum() as u64, PN_XNUM as u64 - 1);
    assert_eq!(i.e_shoff(), 0, "no section table is needed");
    assert_eq!(i.phdr_count(), PN_XNUM as u64 - 1);
}

#[test]
fn at_the_escape_the_count_moves_to_the_section_header() {
    let segs = many(PN_XNUM as usize - 1);
    let img = build(&segs);
    let i = Image::new(&img);
    assert_eq!(i.e_phnum(), PN_XNUM);
    assert_ne!(i.e_shoff(), 0);
    assert_eq!(i.e_shentsize() as usize, SHDR64_BYTES);
    assert_eq!(i.e_shnum(), 1);
    assert_eq!(i.e_shstrndx(), 0);
    assert_eq!(i.phdr_count(), PN_XNUM as u64, "sh_info carries the real count");
}

#[test]
fn past_the_escape_every_mapping_still_has_a_header() {
    let n = PN_XNUM as usize + 3;
    let segs = many(n);
    let img = build(&segs);
    let i = Image::new(&img);
    assert_eq!(i.e_phnum(), PN_XNUM);
    assert_eq!(i.phdr_count() as usize, n + 1);
    assert_eq!(i.phdr(0).ty, PT_NOTE);
    assert_eq!(i.phdr(n).ty, PT_LOAD);
    assert_eq!(i.phdr(n).vaddr, segs[n - 1].start);
    assert_eq!(i.phdr(n).vaddr, segs[n - 1].start);
}

#[test]
fn the_escape_section_header_is_otherwise_empty() {
    let segs = many(PN_XNUM as usize);
    let img = build(&segs);
    let i = Image::new(&img);
    let o = i.e_shoff() as usize;
    let sh = &img[o..o + SHDR64_BYTES];
    assert_eq!(u32::from_le_bytes(sh[0..4].try_into().unwrap()), 0, "sh_name");
    assert_eq!(u32::from_le_bytes(sh[4..8].try_into().unwrap()), SHT_NULL);
    assert_eq!(u64::from_le_bytes(sh[8..16].try_into().unwrap()), 0, "sh_flags");
    assert_eq!(u64::from_le_bytes(sh[16..24].try_into().unwrap()), 0, "sh_addr");
    assert_eq!(u64::from_le_bytes(sh[24..32].try_into().unwrap()), 0, "sh_offset");
    assert_eq!(u64::from_le_bytes(sh[32..40].try_into().unwrap()), 1, "sh_size is the count");
    assert_eq!(u32::from_le_bytes(sh[40..44].try_into().unwrap()), 0, "sh_link");
    assert_eq!(img.len(), o + SHDR64_BYTES, "the section header closes the file");
}

#[test]
fn the_section_header_follows_the_memory_half() {
    let mut segs = many(PN_XNUM as usize);
    segs[0].dump_size = CORE_PAGE_SIZE;
    let img = build(&segs);
    let i = Image::new(&img);
    let last = i.phdr(1);
    assert_eq!(last.filesz, CORE_PAGE_SIZE);
    assert_eq!(i.e_shoff(), last.offset + last.filesz);
}
