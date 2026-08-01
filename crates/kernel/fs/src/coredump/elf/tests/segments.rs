// `PT_LOAD`: where each mapping's bytes are, and what a debugger is told about
// the ones that were not written.

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::build::CORE_PAGE_SIZE;
use crate::coredump::elf::input::{
    CoreImageError, CoreImageInput, CoreSegment, SEG_EXEC, SEG_READ, SEG_WRITE,
};
use crate::coredump::elf::layout::CoreArch;
use crate::coredump::elf::uapi::{PF_R, PF_W, PF_X};

fn build(segs: &[CoreSegment<'_>], mem: &mut impl FnMut(u64, &mut [u8]) -> usize)
    -> Result<alloc::vec::Vec<u8>, CoreImageError>
{
    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 9);
    let threads = [fixture::thread(fixture::TID_MAIN, &r, None)];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: segs, auxv: &[],
        siginfo: None,
    };
    crate::coredump::elf::build::build_core_image(&input, mem)
}

#[test]
fn mapping_headers_carry_the_address_range_and_protection() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    let segs = fixture::segments();
    for (n, s) in segs.iter().enumerate() {
        let p = i.phdr(n + 1);
        assert_eq!(p.vaddr, s.start);
        assert_eq!(p.memsz, s.memsz(), "memsz is the whole mapping");
        assert_eq!(p.filesz, s.dump_size);
        assert_eq!(p.paddr, 0);
        assert_eq!(p.align, CORE_PAGE_SIZE);
    }
    assert_eq!(i.phdr(1).flags, PF_R | PF_X);
    assert_eq!(i.phdr(2).flags, PF_R | PF_W);
    assert_eq!(i.phdr(3).flags, PF_R | PF_W);
}

#[test]
fn an_unreadable_mapping_gets_no_flags() {
    let segs = [CoreSegment {
        start: fixture::DATA_START, end: fixture::DATA_START + CORE_PAGE_SIZE,
        prot: 0, dump_size: 0, file: None,
    }];
    let mut mem = fixture::full_reader();
    let img = build(&segs, &mut mem).unwrap();
    assert_eq!(Image::new(&img).phdr(1).flags, 0);
}

#[test]
fn the_memory_half_starts_on_a_page_boundary() {
    for arch in [CoreArch::X86_64, CoreArch::Aarch64] {
        let img = fixture::image(arch);
        let i = Image::new(&img);
        let note = i.phdr(0);
        let first_data = i.phdrs().iter().find(|p| p.filesz > 0 && p.vaddr != 0).unwrap().offset;
        assert_eq!(first_data % CORE_PAGE_SIZE, 0);
        assert!(first_data >= note.offset + note.filesz);
        assert!(first_data - (note.offset + note.filesz) < CORE_PAGE_SIZE, "pad is minimal");
    }
}

#[test]
fn mapping_offsets_are_contiguous_and_skip_elided_ones() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    let text = i.phdr(1);
    let data = i.phdr(2);
    let stack = i.phdr(3);
    assert_eq!(text.filesz, 0, "the elided mapping writes nothing");
    assert_eq!(data.offset, text.offset, "an elided mapping consumes no file space");
    assert_eq!(stack.offset, data.offset + data.filesz);
    assert_eq!(img.len() as u64, stack.offset + stack.filesz, "the image ends with the last one");
}

#[test]
fn dumped_contents_are_the_bytes_at_the_mapping_address() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    let stack = i.phdr(3);
    let body = &img[stack.offset as usize..(stack.offset + stack.filesz) as usize];
    for (n, b) in body.iter().enumerate() {
        assert_eq!(*b, fixture::byte_at(fixture::STACK_START + n as u64), "byte {n}");
    }
}

#[test]
fn an_elided_mapping_writes_none_of_its_bytes() {
    let segs = [CoreSegment {
        start: fixture::DATA_START, end: fixture::DATA_START + 4 * CORE_PAGE_SIZE,
        prot: SEG_READ | SEG_WRITE, dump_size: 0, file: None,
    }];
    let mut reads = 0usize;
    let img = {
        let mut mem = |_va: u64, _buf: &mut [u8]| { reads += 1; 0 };
        build(&segs, &mut mem).unwrap()
    };
    assert_eq!(reads, 0, "an elided mapping is never read");
    let i = Image::new(&img);
    assert_eq!(i.phdr(1).filesz, 0);
    assert_eq!(i.phdr(1).memsz, 4 * CORE_PAGE_SIZE);
    assert_eq!(img.len() as u64, i.phdr(1).offset);
}

#[test]
fn a_partly_dumped_mapping_keeps_its_full_memsz() {
    // The head of a file-backed mapping is worth dumping even when its body is
    // not: it carries the object's own headers.
    let segs = [CoreSegment {
        start: fixture::TEXT_START, end: fixture::TEXT_START + 8 * CORE_PAGE_SIZE,
        prot: SEG_READ | SEG_EXEC, dump_size: CORE_PAGE_SIZE, file: None,
    }];
    let mut mem = fixture::full_reader();
    let img = build(&segs, &mut mem).unwrap();
    let i = Image::new(&img);
    assert_eq!(i.phdr(1).filesz, CORE_PAGE_SIZE);
    assert_eq!(i.phdr(1).memsz, 8 * CORE_PAGE_SIZE);
    let body = &img[i.phdr(1).offset as usize..];
    assert_eq!(body.len() as u64, CORE_PAGE_SIZE);
    assert_eq!(body[0], fixture::byte_at(fixture::TEXT_START));
}

#[test]
fn a_hole_is_zero_filled_rather_than_shortening_the_segment() {
    let hole = fixture::STACK_START + CORE_PAGE_SIZE;
    let segs = [CoreSegment {
        start: fixture::STACK_START, end: fixture::STACK_START + 3 * CORE_PAGE_SIZE,
        prot: SEG_READ | SEG_WRITE, dump_size: 3 * CORE_PAGE_SIZE, file: None,
    }];
    let mut mem = fixture::holed_reader(hole);
    let img = build(&segs, &mut mem).unwrap();
    let i = Image::new(&img);
    let p = i.phdr(1);
    assert_eq!(p.filesz, 3 * CORE_PAGE_SIZE, "the header still promises the whole mapping");
    assert_eq!(img.len() as u64, p.offset + p.filesz);
    let body = &img[p.offset as usize..];
    assert_eq!(body[0], fixture::byte_at(fixture::STACK_START));
    assert!(body[CORE_PAGE_SIZE as usize..].iter().all(|b| *b == 0), "the hole reads as zero");
}

#[test]
fn a_short_read_only_zeroes_its_own_tail() {
    let segs = [CoreSegment {
        start: fixture::DATA_START, end: fixture::DATA_START + 2 * CORE_PAGE_SIZE,
        prot: SEG_READ, dump_size: 2 * CORE_PAGE_SIZE, file: None,
    }];
    let half = CORE_PAGE_SIZE as usize / 2;
    let mut mem = |va: u64, buf: &mut [u8]| {
        for (i, b) in buf.iter_mut().take(half).enumerate() { *b = fixture::byte_at(va + i as u64) }
        half
    };
    let img = build(&segs, &mut mem).unwrap();
    let i = Image::new(&img);
    let body = &img[i.phdr(1).offset as usize..];
    assert_eq!(body[0], fixture::byte_at(fixture::DATA_START));
    assert!(body[half..CORE_PAGE_SIZE as usize].iter().all(|b| *b == 0));
    assert_eq!(body[CORE_PAGE_SIZE as usize], fixture::byte_at(fixture::DATA_START + CORE_PAGE_SIZE));
}

#[test]
fn an_overlong_read_cannot_overrun_the_segment() {
    let segs = [CoreSegment {
        start: fixture::DATA_START, end: fixture::DATA_START + CORE_PAGE_SIZE,
        prot: SEG_READ, dump_size: CORE_PAGE_SIZE, file: None,
    }];
    // A reader that lies about how much it produced must not move any offset.
    let mut mem = |_va: u64, buf: &mut [u8]| buf.len() * 2;
    let img = build(&segs, &mut mem).unwrap();
    let i = Image::new(&img);
    assert_eq!(img.len() as u64, i.phdr(1).offset + CORE_PAGE_SIZE);
}

#[test]
fn a_malformed_mapping_is_refused() {
    let mut mem = fixture::full_reader();
    let backwards = [CoreSegment {
        start: fixture::DATA_START + CORE_PAGE_SIZE, end: fixture::DATA_START,
        prot: SEG_READ, dump_size: 0, file: None,
    }];
    assert_eq!(build(&backwards, &mut mem).unwrap_err(), CoreImageError::SegmentRange);

    let unaligned = [CoreSegment {
        start: fixture::DATA_START + 1, end: fixture::DATA_START + CORE_PAGE_SIZE,
        prot: SEG_READ, dump_size: 0, file: None,
    }];
    assert_eq!(build(&unaligned, &mut mem).unwrap_err(), CoreImageError::SegmentAlign);

    let too_much = [CoreSegment {
        start: fixture::DATA_START, end: fixture::DATA_START + CORE_PAGE_SIZE,
        prot: SEG_READ, dump_size: 2 * CORE_PAGE_SIZE, file: None,
    }];
    assert_eq!(build(&too_much, &mut mem).unwrap_err(), CoreImageError::SegmentDumpSize);
}

#[test]
fn a_dump_with_no_mappings_is_still_a_valid_file() {
    let mut mem = fixture::full_reader();
    let img = build(&[], &mut mem).unwrap();
    let i = Image::new(&img);
    assert_eq!(i.e_phnum(), 1);
    assert_eq!(i.notes().len(), 3, "prstatus, prpsinfo, auxv");
    assert_eq!(img.len() as u64 % CORE_PAGE_SIZE, 0, "the file still ends page-aligned");
}
