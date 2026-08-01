// `NT_FILE`: the table that lets a debugger reopen the shared libraries a crash
// happened in, instead of showing raw addresses.

use alloc::vec::Vec;

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::build::CORE_PAGE_SIZE;
use crate::coredump::elf::input::{CoreImageInput, CoreSegment};
use crate::coredump::elf::layout::CoreArch;
use crate::coredump::elf::notes;
use crate::coredump::elf::uapi::NT_FILE;

/// The table read back the way a debugger reads it.
struct Entry { start: u64, end: u64, pgoff: u64, path: Vec<u8> }

fn parse(desc: &[u8]) -> (u64, Vec<Entry>) {
    let rd = |o: usize| u64::from_le_bytes(desc[o..o + 8].try_into().unwrap());
    let count = rd(0) as usize;
    let page_size = rd(8);
    let names_off = (2 + 3 * count) * 8;
    let mut names = desc[names_off..].split(|b| *b == 0);
    let mut out = Vec::new();
    for i in 0..count {
        let o = 16 + i * 24;
        out.push(Entry {
            start: rd(o), end: rd(o + 8), pgoff: rd(o + 16),
            path: names.next().expect("one name per entry").to_vec(),
        });
    }
    (page_size, out)
}

#[test]
fn table_describes_every_file_backed_mapping_in_order() {
    let img = fixture::image(CoreArch::X86_64);
    let (page_size, ents) = parse(&Image::new(&img).note(NT_FILE).desc);
    assert_eq!(page_size, CORE_PAGE_SIZE);
    assert_eq!(ents.len(), 2, "the anonymous stack contributes no entry");
    assert_eq!(ents[0].start, fixture::TEXT_START);
    assert_eq!(ents[0].end, fixture::TEXT_START + 2 * CORE_PAGE_SIZE);
    assert_eq!(ents[0].pgoff, 0);
    assert_eq!(ents[0].path, fixture::EXE_PATH);
    assert_eq!(ents[1].start, fixture::DATA_START);
    assert_eq!(ents[1].end, fixture::DATA_START + CORE_PAGE_SIZE);
    assert_eq!(ents[1].pgoff, 7, "the offset is in pages, not bytes");
    assert_eq!(ents[1].path, fixture::LIBC_PATH);
}

#[test]
fn names_begin_where_the_table_ends() {
    let img = fixture::image(CoreArch::Aarch64);
    let d = Image::new(&img).note(NT_FILE).desc;
    let count = u64::from_le_bytes(d[..8].try_into().unwrap()) as usize;
    let names_off = (2 + 3 * count) * 8;
    assert_eq!(&d[names_off..names_off + fixture::EXE_PATH.len()], fixture::EXE_PATH);
    assert_eq!(d[names_off + fixture::EXE_PATH.len()], 0, "names are terminated");
    let tail = fixture::EXE_PATH.len() + 1 + fixture::LIBC_PATH.len() + 1;
    assert_eq!(d.len(), names_off + tail, "the descriptor ends with its last name");
}

#[test]
fn a_dump_with_no_file_backed_mapping_omits_the_note() {
    let segs = [CoreSegment {
        start: fixture::STACK_START, end: fixture::STACK_START + CORE_PAGE_SIZE,
        prot: crate::coredump::elf::input::SEG_READ, dump_size: 0, file: None,
    }];
    assert!(notes::files(CORE_PAGE_SIZE, &segs).is_none());

    let arch = CoreArch::X86_64;
    let r = fixture::regs(arch, 0);
    let threads = [fixture::thread(fixture::TID_MAIN, &r, None)];
    let input = CoreImageInput {
        arch, identity: fixture::identity(), threads: &threads, segments: &segs, auxv: &[],
        siginfo: None,
    };
    let mut mem = fixture::full_reader();
    let img = crate::coredump::elf::build::build_core_image(&input, &mut mem).unwrap();
    assert!(Image::new(&img).notes().iter().all(|n| n.ty != NT_FILE));
}

#[test]
fn an_elided_mapping_still_names_its_file() {
    // The text mapping's contents are not written, which is exactly why its
    // path has to be recorded: the debugger recovers the code from the file.
    let img = fixture::image(CoreArch::X86_64);
    let (_, ents) = parse(&Image::new(&img).note(NT_FILE).desc);
    let i = Image::new(&img);
    assert_eq!(i.phdr(1).filesz, 0);
    assert_eq!(ents[0].start, i.phdr(1).vaddr);
}

#[test]
fn the_descriptor_length_matches_its_content() {
    let segs = fixture::segments();
    let d = notes::files(CORE_PAGE_SIZE, &segs).expect("two file-backed mappings");
    let count = 2usize;
    let expect = (2 + 3 * count) * 8 + fixture::EXE_PATH.len() + 1 + fixture::LIBC_PATH.len() + 1;
    assert_eq!(d.len(), expect);
}
