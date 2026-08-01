// Read the image back and check that every offset it publishes names bytes the
// file actually contains. A core file whose headers disagree with its body is
// worse than no core file: a debugger reports confident nonsense.

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::build::CORE_PAGE_SIZE;
use crate::coredump::elf::layout::CoreArch;
use crate::coredump::elf::uapi::{EHDR64_BYTES, PT_LOAD, PT_NOTE};

fn audit(img: &[u8]) {
    let i = Image::new(img);
    assert!(img.len() >= EHDR64_BYTES);
    let n = i.phdr_count();
    assert!(
        i.e_phoff() + n * i.e_phentsize() as u64 <= img.len() as u64,
        "the header table is inside the file",
    );
    let mut notes_seen = 0;
    let mut prev_end = 0u64;
    for k in 0..n as usize {
        let p = i.phdr(k);
        assert!(p.offset + p.filesz <= img.len() as u64, "phdr {k} names bytes past the end");
        match p.ty {
            PT_NOTE => { notes_seen += 1; assert_eq!(k, 0) }
            PT_LOAD => {
                assert!(p.filesz <= p.memsz, "phdr {k} claims more file than memory");
                assert_eq!(p.align, CORE_PAGE_SIZE);
                assert!(p.offset >= prev_end, "phdr {k} overlaps its predecessor");
                prev_end = p.offset + p.filesz;
                assert!(p.offset >= i.header_bytes());
            }
            other => panic!("unexpected program header type {other}"),
        }
    }
    assert_eq!(notes_seen, 1, "exactly one note segment");
    // Re-splitting the note segment must consume it exactly; a padding mistake
    // shows up here as a leftover or an overrun.
    let total: usize = i.notes().iter()
        .map(|nt| crate::coredump::elf::notes::note_bytes(&nt.name, nt.desc.len()))
        .sum();
    assert_eq!(total as u64, i.phdr(0).filesz);
}

#[test]
fn the_x86_image_is_internally_consistent() { audit(&fixture::image(CoreArch::X86_64)) }

#[test]
fn the_aarch64_image_is_internally_consistent() { audit(&fixture::image(CoreArch::Aarch64)) }

#[test]
fn the_two_arches_differ_only_where_the_register_file_does() {
    let x = fixture::image(CoreArch::X86_64);
    let a = fixture::image(CoreArch::Aarch64);
    let (ix, ia) = (Image::new(&x), Image::new(&a));
    assert_eq!(ix.e_phnum(), ia.e_phnum());
    assert_eq!(ix.notes().len(), ia.notes().len());
    let gap = CoreArch::Aarch64.prstatus_bytes() - CoreArch::X86_64.prstatus_bytes();
    // Two threads, so the wider register file lands twice.
    assert_eq!(ia.phdr(0).filesz - ix.phdr(0).filesz,
               (2 * gap + (CoreArch::Aarch64.fpregset_bytes() - CoreArch::X86_64.fpregset_bytes()))
                   as u64);
}

#[test]
fn a_rebuild_of_the_same_input_is_byte_identical() {
    assert_eq!(fixture::image(CoreArch::X86_64), fixture::image(CoreArch::X86_64));
}

#[test]
fn the_image_is_never_shorter_than_its_headers_and_notes() {
    let img = fixture::image(CoreArch::Aarch64);
    let i = Image::new(&img);
    assert!(img.len() as u64 >= i.phdr(0).offset + i.phdr(0).filesz);
}
