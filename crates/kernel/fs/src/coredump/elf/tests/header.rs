// The ELF header a debugger validates before it reads anything else.

use super::fixture;
use super::reader::Image;
use crate::coredump::elf::layout::CoreArch;
use crate::coredump::elf::uapi::{
    EHDR64_BYTES, EI_CLASS, EI_DATA, EI_OSABI, EI_VERSION, ELFCLASS64, ELFDATA2LSB,
    ELFOSABI_SYSV, ELF_MAGIC, EM_AARCH64, EM_X86_64, ET_CORE, EV_CURRENT, PHDR64_BYTES, PT_LOAD,
    PT_NOTE,
};

#[test]
fn ident_is_little_endian_lp64_sysv() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    assert_eq!(&i.ident()[..4], &ELF_MAGIC);
    assert_eq!(i.ident()[EI_CLASS], ELFCLASS64);
    assert_eq!(i.ident()[EI_DATA], ELFDATA2LSB);
    assert_eq!(i.ident()[EI_VERSION], EV_CURRENT);
    assert_eq!(i.ident()[EI_OSABI], ELFOSABI_SYSV);
    assert!(i.ident()[8..].iter().all(|b| *b == 0), "ident pad is zero");
}

#[test]
fn type_is_core_and_entry_unset() {
    let img = fixture::image(CoreArch::Aarch64);
    let i = Image::new(&img);
    assert_eq!(i.e_type(), ET_CORE);
    assert_eq!(i.e_version(), EV_CURRENT as u32);
    assert_eq!(i.e_entry(), 0);
    assert_eq!(i.e_flags(), 0);
}

#[test]
fn machine_follows_the_register_file() {
    assert_eq!(Image::new(&fixture::image(CoreArch::X86_64)).e_machine(), EM_X86_64);
    assert_eq!(Image::new(&fixture::image(CoreArch::Aarch64)).e_machine(), EM_AARCH64);
}

#[test]
fn header_sizes_are_the_lp64_ones() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    assert_eq!(i.e_ehsize() as usize, EHDR64_BYTES);
    assert_eq!(i.e_phentsize() as usize, PHDR64_BYTES);
    assert_eq!(i.e_phoff() as usize, EHDR64_BYTES);
}

#[test]
fn one_program_header_per_mapping_plus_the_notes() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    assert_eq!(i.e_phnum() as usize, fixture::segments().len() + 1);
    assert_eq!(i.phdr(0).ty, PT_NOTE, "notes lead the table");
    for n in 1..i.e_phnum() as usize { assert_eq!(i.phdr(n).ty, PT_LOAD) }
}

#[test]
fn no_section_table_without_the_escape() {
    let img = fixture::image(CoreArch::X86_64);
    let i = Image::new(&img);
    assert_eq!(i.e_shoff(), 0);
    assert_eq!(i.e_shentsize(), 0);
    assert_eq!(i.e_shnum(), 0);
    assert_eq!(i.e_shstrndx(), 0);
}

#[test]
fn note_segment_follows_the_header_table() {
    for arch in [CoreArch::X86_64, CoreArch::Aarch64] {
        let img = fixture::image(arch);
        let i = Image::new(&img);
        let note = i.phdr(0);
        assert_eq!(note.offset, i.header_bytes());
        assert_eq!(note.vaddr, 0);
        assert_eq!(note.paddr, 0);
        assert_eq!(note.memsz, 0, "a note segment occupies no address space");
        assert_eq!(note.flags, 0);
        assert!(note.filesz > 0);
    }
}
