// Byte-level provenance for the description `/proc/kcore` emits.

use super::*;
use crate::kcore::{Map, Region};

fn u16_at(b: &[u8], at: usize) -> u16 { u16::from_le_bytes([b[at], b[at + 1]]) }
fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }

const HHDM: u64 = 0xFFFF_8000_0000_0000;
const TEXT: u64 = 0xFFFF_FFFF_8000_0000;

fn map() -> Map {
    Map {
        page_offset: HHDM,
        machine: EM_X86_64,
        regions: alloc::vec![
            Region { vaddr: TEXT, size: 0x20_0000, paddr: Some(0x20_0000) },
            Region { vaddr: HHDM, size: 0x1000_0000, paddr: Some(0) },
            Region { vaddr: HHDM + 0x8000_0000, size: 0x1000, paddr: None },
        ],
        notes: alloc::vec![0xAAu8; 300],
    }
}

#[test]
fn the_elf_header_identifies_a_little_endian_sixty_four_bit_core() {
    let h = ehdr(EM_X86_64, 4);
    assert_eq!(&h[0..4], &ELF_MAG);
    assert_eq!(h[4], ELFCLASS64);
    assert_eq!(h[5], ELFDATA2LSB);
    assert_eq!(h[6], EV_CURRENT as u8);
    assert_eq!(h[7], ELFOSABI_NONE);
    // A file typed as anything but a core sends the reader looking for a
    // section table and an entry point that a running kernel does not have.
    assert_eq!(u16_at(&h, 16), ET_CORE);
    assert_eq!(u16_at(&h, 18), EM_X86_64);
    assert_eq!(u32_at(&h, 20), EV_CURRENT);
    assert_eq!(u64_at(&h, 24), 0, "a core has no entry point");
    assert_eq!(u64_at(&h, 40), 0, "a core has no section table");
}

#[test]
fn the_header_field_offsets_and_sizes_are_the_sixty_four_bit_ones() {
    // Each of these is read at a fixed offset by every consumer. A field one
    // slot early does not fail to parse; it parses as the neighbouring value.
    let h = ehdr(EM_AARCH64, 9);
    assert_eq!(h.len(), EHDR_SIZE);
    assert_eq!(EHDR_SIZE, 64);
    assert_eq!(PHDR_SIZE, 56);
    assert_eq!(u64_at(&h, 32), PHDR_OFF as u64, "e_phoff");
    assert_eq!(u16_at(&h, 52), EHDR_SIZE as u16, "e_ehsize");
    assert_eq!(u16_at(&h, 54), PHDR_SIZE as u16, "e_phentsize");
    assert_eq!(u16_at(&h, 56), 9, "e_phnum");
    assert_eq!(u16_at(&h, 18), EM_AARCH64);
}

#[test]
fn the_program_header_count_offset_and_entry_size_agree_with_the_table() {
    let m = map();
    let h = ehdr(m.machine, phnum(&m.regions));
    let table = phdr_table(&m);
    let count = u16_at(&h, 56) as usize;
    let entry = u16_at(&h, 54) as usize;
    let at = u64_at(&h, 32) as usize;
    // Mutual consistency is the invariant a reader relies on: it walks
    // `e_phnum` entries of `e_phentsize` bytes starting at `e_phoff`, and
    // must land exactly on the end of the table.
    assert_eq!(count, 1 + m.regions.len());
    assert_eq!(count * entry, table.len());
    assert_eq!(at + table.len(), notes_offset(&m.regions));
}

#[test]
fn the_first_program_header_is_the_note_segment() {
    let m = map();
    let table = phdr_table(&m);
    assert_eq!(u32_at(&table, 0), PT_NOTE);
    assert_eq!(u64_at(&table, 8), notes_offset(&m.regions) as u64, "p_offset");
    assert_eq!(u64_at(&table, 32), m.notes.len() as u64, "p_filesz");
}

#[test]
fn each_region_becomes_one_load_segment_carrying_both_addresses() {
    let m = map();
    let table = phdr_table(&m);
    let data = data_offset(&m.regions, m.notes.len());
    for (i, r) in m.regions.iter().enumerate() {
        let p = &table[(i + 1) * PHDR_SIZE..(i + 2) * PHDR_SIZE];
        assert_eq!(u32_at(p, 0), PT_LOAD);
        assert_eq!(u32_at(p, 4), PF_RWX);
        assert_eq!(u64_at(p, 8), offset_of(m.page_offset, data, r.vaddr), "p_offset");
        assert_eq!(u64_at(p, 16), r.vaddr, "p_vaddr");
        // A region with no physical address reports all-ones, NOT zero: zero
        // is a real physical address and a consumer would read it as one.
        assert_eq!(u64_at(p, 24), r.paddr.unwrap_or(PADDR_NONE), "p_paddr");
        assert_eq!(u64_at(p, 32), r.size, "p_filesz");
        assert_eq!(u64_at(p, 40), r.size, "p_memsz");
        assert_eq!(u64_at(p, 48), PAGE_SIZE, "p_align");
    }
    assert_eq!(u64_at(&table[3 * PHDR_SIZE..], 24), PADDR_NONE);
}

#[test]
fn the_data_area_starts_on_a_page_after_the_header_table_and_notes() {
    let m = map();
    let data = data_offset(&m.regions, m.notes.len());
    assert!(data >= (notes_offset(&m.regions) + m.notes.len()) as u64);
    assert_eq!(data % PAGE_SIZE, 0);
    assert!(data - ((notes_offset(&m.regions) + m.notes.len()) as u64) < PAGE_SIZE);
    // An exactly-page-sized prefix must not be rounded up to the next page:
    // that shifts every described address by a page.
    let exact = data_offset(&m.regions, PAGE_SIZE as usize - notes_offset(&m.regions));
    assert_eq!(exact, PAGE_SIZE);
}

#[test]
fn an_address_and_its_file_offset_convert_back_and_forth() {
    let m = map();
    let data = data_offset(&m.regions, m.notes.len());
    for v in [HHDM, HHDM + 0x1234, TEXT, TEXT + 0xFFFF] {
        let off = offset_of(m.page_offset, data, v);
        assert_eq!(vaddr_of(m.page_offset, data, off), v);
    }
    // The mapping is linear from the base, offset by the header area — this is
    // the one subtraction a consumer performs to turn an address into a seek.
    assert_eq!(offset_of(HHDM, data, HHDM), data);
    assert_eq!(offset_of(HHDM, data, HHDM + 0x1000), data + 0x1000);
}

#[test]
fn the_file_reaches_the_end_of_the_highest_described_region() {
    let m = map();
    let data = data_offset(&m.regions, m.notes.len());
    assert_eq!(file_size(&m), offset_of(m.page_offset, data, TEXT + 0x20_0000));
    // With nothing described the file is just its header area.
    let empty = Map { page_offset: HHDM, machine: EM_X86_64,
        regions: alloc::vec![], notes: alloc::vec![] };
    assert_eq!(file_size(&empty), data_offset(&[], 0));
}
