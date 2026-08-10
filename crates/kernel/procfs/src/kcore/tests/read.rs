// Provenance for offset-addressable reads: a consumer seeks, so every read
// must answer for the offset it was given.

use super::*;
use crate::kcore::{layout, notes, Map, Region};

const HHDM: u64 = 0xFFFF_8000_0000_0000;
const TEXT: u64 = 0xFFFF_FFFF_8000_0000;
const RAM_LEN: u64 = 0x4000;
const TEXT_LEN: u64 = 0x2000;

fn map() -> Map {
    Map {
        page_offset: HHDM,
        machine: layout::EM_X86_64,
        regions: alloc::vec![
            Region { vaddr: HHDM, size: RAM_LEN, paddr: Some(0) },
            Region { vaddr: TEXT, size: TEXT_LEN, paddr: Some(0x20_0000) },
        ],
        notes: notes::segment(notes::PRSTATUS_SIZE_X86_64, b"quiet", "1.2.3", 4096, TEXT),
    }
}

/// Stand-in for live memory: byte `i` of a region reads as a value derived from
/// its ADDRESS, so a read from the wrong place is visible in the bytes.
fn fetch(vaddr: u64, dst: &mut [u8]) {
    for (i, b) in dst.iter_mut().enumerate() { *b = (vaddr.wrapping_add(i as u64) & 0xFF) as u8; }
}

fn expect_mem(vaddr: u64, len: usize) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; len];
    fetch(vaddr, &mut v);
    v
}

#[test]
fn a_read_at_zero_returns_the_elf_header() {
    let m = map();
    let mut buf = [0u8; 64];
    assert_eq!(read_at(&m, 0, &mut buf, fetch), 64);
    assert_eq!(&buf[..], &layout::ehdr(m.machine, layout::phnum(&m.regions))[..]);
}

#[test]
fn a_read_starting_mid_header_returns_that_offsets_bytes_and_not_the_start() {
    // The failure this pins: a read that ignores its offset and always
    // restarts at zero. A consumer that seeked to the program-header table
    // would get the ELF header back and read `\x7fELF` as a `p_type`.
    let m = map();
    let whole = header_bytes(&m);
    for at in [1usize, 63, 64, 71, 200] {
        let mut buf = [0u8; 24];
        assert_eq!(read_at(&m, at as u64, &mut buf, fetch), 24);
        assert_eq!(&buf[..], &whole[at..at + 24], "read at {at}");
    }
}

#[test]
fn the_program_header_table_and_the_notes_are_where_the_header_says() {
    let m = map();
    let table_at = layout::PHDR_OFF;
    let notes_at = layout::notes_offset(&m.regions);
    let mut buf = alloc::vec![0u8; m.notes.len()];
    assert_eq!(read_at(&m, notes_at as u64, &mut buf, fetch), m.notes.len());
    assert_eq!(buf, m.notes);

    let mut phdrs = alloc::vec![0u8; notes_at - table_at];
    assert_eq!(read_at(&m, table_at as u64, &mut phdrs, fetch), phdrs.len());
    assert_eq!(phdrs, layout::phdr_table(&m));
}

#[test]
fn a_described_region_reads_its_own_bytes_at_the_offset_its_header_gives() {
    let m = map();
    let data = layout::data_offset(&m.regions, m.notes.len());
    for r in m.regions.iter() {
        let at = layout::offset_of(m.page_offset, data, r.vaddr);
        let mut buf = alloc::vec![0u8; 32];
        assert_eq!(read_at(&m, at, &mut buf, fetch), 32);
        assert_eq!(buf, expect_mem(r.vaddr, 32));
        // And from the middle of the region, which is what a seek to a
        // specific kernel address produces.
        let mid = at + r.size / 2;
        assert_eq!(read_at(&m, mid, &mut buf, fetch), 32);
        assert_eq!(buf, expect_mem(r.vaddr + r.size / 2, 32));
    }
}

#[test]
fn a_read_in_a_hole_returns_zeroes_rather_than_a_short_read() {
    // The address space between two described regions is not an error: a
    // consumer stepping across the gap must get zeroes and keep going.
    let m = map();
    let data = layout::data_offset(&m.regions, m.notes.len());
    let hole = layout::offset_of(m.page_offset, data, HHDM + RAM_LEN + 0x1000);
    let mut buf = [0xFFu8; 64];
    assert_eq!(read_at(&m, hole, &mut buf, fetch), 64);
    assert!(buf.iter().all(|&b| b == 0), "a hole must read as zeroes");
}

#[test]
fn a_read_spanning_a_regions_end_returns_its_bytes_then_zeroes() {
    let m = map();
    let data = layout::data_offset(&m.regions, m.notes.len());
    let at = layout::offset_of(m.page_offset, data, HHDM + RAM_LEN - 16);
    let mut buf = [0xFFu8; 48];
    assert_eq!(read_at(&m, at, &mut buf, fetch), 48);
    assert_eq!(&buf[..16], &expect_mem(HHDM + RAM_LEN - 16, 16)[..]);
    assert!(buf[16..].iter().all(|&b| b == 0));
}

#[test]
fn a_read_spanning_the_header_boundary_joins_the_description_to_the_memory() {
    let m = map();
    let data = layout::data_offset(&m.regions, m.notes.len());
    let at = data - 8;
    let mut buf = [0xFFu8; 24];
    assert_eq!(read_at(&m, at, &mut buf, fetch), 24);
    assert_eq!(&buf[..8], &header_bytes(&m)[at as usize..]);
    // The first described region begins exactly at the data offset.
    assert_eq!(&buf[8..], &expect_mem(HHDM, 16)[..]);
}

#[test]
fn a_read_at_or_past_the_end_of_the_file_returns_nothing() {
    let m = map();
    let size = layout::file_size(&m);
    let mut buf = [0xFFu8; 16];
    assert_eq!(read_at(&m, size, &mut buf, fetch), 0);
    assert_eq!(read_at(&m, size + 4096, &mut buf, fetch), 0);
    // A read that straddles the end is clipped to what the file holds.
    assert_eq!(read_at(&m, size - 4, &mut buf, fetch), 4);
}

#[test]
fn the_header_prefix_is_exactly_as_long_as_the_data_offset() {
    // These two are computed separately and every described address depends on
    // them agreeing; a byte of drift shifts the whole memory area.
    let m = map();
    assert_eq!(header_bytes(&m).len() as u64,
        layout::data_offset(&m.regions, m.notes.len()));
}
