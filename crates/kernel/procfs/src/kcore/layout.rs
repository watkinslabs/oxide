// The ELF file `/proc/kcore` presents: header fields, the program-header
// table, and the offset arithmetic that ties the two together.
//
// Every byte here is consumed by a debugger that seeks. A field written at the
// wrong offset does not fail to parse — it parses as a DIFFERENT value, and the
// tool reads kernel memory from an address that is not the one it asked for.
// So the field offsets, the entry sizes, and the mutual consistency of
// `e_phoff`/`e_phentsize`/`e_phnum` with the table that follows are pinned by
// test rather than by inspection.

extern crate alloc;
use alloc::vec::Vec;

use super::{Map, Region};

/// 64-bit ELF header size, and `e_ehsize`.
pub const EHDR_SIZE: usize = 64;
/// 64-bit program-header entry size, and `e_phentsize`.
pub const PHDR_SIZE: usize = 56;
/// `e_phoff`: the table starts immediately after the header.
pub const PHDR_OFF: usize = EHDR_SIZE;

/// `e_ident` magic and the four class/data/version/osabi selectors.
pub const ELF_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// Two's-complement little-endian. Both target arches run little-endian.
pub const ELFDATA2LSB: u8 = 1;
/// `EV_CURRENT`, in both `e_ident` and `e_version`.
pub const EV_CURRENT: u32 = 1;
/// `ELFOSABI_NONE`.
pub const ELFOSABI_NONE: u8 = 0;

/// `e_type`: a core file. A debugger that saw an executable here would look
/// for a section table and an entry point that this file does not have.
pub const ET_CORE: u16 = 4;
/// `e_machine` values for the two target arches.
pub const EM_X86_64: u16 = 62;
/// See [`EM_X86_64`].
pub const EM_AARCH64: u16 = 183;

/// `p_type` values used by this file.
pub const PT_LOAD: u32 = 1;
/// See [`PT_LOAD`].
pub const PT_NOTE: u32 = 4;

/// `p_flags`. Every described region is reported readable, writable and
/// executable: the file describes the kernel's own address space, in which the
/// distinction belongs to the page tables and not to this description.
pub const PF_X: u32 = 1;
/// See [`PF_X`].
pub const PF_W: u32 = 2;
/// See [`PF_X`].
pub const PF_R: u32 = 4;
/// See [`PF_X`].
pub const PF_RWX: u32 = PF_R | PF_W | PF_X;

/// `p_paddr` for a region that has no physical address.
pub const PADDR_NONE: u64 = u64::MAX;

/// Alignment every `PT_LOAD` reports, and the granule the data area starts on.
pub const PAGE_SIZE: u64 = hal::PAGE_SIZE_BYTES;

/// Program headers in the file: one note segment, then one per region.
/// # C: O(1)
pub fn phnum(regions: &[Region]) -> usize { 1 + regions.len() }

/// Bytes the program-header table occupies. # C: O(1)
pub fn phdrs_len(regions: &[Region]) -> usize { phnum(regions) * PHDR_SIZE }

/// File offset of the note segment's contents. # C: O(1)
pub fn notes_offset(regions: &[Region]) -> usize { PHDR_OFF + phdrs_len(regions) }

/// File offset the described memory starts at: everything before it is the
/// header, the table and the notes, rounded up to a page so a mapped read of a
/// described region is page-aligned. # C: O(1)
pub fn data_offset(regions: &[Region], notes_len: usize) -> u64 {
    let end = (notes_offset(regions) + notes_len) as u64;
    (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// File offset a kernel virtual address is read at.
///
/// The whole address space above `page_offset` is laid out linearly after the
/// header area, so the file is enormous and almost entirely holes. That is what
/// makes a seek to an address computable without consulting the table: a reader
/// converts an address to an offset with this one subtraction.
/// # C: O(1)
pub fn offset_of(page_offset: u64, data_offset: u64, vaddr: u64) -> u64 {
    vaddr.wrapping_sub(page_offset).wrapping_add(data_offset)
}

/// The address a file offset in the data area names. Inverse of [`offset_of`].
/// # C: O(1)
pub fn vaddr_of(page_offset: u64, data_offset: u64, off: u64) -> u64 {
    off.wrapping_sub(data_offset).wrapping_add(page_offset)
}

/// Total file length: the data area reaches the highest described address.
/// # C: O(N regions)
pub fn file_size(map: &Map) -> u64 {
    let data = data_offset(&map.regions, map.notes.len());
    let mut end = data;
    for r in map.regions.iter() {
        let e = offset_of(map.page_offset, data, r.vaddr.wrapping_add(r.size));
        if e > end { end = e; }
    }
    end
}

/// The ELF header. # C: O(1)
pub fn ehdr(machine: u16, phnum: usize) -> [u8; EHDR_SIZE] {
    let mut h = [0u8; EHDR_SIZE];
    h[0..4].copy_from_slice(&ELF_MAG);
    h[4] = ELFCLASS64;
    h[5] = ELFDATA2LSB;
    h[6] = EV_CURRENT as u8;
    h[7] = ELFOSABI_NONE;
    put16(&mut h, 16, ET_CORE);
    put16(&mut h, 18, machine);
    put32(&mut h, 20, EV_CURRENT);
    // e_entry (24) and e_shoff (40) stay zero: a core of a running kernel has
    // neither a start address nor a section table.
    put64(&mut h, 32, PHDR_OFF as u64);
    put16(&mut h, 52, EHDR_SIZE as u16);
    put16(&mut h, 54, PHDR_SIZE as u16);
    put16(&mut h, 56, phnum as u16);
    h
}

/// One program-header entry. # C: O(1)
#[allow(clippy::too_many_arguments)]
pub fn phdr(ptype: u32, flags: u32, offset: u64, vaddr: u64, paddr: u64,
    filesz: u64, memsz: u64, align: u64) -> [u8; PHDR_SIZE]
{
    let mut p = [0u8; PHDR_SIZE];
    put32(&mut p, 0, ptype);
    put32(&mut p, 4, flags);
    put64(&mut p, 8, offset);
    put64(&mut p, 16, vaddr);
    put64(&mut p, 24, paddr);
    put64(&mut p, 32, filesz);
    put64(&mut p, 40, memsz);
    put64(&mut p, 48, align);
    p
}

/// The whole program-header table: the note segment first, then the regions in
/// the order they were described. # C: O(N regions)
pub fn phdr_table(map: &Map) -> Vec<u8> {
    let data = data_offset(&map.regions, map.notes.len());
    let mut out = Vec::with_capacity(phdrs_len(&map.regions));
    out.extend_from_slice(&phdr(PT_NOTE, 0, notes_offset(&map.regions) as u64, 0, 0,
        map.notes.len() as u64, 0, 0));
    for r in map.regions.iter() {
        out.extend_from_slice(&phdr(PT_LOAD, PF_RWX,
            offset_of(map.page_offset, data, r.vaddr), r.vaddr,
            r.paddr.unwrap_or(PADDR_NONE), r.size, r.size, PAGE_SIZE));
    }
    out
}

fn put16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn put64(b: &mut [u8], at: usize, v: u64) { b[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

#[cfg(test)]
#[path = "tests/layout.rs"]
mod tests;
