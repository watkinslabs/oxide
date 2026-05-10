// Hosted tests for the ELF parser. Synthetic ELF byte arrays cover
// invariants 1-3 (`31§2`).

extern crate alloc;
use super::*;
use crate::parser::*;

use alloc::vec;
use alloc::vec::Vec;

const PHENT: usize = 56;
const EHDR_SIZE: usize = 64;

/// Build a minimal ELF64 LE file with `phdrs` program headers right
/// after the header. Each phdr is 56 bytes per ELF spec.
fn build_elf(
    elf_type: ElfType,
    machine:  u16,
    entry:    u64,
    phdrs:    &[[u8; PHENT]],
) -> Vec<u8> {
    let phnum = phdrs.len() as u16;
    let mut buf = vec![0u8; EHDR_SIZE + phdrs.len() * PHENT];

    buf[0..4].copy_from_slice(&EI_MAG);
    buf[4] = ELFCLASS64;
    buf[5] = ELFDATA2LSB;
    buf[6] = EV_CURRENT;
    buf[7] = ELFOSABI_SYSV;

    buf[16..18].copy_from_slice(&(elf_type as u16).to_le_bytes());
    buf[18..20].copy_from_slice(&machine.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());      // e_version
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    buf[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
    buf[40..48].copy_from_slice(&0u64.to_le_bytes());      // e_shoff
    buf[48..52].copy_from_slice(&0u32.to_le_bytes());      // e_flags
    buf[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());     // e_phentsize
    buf[56..58].copy_from_slice(&phnum.to_le_bytes());     // e_phnum

    for (i, ph) in phdrs.iter().enumerate() {
        let base = EHDR_SIZE + i * PHENT;
        buf[base..base + PHENT].copy_from_slice(ph);
    }
    buf
}

fn pload(file_off: u64, file_sz: u64, mem_sz: u64, vaddr: u64, flags: u32, align: u64) -> [u8; PHENT] {
    let mut p = [0u8; PHENT];
    p[0..4]  .copy_from_slice(&(PType::Load as u32).to_le_bytes());
    p[4..8]  .copy_from_slice(&flags.to_le_bytes());
    p[8..16] .copy_from_slice(&file_off.to_le_bytes());
    p[16..24].copy_from_slice(&vaddr.to_le_bytes());        // p_vaddr
    p[24..32].copy_from_slice(&vaddr.to_le_bytes());        // p_paddr (== vaddr in v1)
    p[32..40].copy_from_slice(&file_sz.to_le_bytes());
    p[40..48].copy_from_slice(&mem_sz.to_le_bytes());
    p[48..56].copy_from_slice(&align.to_le_bytes());
    p
}

fn pinterp(file_off: u64, file_sz: u64) -> [u8; PHENT] {
    let mut p = [0u8; PHENT];
    p[0..4]  .copy_from_slice(&(PType::Interp as u32).to_le_bytes());
    p[8..16] .copy_from_slice(&file_off.to_le_bytes());
    p[32..40].copy_from_slice(&file_sz.to_le_bytes());
    p[40..48].copy_from_slice(&file_sz.to_le_bytes());
    p
}

fn pgnustack(flags: u32) -> [u8; PHENT] {
    let mut p = [0u8; PHENT];
    p[0..4].copy_from_slice(&(PType::GnuStack as u32).to_le_bytes());
    p[4..8].copy_from_slice(&flags.to_le_bytes());
    p
}

// ---------------------------------------------------------------------------
// Header validation (invariant 1)
// ---------------------------------------------------------------------------

#[test]
fn rejects_short_file() {
    let buf = vec![0u8; 16];
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn rejects_bad_magic() {
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0, &[]);
    buf[0] = 0;
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn rejects_wrong_class() {
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0, &[]);
    buf[4] = 1; // ELFCLASS32
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn rejects_wrong_endian() {
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0, &[]);
    buf[5] = 2; // big endian
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn rejects_wrong_machine() {
    let buf = build_elf(ElfType::Dyn, EM_AARCH64, 0, &[]);
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn rejects_relocatable_and_core_types() {
    let buf = build_elf(ElfType::Rel, EM_X86_64, 0, &[]);
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
    let buf = build_elf(ElfType::Core, EM_X86_64, 0, &[]);
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Enoexec));
}

#[test]
fn accepts_dyn_pie() {
    let buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &[]);
    let p = parse(&buf, EM_X86_64).unwrap();
    assert_eq!(p.elf_type, ElfType::Dyn);
    assert!(p.is_pie());
    assert_eq!(p.entry, 0x1000);
    assert!(p.loads.is_empty());
}

#[test]
fn accepts_exec_with_warning_flag() {
    let buf = build_elf(ElfType::Exec, EM_X86_64, 0x40_1000, &[]);
    let p = parse(&buf, EM_X86_64).unwrap();
    assert_eq!(p.elf_type, ElfType::Exec);
    assert!(!p.is_pie(), "ET_EXEC must report not-PIE so caller can warn");
}

// ---------------------------------------------------------------------------
// Program-header walking (PT_LOAD + PT_INTERP)
// ---------------------------------------------------------------------------

#[test]
fn walks_pt_load_segments() {
    let phdrs = [
        pload(0,     4096, 4096, 0x1000, PFlags::R.bits() | PFlags::X.bits(), 0x1000),
        pload(0x1000, 8192, 8192, 0x2000, PFlags::R.bits() | PFlags::W.bits(), 0x1000),
    ];
    // Pad to phdr extents.
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    if buf.len() < 0x3000 { buf.resize(0x3000, 0); }
    let p = parse(&buf, EM_X86_64).unwrap();
    assert_eq!(p.loads.len(), 2);
    assert_eq!(p.loads[0].flags, PFlags::R | PFlags::X);
    assert_eq!(p.loads[1].flags, PFlags::R | PFlags::W);
    assert_eq!(p.loads[0].vaddr, 0x1000);
    assert_eq!(p.loads[1].vaddr, 0x2000);
}

#[test]
fn rejects_pt_load_with_w_and_x() {
    let phdrs = [
        pload(0, 4096, 4096, 0x1000,
              PFlags::R.bits() | PFlags::W.bits() | PFlags::X.bits(),
              0x1000),
    ];
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    if buf.len() < 0x2000 { buf.resize(0x2000, 0); }
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Einval));
}

#[test]
fn rejects_pt_load_filesz_exceeds_memsz() {
    let phdrs = [pload(0, 4096, 1024, 0x1000, PFlags::R.bits(), 0x1000)];
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    if buf.len() < 0x2000 { buf.resize(0x2000, 0); }
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Einval));
}

#[test]
fn rejects_pt_load_off_past_file_end() {
    let phdrs = [pload(0x10_0000, 4096, 4096, 0x1000, PFlags::R.bits(), 0x1000)];
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    if buf.len() < 0x2000 { buf.resize(0x2000, 0); }
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Einval));
}

#[test]
fn extracts_pt_interp_path() {
    // Place interp string at file offset 0x1000.
    let interp_off: u64 = 0x1000;
    let interp_str = b"/lib/ld-oxide.so.1\0";
    let phdrs = [pinterp(interp_off, interp_str.len() as u64)];
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0x2000, &phdrs);
    buf.resize(interp_off as usize + interp_str.len(), 0);
    buf[interp_off as usize..interp_off as usize + interp_str.len()]
        .copy_from_slice(interp_str);
    let p = parse(&buf, EM_X86_64).unwrap();
    assert_eq!(p.interp.unwrap(), b"/lib/ld-oxide.so.1");
}

#[test]
fn pt_gnu_stack_executable_rejected() {
    let phdrs = [pgnustack(PFlags::R.bits() | PFlags::W.bits() | PFlags::X.bits())];
    let buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Einval));
}

#[test]
fn pt_gnu_stack_non_executable_ok() {
    let phdrs = [pgnustack(PFlags::R.bits() | PFlags::W.bits())];
    let buf = build_elf(ElfType::Dyn, EM_X86_64, 0x1000, &phdrs);
    let p = parse(&buf, EM_X86_64).unwrap();
    assert!(p.loads.is_empty());
}

#[test]
fn aarch64_machine_check() {
    let buf = build_elf(ElfType::Dyn, EM_AARCH64, 0, &[]);
    let p = parse(&buf, EM_AARCH64).unwrap();
    assert_eq!(p.machine, EM_AARCH64);
}

#[test]
fn truncated_phdr_table_is_einval() {
    // Build an ELF claiming 4 phdrs but truncate before the end of the
    // table.
    let mut buf = build_elf(ElfType::Dyn, EM_X86_64, 0, &[]);
    buf[56..58].copy_from_slice(&4u16.to_le_bytes()); // e_phnum = 4
    // No actual phdr bytes; table_end > file.len().
    assert_eq!(parse(&buf, EM_X86_64).err(), Some(ElfError::Einval));
}
