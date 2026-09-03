//! ELF64 runtime relocation application for ET_DYN images.

use crate::parser::{ElfError, LoadSegment};
use crate::SharedObject;

pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_AARCH64_ABS64: u32 = 257;

/// Apply the dynamic relocation tables of a mapped shared object to one
/// contiguous staged image. The resolver owns process-wide symbol lookup;
/// defined symbols are resolved against this object and never call it.
/// # C: O(N_relocations)
pub fn apply_runtime_relocations<F>(
    file: &[u8], object: &SharedObject<'_>, load_bias: u64,
    image: &mut [u8], image_base: u64, mut resolve: F,
) -> Result<(), ElfError>
where F: FnMut(&[u8]) -> Option<u64> {
    let mut tables = [None, None];
    if let (Some(addr), Some(size), Some(ent)) = (object.dynamic.rela_addr, object.dynamic.rela_size, object.dynamic.rela_ent) {
        tables[0] = Some((addr, size, ent));
    }
    if let (Some(addr), Some(size), Some(kind)) = (object.dynamic.jmprel_addr, object.dynamic.pltrel_size, object.dynamic.pltrel_kind) {
        if kind != 7 { return Err(ElfError::Eopnotsupp); }
        tables[1] = Some((addr, size, object.dynamic.rela_ent.unwrap_or(0)));
    }
    for table in tables.into_iter().flatten() {
        if table.2 != 24 || table.1 % table.2 != 0 { return Err(ElfError::Einval); }
        let count = table.1 / table.2;
        for index in 0..count {
            let entry = table.0.checked_add(index.checked_mul(table.2).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
            let off = vaddr_to_file(object.parsed.loads.as_slice(), entry, 24).ok_or(ElfError::Einval)?;
            let r_offset = u64_at(file, off)?;
            let info = u64_at(file, off + 8)?;
            let addend = i64_at(file, off + 16)?;
            let kind = info as u32;
            let sym_index = info >> 32;
            let target = load_bias.checked_add(r_offset).ok_or(ElfError::Einval)?;
            let dest = target.checked_sub(image_base).ok_or(ElfError::Einval)? as usize;
            let value = match kind {
                R_X86_64_RELATIVE => load_bias.wrapping_add(addend as u64),
                R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_AARCH64_ABS64 => {
                    let symbol = read_dynamic_symbol(file, object, sym_index)?;
                    if !symbol.defined { resolve(symbol.name).ok_or(ElfError::Einval)? } else { load_bias.checked_add(symbol.value).ok_or(ElfError::Einval)? }
                        .wrapping_add(addend as u64)
                }
                _ => return Err(ElfError::Eopnotsupp),
            };
            let slot = image.get_mut(dest..dest.checked_add(8).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
            slot.copy_from_slice(&value.to_le_bytes());
        }
    }
    if let (Some(addr), Some(size), Some(ent)) = (object.dynamic.relr_addr, object.dynamic.relr_size, object.dynamic.relr_ent) {
        if ent != 8 || size % ent != 0 { return Err(ElfError::Einval); }
        let count = size / ent;
        let mut index = 0;
        let mut next = 0u64;
        while index < count {
            let entry_addr = addr.checked_add(index.checked_mul(ent).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
            let off = vaddr_to_file(object.parsed.loads.as_slice(), entry_addr, 8).ok_or(ElfError::Einval)?;
            let entry = u64_at(file, off)?;
            if entry & 1 == 0 {
                next = entry.checked_add(8).ok_or(ElfError::Einval)?;
                apply_relative(image, image_base, load_bias, entry)?;
            } else {
                for bit in 1..64 {
                    if entry & (1u64 << bit) != 0 { apply_relative(image, image_base, load_bias, next)?; }
                    next = next.checked_add(8).ok_or(ElfError::Einval)?;
                }
            }
            index += 1;
        }
    }
    Ok(())
}

fn apply_relative(image: &mut [u8], image_base: u64, load_bias: u64, offset: u64) -> Result<(), ElfError> {
    let target = load_bias.checked_add(offset).ok_or(ElfError::Einval)?;
    let dest = target.checked_sub(image_base).ok_or(ElfError::Einval)? as usize;
    let slot = image.get_mut(dest..dest.checked_add(8).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
    let addend = u64::from_le_bytes(slot.try_into().unwrap());
    slot.copy_from_slice(&load_bias.wrapping_add(addend).to_le_bytes());
    Ok(())
}

/// One validated dynamic symbol. Undefined symbols require resolution from
/// the process ELF catalog; defined symbols are relative to this object.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DynamicSymbol<'a> { pub name: &'a [u8], pub value: u64, pub defined: bool }

/// Read one symbol from the validated object's dynamic symbol table.
/// # C: O(1)
pub fn read_dynamic_symbol<'a>(file: &'a [u8], object: &SharedObject<'_>, index: u64) -> Result<DynamicSymbol<'a>, ElfError> {
    let dynamic = &object.dynamic;
    let loads = object.parsed.loads.as_slice();
    let table = dynamic.symtab_addr.ok_or(ElfError::Einval)?;
    let syment = dynamic.syment.ok_or(ElfError::Einval)?;
    if syment != 24 { return Err(ElfError::Einval); }
    let address = table.checked_add(index.checked_mul(syment).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
    let off = vaddr_to_file(loads, address, 24).ok_or(ElfError::Einval)?;
    let name_off = u32_at(file, off)? as u64;
    let shndx = u16_at(file, off + 6)?;
    let value = u64_at(file, off + 8)?;
    let strtab = dynamic.strtab_addr.ok_or(ElfError::Einval)?;
    let strsz = dynamic.strtab_size.ok_or(ElfError::Einval)?;
    let str_off = vaddr_to_file(loads, strtab, strsz).ok_or(ElfError::Einval)?;
    let name = file.get(str_off..str_off.checked_add(strsz as usize).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
    let start = name_off as usize;
    let end = name.get(start..).ok_or(ElfError::Einval)?.iter().position(|b| *b == 0).map(|n| start + n).ok_or(ElfError::Einval)?;
    Ok(DynamicSymbol { name: &name[start..end], value, defined: shndx != 0 })
}

fn vaddr_to_file(loads: &[LoadSegment], address: u64, size: u64) -> Option<usize> {
    loads.iter().find_map(|seg| {
        let end = address.checked_add(size)?;
        let seg_end = seg.vaddr.checked_add(seg.file_sz)?;
        if address >= seg.vaddr && end <= seg_end { seg.file_off.checked_add(address - seg.vaddr)?.try_into().ok() } else { None }
    })
}

fn u16_at(file: &[u8], off: usize) -> Result<u16, ElfError> { Ok(u16::from_le_bytes(file.get(off..off + 2).ok_or(ElfError::Einval)?.try_into().unwrap())) }
fn u32_at(file: &[u8], off: usize) -> Result<u32, ElfError> { Ok(u32::from_le_bytes(file.get(off..off + 4).ok_or(ElfError::Einval)?.try_into().unwrap())) }
fn u64_at(file: &[u8], off: usize) -> Result<u64, ElfError> { Ok(u64::from_le_bytes(file.get(off..off + 8).ok_or(ElfError::Einval)?.try_into().unwrap())) }
fn i64_at(file: &[u8], off: usize) -> Result<i64, ElfError> { Ok(i64::from_le_bytes(file.get(off..off + 8).ok_or(ElfError::Einval)?.try_into().unwrap())) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_relative_entry_adds_bias_to_existing_addend() {
        let mut image = [0u8; 0x110];
        image[0x100..0x108].copy_from_slice(&0x24u64.to_le_bytes());
        apply_relative(&mut image, 0x4000, 0x4000, 0x100).unwrap();
        assert_eq!(u64::from_le_bytes(image[0x100..0x108].try_into().unwrap()), 0x4024);
    }

    #[test]
    fn virtual_dynamic_table_address_maps_only_inside_file_bytes() {
        let loads = [LoadSegment { flags: crate::parser::PFlags::R, file_off: 0x200, file_sz: 0x80, vaddr: 0x1000, mem_sz: 0x1000, align: 0x1000 }];
        assert_eq!(vaddr_to_file(&loads, 0x1010, 16), Some(0x210));
        assert_eq!(vaddr_to_file(&loads, 0x1078, 16), None);
    }
}
