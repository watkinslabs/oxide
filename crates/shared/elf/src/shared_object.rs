//! Validated ELF64 shared-object metadata for native Unixlib loading.

use alloc::vec::Vec;
use crate::dynamic::{parse_dynamic, read_strtab_bytes, DynInfo};
use crate::parser::{ElfError, ElfType, ParsedElf};

/// One ET_DYN image whose PT_LOAD and PT_DYNAMIC ranges are safe to map.
/// Mapping and relocation remain owned by the address-space loader; this type
/// carries the single validated metadata view into both operations.
#[derive(Debug)]
pub struct SharedObject<'a> {
    pub parsed: ParsedElf<'a>,
    pub dynamic: DynInfo,
}

/// Parse a native shared object and validate the dynamic tables needed before
/// any mapping or relocation is published. # C: O(phdrs + dynamic entries)
pub fn parse_shared_object(file: &[u8], machine: u16) -> Result<SharedObject<'_>, ElfError> {
    parse_dynamic_object(file, machine, false)
}

/// Parse a dependency object. Unlike a Wine Unixlib root, a system shared
/// object may carry `PT_INTERP`; the dependency boundary records it for the
/// later Linux-shaped runtime rather than silently treating it as a Unixlib.
/// # C: O(phdrs + dynamic entries)
pub fn parse_dependency_object(file: &[u8], machine: u16) -> Result<SharedObject<'_>, ElfError> {
    parse_dynamic_object(file, machine, true)
}

fn parse_dynamic_object(file: &[u8], machine: u16, allow_interp: bool) -> Result<SharedObject<'_>, ElfError> {
    let parsed = crate::parser::parse(file, machine)?;
    if parsed.elf_type != ElfType::Dyn || (!allow_interp && parsed.interp.is_some()) { return Err(ElfError::Einval); }
    let (dynamic_off, dynamic_size) = parsed.dynamic.ok_or(ElfError::Einval)?;
    let dynamic = parse_dynamic(file, dynamic_off as usize, dynamic_size as usize)?;
    let strtab = dynamic.strtab_addr.ok_or(ElfError::Einval)?;
    let strsz = dynamic.strtab_size.ok_or(ElfError::Einval)?;
    if !vaddr_range_in_loads(&parsed, strtab, strsz) { return Err(ElfError::Einval); }
    if let (Some(rela), Some(size), Some(ent)) = (dynamic.rela_addr, dynamic.rela_size, dynamic.rela_ent) {
        if ent != 24 || size % ent != 0 || !vaddr_range_in_loads(&parsed, rela, size) { return Err(ElfError::Einval); }
    }
    if let Some(symtab) = dynamic.symtab_addr {
        let syment = dynamic.syment.ok_or(ElfError::Einval)?;
        if syment != 24 || !vaddr_range_in_loads(&parsed, symtab, syment) { return Err(ElfError::Einval); }
    }
    if let (Some(relr), Some(size), Some(ent)) = (dynamic.relr_addr, dynamic.relr_size, dynamic.relr_ent) {
        if ent != 8 || size % ent != 0 || !vaddr_range_in_loads(&parsed, relr, size) { return Err(ElfError::Einval); }
    }
    Ok(SharedObject { parsed, dynamic })
}

/// Return the direct `DT_NEEDED` names from the one validated dynamic scope.
/// The string table and every offset are checked against file-backed bytes;
/// no caller can turn a dynamic pointer into an unchecked file read.
/// # C: O(dynamic entries + dependency-name bytes)
pub fn needed_names(file: &[u8], object: &SharedObject<'_>) -> Result<Vec<Vec<u8>>, ElfError> {
    let table = object.dynamic.strtab_addr.ok_or(ElfError::Einval)?;
    let size = object.dynamic.strtab_size.ok_or(ElfError::Einval)?;
    let off = vaddr_to_file(&object.parsed, table, size).ok_or(ElfError::Einval)?;
    let strings = file.get(off..off.checked_add(size as usize).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
    object.dynamic.needed.iter().map(|offset| read_strtab_bytes(strings, *offset)).collect()
}

/// Return the object's advertised `DT_SONAME`, when present.
/// # C: O(name length)
pub fn soname(file: &[u8], object: &SharedObject<'_>) -> Result<Option<Vec<u8>>, ElfError> {
    let Some(offset) = object.dynamic.soname_off else { return Ok(None) };
    let table = object.dynamic.strtab_addr.ok_or(ElfError::Einval)?;
    let size = object.dynamic.strtab_size.ok_or(ElfError::Einval)?;
    let off = vaddr_to_file(&object.parsed, table, size).ok_or(ElfError::Einval)?;
    let strings = file.get(off..off.checked_add(size as usize).ok_or(ElfError::Einval)?).ok_or(ElfError::Einval)?;
    Ok(Some(read_strtab_bytes(strings, offset)?))
}

fn vaddr_range_in_loads(parsed: &ParsedElf<'_>, start: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(size) else { return false };
    parsed.loads.iter().any(|load| start >= load.vaddr && end <= load.vaddr.saturating_add(load.mem_sz))
}

fn vaddr_to_file(parsed: &ParsedElf<'_>, address: u64, size: u64) -> Option<usize> {
    let end = address.checked_add(size)?;
    parsed.loads.iter().find_map(|load| {
        let seg_end = load.vaddr.checked_add(load.file_sz)?;
        if address >= load.vaddr && end <= seg_end {
            load.file_off.checked_add(address - load.vaddr)?.try_into().ok()
        } else { None }
    })
}

#[cfg(test)]
mod tests {
    use super::{needed_names, parse_shared_object, soname};
    use crate::parser::EM_X86_64;

    #[test]
    fn installed_wine_vulkan_unixlib_has_valid_dynamic_metadata() {
        let paths = ["/usr/lib64/wine/x86_64-unix/winevulkan.so", "/usr/lib/wine/x86_64-unix/winevulkan.so"];
        let Some(path) = paths.iter().find(|path| std::path::Path::new(path).is_file()) else { return };
        let bytes = std::fs::read(path).unwrap();
        let object = parse_shared_object(&bytes, EM_X86_64).unwrap();
        assert!(object.dynamic.strtab_addr.is_some());
        assert!(!object.parsed.loads.is_empty());
        assert!(!needed_names(&bytes, &object).unwrap().is_empty());
        assert!(soname(&bytes, &object).unwrap().is_some());
    }
}
