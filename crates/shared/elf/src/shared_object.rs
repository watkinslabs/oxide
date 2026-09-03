//! Validated ELF64 shared-object metadata for native Unixlib loading.

use crate::dynamic::{parse_dynamic, DynInfo};
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
    let parsed = crate::parser::parse(file, machine)?;
    if parsed.elf_type != ElfType::Dyn || parsed.interp.is_some() { return Err(ElfError::Einval); }
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
    Ok(SharedObject { parsed, dynamic })
}

fn vaddr_range_in_loads(parsed: &ParsedElf<'_>, start: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(size) else { return false };
    parsed.loads.iter().any(|load| start >= load.vaddr && end <= load.vaddr.saturating_add(load.mem_sz))
}

#[cfg(test)]
mod tests {
    use super::parse_shared_object;
    use crate::parser::EM_X86_64;

    #[test]
    fn installed_wine_vulkan_unixlib_has_valid_dynamic_metadata() {
        let paths = ["/usr/lib64/wine/x86_64-unix/winevulkan.so", "/usr/lib/wine/x86_64-unix/winevulkan.so"];
        let Some(path) = paths.iter().find(|path| std::path::Path::new(path).is_file()) else { return };
        let bytes = std::fs::read(path).unwrap();
        let object = parse_shared_object(&bytes, EM_X86_64).unwrap();
        assert!(object.dynamic.strtab_addr.is_some());
        assert!(!object.parsed.loads.is_empty());
    }
}
