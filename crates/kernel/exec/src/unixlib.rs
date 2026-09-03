//! Native ELF Unixlib placement for the Wine-compatible process boundary.
//!
//! This is deliberately separate from PE loading: a Unixlib is an ELF ET_DYN
//! image with no interpreter. The kernel chooses one contiguous arena, then
//! publishes every PT_LOAD at a fixed address with the segment's final W^X
//! protection.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use elf::{parse_shared_object, PFlags, SharedObject};
use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

use crate::{ARCH_MACHINE, LoadError, PAGE};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappedUnixlib {
    pub base: u64,
    pub end: u64,
}

/// Map a validated native Unixlib into `as_` as one contiguous ET_DYN image.
/// The input is copied into address-space-owned staging pages before this
/// function returns, so the caller may release its file buffer.
/// # C: O(phdrs + mapped bytes)
pub fn map_shared_object(file: &[u8], as_: &AddressSpace) -> Result<MappedUnixlib, LoadError> {
    let object = parse_shared_object(file, ARCH_MACHINE).map_err(LoadError::from)?;
    let (min_vaddr, max_vaddr) = mapping_span(&object).ok_or(LoadError::Einval)?;
    let span = max_vaddr.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let arena = as_.get_unmapped_area(span as usize).map_err(|_| LoadError::Enomem)?.as_u64();
    let bias = arena.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let exports = defined_exports(file, &object, bias)?;
    let mut mapped = Vec::new();

    for seg in &object.parsed.loads {
        let va = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let start = align_down(va);
        let end = align_up(va.checked_add(seg.mem_sz).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let len = end.checked_sub(start).ok_or(LoadError::Einval)? as usize;
        let file_start = seg.file_off as usize;
        let file_end = file_start.checked_add(seg.file_sz as usize).ok_or(LoadError::Einval)?;
        let source = file.get(file_start..file_end).ok_or(LoadError::Einval)?;
        let head = (va - start) as usize;
        let mut bytes = vec![0; len];
        let copy = source.len().min(len.saturating_sub(head));
        bytes[head..head + copy].copy_from_slice(&source[..copy]);
        let prot = segment_protection(seg.flags);
        let addr = UserVirtAddr::new(start).ok_or(LoadError::Einval)?;
        if as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(addr), len, prot, prot,
            VmaFlags::PRIVATE, VmaBacking::KernelBytes { data: as_.stash_bytes(bytes.into_boxed_slice()), off: 0 })
            .is_err() {
            for (at, size) in mapped { let _ = as_.munmap(at, size); }
            return Err(LoadError::Enomem);
        }
        mapped.push((addr, len));
    }
    crate::elf_modules::append_symbols(as_, &exports);
    Ok(MappedUnixlib { base: bias, end: max_vaddr.checked_add(bias).ok_or(LoadError::Einval)? })
}

/// Map a Unixlib after applying every supported dynamic relocation to the
/// complete staged image. No segment is published when relocation or symbol
/// resolution fails.
/// # C: O(phdrs + mapped bytes + relocations)
pub fn map_shared_object_with_resolver<F>(
    file: &[u8], as_: &AddressSpace, resolver: F,
) -> Result<MappedUnixlib, LoadError>
where F: FnMut(&[u8]) -> Option<u64> {
    let object = parse_shared_object(file, ARCH_MACHINE).map_err(LoadError::from)?;
    let (min_vaddr, max_vaddr) = mapping_span(&object).ok_or(LoadError::Einval)?;
    let span = max_vaddr.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let arena = as_.get_unmapped_area(span as usize).map_err(|_| LoadError::Enomem)?.as_u64();
    let bias = arena.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let image_base = bias.checked_add(min_vaddr).ok_or(LoadError::Einval)?;
    let mut image = vec![0; span as usize];
    for seg in &object.parsed.loads {
        let va = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let start = align_down(va);
        let image_start = start.checked_sub(image_base).ok_or(LoadError::Einval)? as usize;
        let end = align_up(va.checked_add(seg.mem_sz).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let len = end.checked_sub(start).ok_or(LoadError::Einval)? as usize;
        let source_start = seg.file_off as usize;
        let source_end = source_start.checked_add(seg.file_sz as usize).ok_or(LoadError::Einval)?;
        let source = file.get(source_start..source_end).ok_or(LoadError::Einval)?;
        let target = image.get_mut(image_start..image_start.checked_add(len).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let head = (va - start) as usize;
        let copy = source.len().min(len.saturating_sub(head));
        target[head..head + copy].copy_from_slice(&source[..copy]);
    }
    elf::apply_runtime_relocations(file, &object, bias, &mut image, image_base, resolver)
        .map_err(LoadError::from)?;
    let exports = defined_exports(file, &object, bias)?;
    let mut mapped = Vec::new();
    for seg in &object.parsed.loads {
        let va = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let start = align_down(va);
        let end = align_up(va.checked_add(seg.mem_sz).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let image_start = start.checked_sub(image_base).ok_or(LoadError::Einval)? as usize;
        let len = end.checked_sub(start).ok_or(LoadError::Einval)? as usize;
        let bytes = image.get(image_start..image_start.checked_add(len).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?.to_vec();
        let addr = UserVirtAddr::new(start).ok_or(LoadError::Einval)?;
        let prot = segment_protection(seg.flags);
        if as_.mmap_with_may_at(MmapPlacement::FixedNoReplace(addr), len, prot, prot,
            VmaFlags::PRIVATE, VmaBacking::KernelBytes { data: as_.stash_bytes(bytes.into_boxed_slice()), off: 0 }).is_err() {
            for (at, size) in mapped { let _ = as_.munmap(at, size); }
            return Err(LoadError::Enomem);
        }
        mapped.push((addr, len));
    }
    crate::elf_modules::append_symbols(as_, &exports);
    Ok(MappedUnixlib { base: bias, end: max_vaddr.checked_add(bias).ok_or(LoadError::Einval)? })
}

fn defined_exports(file: &[u8], object: &SharedObject<'_>, bias: u64)
    -> Result<Vec<crate::elf_modules::ElfRuntimeSymbol>, LoadError>
{
    let Ok(symbols) = elf::collect_dynamic_symbols(file, object) else { return Ok(Vec::new()) };
    symbols.into_iter().map(|symbol| {
        Ok(crate::elf_modules::ElfRuntimeSymbol {
            name: symbol.name.to_vec(),
            address: bias.checked_add(symbol.value).ok_or(LoadError::Einval)?,
        })
    }).collect()
}

fn mapping_span(object: &SharedObject<'_>) -> Option<(u64, u64)> {
    let min = object.parsed.loads.iter().map(|s| align_down(s.vaddr)).min()?;
    let max = object.parsed.loads.iter().filter_map(|s| s.vaddr.checked_add(s.mem_sz).and_then(align_up)).max()?;
    Some((min, max))
}

fn segment_protection(flags: PFlags) -> VmaProt {
    let mut prot = VmaProt::empty();
    if flags.contains(PFlags::R) { prot |= VmaProt::READ; }
    if flags.contains(PFlags::W) { prot |= VmaProt::WRITE; }
    if flags.contains(PFlags::X) { prot |= VmaProt::EXEC; }
    prot
}

fn align_down(v: u64) -> u64 { v & !(PAGE - 1) }
fn align_up(v: u64) -> Option<u64> { v.checked_add(PAGE - 1).map(|v| v & !(PAGE - 1)) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_preserves_elf_flags() {
        assert_eq!(segment_protection(PFlags::R | PFlags::X), VmaProt::READ | VmaProt::EXEC);
        assert_eq!(segment_protection(PFlags::R | PFlags::W), VmaProt::READ | VmaProt::WRITE);
    }

    #[test]
    fn installed_wine_vulkan_unixlib_maps_as_one_image() {
        let paths = ["/usr/lib64/wine/x86_64-unix/winevulkan.so", "/usr/lib/wine/x86_64-unix/winevulkan.so"];
        let Some(path) = paths.iter().find(|path| std::path::Path::new(path).is_file()) else { return };
        let bytes = std::fs::read(path).unwrap();
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let image = map_shared_object(&bytes, &as_).unwrap();
        assert!(image.base < image.end);
        assert_eq!(image.end - image.base, 0xb2_000);
    }

    #[test]
    fn resolver_aware_mapping_rejects_unresolved_wine_imports() {
        let paths = ["/usr/lib64/wine/x86_64-unix/winevulkan.so", "/usr/lib/wine/x86_64-unix/winevulkan.so"];
        let Some(path) = paths.iter().find(|path| std::path::Path::new(path).is_file()) else { return };
        let bytes = std::fs::read(path).unwrap();
        let as_ = AddressSpace::new(0x20_000).unwrap();
        assert!(map_shared_object_with_resolver(&bytes, &as_, |_| None).is_err());
        assert_eq!(as_.vma_count(), 0);
    }
}
