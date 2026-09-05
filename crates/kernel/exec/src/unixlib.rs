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

mod context;
mod loader;
pub use context::{build_load_context, UnixlibLoadContext, UnixlibSourceObject};
pub use loader::{map_load_context, MappedUnixlibObject};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MappedUnixlib {
    pub base: u64,
    pub end: u64,
}

/// Decode and validate the relocated Unixlib function-pointer table. `image`
/// covers `[image_base,image_end)`, while each executable range is an image
/// range already admitted by the ELF loader. No pointer is dereferenced.
/// # C: O(entry_count + executable_ranges)
pub fn decode_callable_table(image: &[u8], image_base: u64, image_end: u64,
    table_offset: u64, entry_count: u64, executable_ranges: &[(u64, u64)])
    -> Result<Vec<u64>, crate::elf_modules::UnixlibRegistrationError>
{
    if image_base >= image_end || image.len() as u64 != image_end - image_base || entry_count == 0 {
        return Err(crate::elf_modules::UnixlibRegistrationError::InvalidRange);
    }
    let table_address = image_base.checked_add(table_offset)
        .ok_or(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow)?;
    let bytes = entry_count.checked_mul(core::mem::size_of::<u64>() as u64)
        .ok_or(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow)?;
    let table_end = table_address.checked_add(bytes)
        .ok_or(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow)?;
    if table_address < image_base || table_end > image_end { return Err(crate::elf_modules::UnixlibRegistrationError::InvalidRange); }
    let start = (table_address - image_base) as usize;
    let end = start.checked_add(bytes as usize)
        .ok_or(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow)?;
    let table = image.get(start..end).ok_or(crate::elf_modules::UnixlibRegistrationError::InvalidRange)?;
    let mut entries = Vec::with_capacity(entry_count as usize);
    for slot in table.chunks_exact(core::mem::size_of::<u64>()) {
        let entry = u64::from_le_bytes(slot.try_into().unwrap());
        if entry == 0 || !executable_ranges.iter().any(|(begin, end)| entry >= *begin && entry < *end) {
            return Err(crate::elf_modules::UnixlibRegistrationError::InvalidRange);
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Register a decoded callable table exported by a mapped Unixlib. `table_offset`
/// is the value of `__wine_unix_call_funcs` in the ELF symbol scope; `entries`
/// came from [`decode_callable_table`] after relocation and validation.
/// # C: O(entry_count)
pub fn register_callable_table(as_: &AddressSpace, image: MappedUnixlib, table_offset: u64,
    entries: &[u64], executable_ranges: &[(u64, u64)]) -> Result<crate::elf_modules::ElfUnixlibDescriptor,
    crate::elf_modules::UnixlibRegistrationError>
{
    let table_address = image.base.checked_add(table_offset)
        .ok_or(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow)?;
    let descriptor = crate::elf_modules::ElfUnixlibDescriptor {
        table_address, entry_count: entries.len() as u64, module_base: image.base, module_end: image.end,
        entries: entries.to_vec(),
        executable_ranges: executable_ranges.to_vec(),
    };
    crate::elf_modules::register_unixlib_table(as_, descriptor.clone())?;
    Ok(descriptor)
}

/// One admitted native object. The loader publishes this transaction only
/// after the complete dependency closure has been parsed and ordered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixlibDependency {
    pub name: Vec<u8>,
    pub soname: Option<Vec<u8>>,
    pub needed: Vec<Vec<u8>>,
    pub exports: Vec<UnixlibExport>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixlibExport {
    pub name: Vec<u8>,
    pub value: u64,
}

/// Admit one ET_DYN Unixlib and its transitive `DT_NEEDED` closure. `open`
/// is the canonical VFS/catalog lookup supplied by the caller. The result is
/// dependency-first and is not published until every node succeeds; missing
/// names, duplicate identity, malformed metadata, and cycles abort atomically.
/// # C: O(objects * (dynamic entries + symbols))
pub fn admit_dependency_closure<F>(root_name: &[u8], root_file: &[u8], mut open: F)
    -> Result<Vec<UnixlibDependency>, LoadError>
where F: FnMut(&[u8]) -> Option<Vec<u8>> {
    let mut active = Vec::new();
    let mut done = Vec::new();
    let mut result = Vec::new();
    admit_one(root_name, root_file, true, &mut open, &mut active, &mut done, &mut result)?;
    Ok(result)
}

fn admit_one<F>(name: &[u8], file: &[u8], root: bool, open: &mut F, active: &mut Vec<Vec<u8>>,
    done: &mut Vec<Vec<u8>>, result: &mut Vec<UnixlibDependency>) -> Result<(), LoadError>
where F: FnMut(&[u8]) -> Option<Vec<u8>> {
    if active.iter().any(|seen| seen.as_slice() == name) { return Err(LoadError::Einval); }
    if done.iter().any(|seen| seen.as_slice() == name) { return Ok(()); }
    let object = if root { parse_shared_object(file, ARCH_MACHINE) }
        else { elf::parse_dependency_object(file, ARCH_MACHINE) }
        .map_err(LoadError::from)?;
    let needed = elf::needed_names(file, &object).map_err(LoadError::from)?;
    active.push(name.to_vec());
    for dependency in &needed {
        let bytes = open(dependency).ok_or(LoadError::Enoexec)?;
        admit_one(dependency, &bytes, false, open, active, done, result)?;
    }
    active.pop();
    let exports = match elf::collect_dynamic_symbols(file, &object) {
        Ok(symbols) => symbols.into_iter().map(|symbol| UnixlibExport {
            name: symbol.name.to_vec(), value: symbol.value,
        }).collect(),
        // A library without a dynamic hash has no safely enumerable export
        // scope. It remains admissible for code that has no relocations.
        Err(elf::ElfError::Einval) if object.dynamic.hash_addr.is_none() && object.dynamic.gnu_hash_addr.is_none() => Vec::new(),
        Err(error) => return Err(LoadError::from(error)),
    };
    let soname = elf::soname(file, &object).map_err(LoadError::from)?;
    done.push(name.to_vec());
    result.push(UnixlibDependency { name: name.to_vec(), soname, needed, exports });
    Ok(())
}

/// Resolve an export in an already admitted, dependency-first scope. The
/// caller adds the mapped object's load bias; no address is published here.
/// # C: O(objects * exports)
pub fn resolve_admitted_symbol(scope: &[UnixlibDependency], name: &[u8]) -> Option<u64> {
    scope.iter().find_map(|object| object.exports.iter()
        .find(|export| export.name.as_slice() == name && export.value != 0).map(|export| export.value))
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

    #[test]
    fn admitted_symbol_scope_resolves_exact_export_and_has_lifecycle_boundary() {
        let scope = vec![UnixlibDependency {
            name: b"ntdll.so".to_vec(), soname: None, needed: Vec::new(),
            exports: vec![UnixlibExport { name: b"__wine_unix_call_funcs".to_vec(), value: 0x2400 }],
        }];
        assert_eq!(resolve_admitted_symbol(&scope, b"__wine_unix_call_funcs"), Some(0x2400));
        assert_eq!(resolve_admitted_symbol(&scope, b"__WINE_UNIX_CALL_FUNCS"), None);
        let released = scope;
        assert_eq!(released.len(), 1);
        drop(released);
    }

    #[test]
    fn admitted_symbol_scope_rejects_a_null_callable_export() {
        let scope = vec![UnixlibDependency {
            name: b"winevulkan.so".to_vec(), soname: None, needed: Vec::new(),
            exports: vec![UnixlibExport { name: b"__wine_unix_call_funcs".to_vec(), value: 0 }],
        }];
        assert_eq!(resolve_admitted_symbol(&scope, b"__wine_unix_call_funcs"), None);
    }

    #[test]
    fn source_context_is_dependency_first_and_root_last() {
        let context = UnixlibLoadContext { root_name: b"root.so".to_vec(), objects: vec![
            UnixlibSourceObject { name: b"dep.so".to_vec(), path: b"/wine/dep.so".to_vec(), file: vec![1] },
            UnixlibSourceObject { name: b"root.so".to_vec(), path: b"/wine/root.so".to_vec(), file: vec![2] },
        ] };
        assert_eq!(context.validate(), Ok(()));
    }

    #[test]
    fn source_context_rejects_duplicate_names_and_noncanonical_sources() {
        let duplicate = UnixlibLoadContext { root_name: b"root.so".to_vec(), objects: vec![
            UnixlibSourceObject { name: b"dep.so".to_vec(), path: b"/wine/dep.so".to_vec(), file: vec![1] },
            UnixlibSourceObject { name: b"root.so".to_vec(), path: b"/wine/root.so".to_vec(), file: vec![2] },
            UnixlibSourceObject { name: b"root.so".to_vec(), path: b"/wine/root-copy.so".to_vec(), file: vec![3] },
        ] };
        assert_eq!(duplicate.validate(), Err(LoadError::Einval));
        let relative = UnixlibLoadContext { root_name: b"root.so".to_vec(), objects: vec![
            UnixlibSourceObject { name: b"root.so".to_vec(), path: b"root.so".to_vec(), file: vec![1] },
        ] };
        assert_eq!(relative.validate(), Err(LoadError::Einval));
    }

    #[test]
    fn callable_table_registration_uses_loaded_image_bounds() {
        let as_ = AddressSpace::new(0x7_2500).unwrap();
        let image = MappedUnixlib { base: 0x40_000, end: 0x41_000 };
        let entries = (0..8).map(|index| image.base + 0x100 + index * 8).collect::<Vec<_>>();
        let executable = [(image.base + 0x100, image.end)];
        let descriptor = register_callable_table(&as_, image, 0x800, &entries, &executable).unwrap();
        assert_eq!(descriptor.table_address, 0x40_800);
        assert_eq!(crate::elf_modules::unixlib_descriptor(as_.root_pa()), Some(descriptor.clone()));
        assert_eq!(register_callable_table(&as_, image, 0x800, &entries, &executable), Ok(descriptor));
        crate::elf_modules::clear(as_.root_pa());
    }

    #[test]
    fn callable_table_registration_rejects_outside_and_overflow_ranges() {
        let as_ = AddressSpace::new(0x7_2600).unwrap();
        let image = MappedUnixlib { base: 0x50_000, end: 0x51_000 };
        assert_eq!(register_callable_table(&as_, image, 0x1000, &[0x5010], &[(0x5010, 0x5100)]),
            Err(crate::elf_modules::UnixlibRegistrationError::InvalidRange));
        assert_eq!(register_callable_table(&as_, image, u64::MAX - image.base + 1, &[0x5010], &[(0x5010, 0x5100)]),
            Err(crate::elf_modules::UnixlibRegistrationError::ArithmeticOverflow));
        crate::elf_modules::clear(as_.root_pa());
    }

    #[test]
    fn callable_table_registration_rejects_a_second_identity() {
        let as_ = AddressSpace::new(0x7_2700).unwrap();
        let image = MappedUnixlib { base: 0x60_000, end: 0x61_000 };
        let entries = (0..8).map(|index| image.base + 0x100 + index * 8).collect::<Vec<_>>();
        let executable = [(image.base + 0x100, image.end)];
        let _ = register_callable_table(&as_, image, 0x200, &entries, &executable).unwrap();
        assert_eq!(register_callable_table(&as_, image, 0x300, &entries, &executable),
            Err(crate::elf_modules::UnixlibRegistrationError::AlreadyRegistered));
        crate::elf_modules::clear(as_.root_pa());
    }

    #[test]
    fn callable_table_decode_admits_only_executable_relocated_targets() {
        let mut image = vec![0u8; 0x100];
        image[0x20..0x28].copy_from_slice(&0x4080u64.to_le_bytes());
        image[0x28..0x30].copy_from_slice(&0x4090u64.to_le_bytes());
        assert_eq!(decode_callable_table(&image, 0x4000, 0x4100, 0x20, 2,
            &[(0x4080, 0x40a0)]).unwrap(), vec![0x4080, 0x4090]);
    }

    #[test]
    fn callable_table_decode_rejects_null_data_and_truncated_slots() {
        let mut image = vec![0u8; 0x28];
        image[0x20..0x28].copy_from_slice(&0x4030u64.to_le_bytes());
        assert!(decode_callable_table(&image, 0x4000, 0x4028, 0x20, 1,
            &[(0x4020, 0x4028)]).is_err());
        assert!(decode_callable_table(&image, 0x4000, 0x4028, 0x20, 2,
            &[(0x4020, 0x4028)]).is_err());
        image[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        assert!(decode_callable_table(&image, 0x4000, 0x4028, 0x20, 1,
            &[(0x4020, 0x4028)]).is_err());
    }

    #[test]
    fn dependency_admission_rejects_missing_library_before_mapping() {
        let Some(bytes) = installed_unixlib() else { return };
        let result = admit_dependency_closure(b"winevulkan.so", &bytes, |_| None);
        assert_eq!(result, Err(LoadError::Enoexec));
    }

    #[test]
    fn dependency_admission_rejects_cycle_before_publishing_scope() {
        let Some(bytes) = installed_unixlib() else { return };
        let result = admit_dependency_closure(b"winevulkan.so", &bytes, |_| Some(bytes.clone()));
        assert_eq!(result, Err(LoadError::Einval));
    }

    #[test]
    fn dependency_admission_rejects_malformed_needed_offset() {
        let Some(mut bytes) = installed_unixlib() else { return };
        let object = parse_shared_object(&bytes, ARCH_MACHINE).unwrap();
        assert!(object.parsed.dynamic.is_some());
        let (dynamic, size) = object.parsed.dynamic.unwrap();
        let mut offset = dynamic as usize;
        let end = offset + size as usize;
        let mut found = false;
        while offset + 16 <= end {
            let tag = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            if tag == elf::DT_NEEDED {
                bytes[offset + 8..offset + 16].copy_from_slice(&u64::MAX.to_le_bytes());
                found = true;
                break;
            }
            if tag == elf::DT_NULL { break; }
            offset += 16;
        }
        assert!(found);
        assert!(admit_dependency_closure(b"winevulkan.so", &bytes, |_| None).is_err());
    }

    #[test]
    fn dependency_admission_orders_real_wine_closure_dependency_first() {
        let Some(root) = installed_unixlib() else { return };
        let scope = admit_dependency_closure(b"winevulkan.so", &root, |name| {
            let text = core::str::from_utf8(name).ok()?;
            let paths = [
                alloc::format!("/usr/lib64/wine/x86_64-unix/{text}"),
                alloc::format!("/usr/lib/wine/x86_64-unix/{text}"),
                alloc::format!("/usr/lib64/{text}"),
                alloc::format!("/usr/lib/{text}"),
                alloc::format!("/usr/lib/x86_64-linux-gnu/{text}"),
                alloc::format!("/lib64/{text}"),
                alloc::format!("/lib/{text}"),
            ];
            paths.iter().find_map(|path| std::fs::read(path).ok())
        }).unwrap();
        assert!(!scope.is_empty());
        assert_eq!(scope.last().unwrap().name, b"winevulkan.so");
        assert!(scope.iter().all(|object| object.name != b""));
    }

    #[test]
    fn source_context_carries_real_wine_paths_for_the_entire_closure() {
        let Some(root) = installed_unixlib() else { return };
        let root_path = b"/usr/lib64/wine/x86_64-unix/winevulkan.so";
        let context = build_load_context(b"winevulkan.so", root_path, &root, |name| {
            let text = core::str::from_utf8(name).ok()?;
            let paths = [
                alloc::format!("/usr/lib64/wine/x86_64-unix/{text}"),
                alloc::format!("/usr/lib/wine/x86_64-unix/{text}"),
                alloc::format!("/usr/lib64/{text}"), alloc::format!("/usr/lib/{text}"),
                alloc::format!("/usr/lib/x86_64-linux-gnu/{text}"),
                alloc::format!("/lib64/{text}"), alloc::format!("/lib/{text}"),
            ];
            paths.iter().find_map(|path| std::fs::read(path).ok().map(|file| (path.as_bytes().to_vec(), file)))
        }).unwrap();
        assert_eq!(context.objects.last().unwrap().name, b"winevulkan.so");
        assert_eq!(context.objects.last().unwrap().path, root_path);
        assert!(context.objects.iter().all(|object| object.path.first() == Some(&b'/')));
    }

    fn installed_unixlib() -> Option<Vec<u8>> {
        let paths = [
            "/usr/lib64/wine/x86_64-unix/winevulkan.so",
            "/usr/lib/wine/x86_64-unix/winevulkan.so",
        ];
        paths.iter().find_map(|path| std::fs::read(path).ok())
    }
}
