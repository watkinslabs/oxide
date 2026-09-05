//! Atomic publication of a validated native Unixlib dependency context.

extern crate alloc;

use alloc::vec::Vec;
use elf::{parse_shared_object, PFlags, SharedObject};
use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

use super::{UnixlibLoadContext, UnixlibSourceObject};
use crate::{ARCH_MACHINE, LoadError, PAGE};
use crate::elf_modules::ElfRuntimeSymbol;

/// One context object after it has been mapped into the owning address space.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappedUnixlibObject {
    pub name: Vec<u8>,
    pub path: Vec<u8>,
    pub image: super::MappedUnixlib,
    mapped_start: u64,
}

/// Consume a validated dependency-first context and publish all images in one
/// address space. Staging, relocation, and VMA insertion are one transaction:
/// an error removes every VMA inserted by this call and does not alter the
/// existing ELF symbol catalog. The caller owns the fixed Wine ABI envelope;
/// this function only consumes its canonical source objects.
/// # C: O(objects * (phdrs + bytes + relocations + symbols))
pub fn map_load_context(
    context: &UnixlibLoadContext, as_: &AddressSpace,
) -> Result<Vec<MappedUnixlibObject>, LoadError> {
    context.validate()?;
    let mut mapped = Vec::new();
    let mut scope = Vec::new();
    for source in &context.objects {
        let result = map_object(source, as_, &scope);
        let (image, exports, mapped_start) = match result {
            Ok(value) => value,
            Err(error) => {
                rollback(as_, &mapped);
                return Err(error);
            }
        };
        scope.extend(exports.iter().cloned());
        mapped.push(MappedUnixlibObject {
            name: source.name.clone(), path: source.path.clone(), mapped_start,
            image,
        });
    }
    // Publication is deliberately last. The registry update takes one lock
    // and cannot fail, so no partially admitted scope can be observed.
    super::super::elf_modules::append_symbols(as_, &scope);
    Ok(mapped)
}

fn map_object(
    source: &UnixlibSourceObject, as_: &AddressSpace, scope: &[ElfRuntimeSymbol],
) -> Result<(super::MappedUnixlib, Vec<ElfRuntimeSymbol>, u64), LoadError> {
    let object = parse_shared_object(&source.file, ARCH_MACHINE).map_err(LoadError::from)?;
    let (min_vaddr, max_vaddr) = mapping_span(&object).ok_or(LoadError::Einval)?;
    let span = max_vaddr.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let span_len: usize = span.try_into().map_err(|_| LoadError::Einval)?;
    let arena = as_.get_unmapped_area(span_len).map_err(|_| LoadError::Enomem)?.as_u64();
    let bias = arena.checked_sub(min_vaddr).ok_or(LoadError::Einval)?;
    let mut image = Vec::new();
    image.try_reserve(span_len).map_err(|_| LoadError::Enomem)?;
    image.resize(span_len, 0);
    copy_loads(&source.file, &object, bias, arena, &mut image)?;
    elf::apply_runtime_relocations(
        &source.file, &object, bias, &mut image, arena,
        |name| scope.iter().find(|symbol| symbol.name.as_slice() == name)
            .map(|symbol| symbol.address),
    ).map_err(LoadError::from)?;
    let exports = defined_exports(&source.file, &object, bias)?;
    let addr = UserVirtAddr::new(arena).ok_or(LoadError::Einval)?;
    let may = object.parsed.loads.iter().fold(VmaProt::empty(), |all, seg| {
        all | segment_protection(seg.flags)
    });
    if as_.mmap_with_may_at(
        MmapPlacement::FixedNoReplace(addr), span_len, VmaProt::empty(), may,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes {
            data: as_.stash_bytes(image.into_boxed_slice()), off: 0,
        },
    ).is_err() {
        return Err(LoadError::Enomem);
    }
    let mut finalized = 0usize;
    for seg in &object.parsed.loads {
        let va = seg.vaddr.checked_add(bias).ok_or_else(|| {
            let _ = as_.munmap(addr, span_len); LoadError::Einval
        })?;
        let start = align_down(va);
        let end = align_up(va.checked_add(seg.mem_sz).ok_or_else(|| {
            let _ = as_.munmap(addr, span_len); LoadError::Einval
        })?).ok_or_else(|| {
            let _ = as_.munmap(addr, span_len); LoadError::Einval
        })?;
        let len: usize = end.checked_sub(start).ok_or(LoadError::Einval)?
            .try_into().map_err(|_| LoadError::Einval)?;
        if as_.mprotect(UserVirtAddr::new(start).ok_or(LoadError::Einval)?, len,
            segment_protection(seg.flags)).is_err() {
            let _ = as_.munmap(addr, span_len);
            return Err(LoadError::Einval);
        }
        finalized += 1;
    }
    if finalized == 0 { let _ = as_.munmap(addr, span_len); return Err(LoadError::Einval); }
    Ok((super::MappedUnixlib { base: bias, end: max_vaddr.checked_add(bias).ok_or(LoadError::Einval)? }, exports, arena))
}

fn copy_loads(
    file: &[u8], object: &SharedObject<'_>, bias: u64, image_base: u64,
    image: &mut [u8],
) -> Result<(), LoadError> {
    for seg in &object.parsed.loads {
        if seg.file_sz > seg.mem_sz { return Err(LoadError::Einval); }
        let va = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let start = align_down(va);
        let image_start: usize = start.checked_sub(image_base).ok_or(LoadError::Einval)?
            .try_into().map_err(|_| LoadError::Einval)?;
        let end = align_up(va.checked_add(seg.mem_sz).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let len: usize = end.checked_sub(start).ok_or(LoadError::Einval)?
            .try_into().map_err(|_| LoadError::Einval)?;
        let file_start: usize = seg.file_off.try_into().map_err(|_| LoadError::Einval)?;
        let file_end = file_start.checked_add(seg.file_sz.try_into().map_err(|_| LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let source = file.get(file_start..file_end).ok_or(LoadError::Einval)?;
        let target = image.get_mut(image_start..image_start.checked_add(len).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let head: usize = (va - start).try_into().map_err(|_| LoadError::Einval)?;
        let copy = source.len().min(len.saturating_sub(head));
        target[head..head + copy].copy_from_slice(&source[..copy]);
    }
    Ok(())
}

fn defined_exports(
    file: &[u8], object: &SharedObject<'_>, bias: u64,
) -> Result<Vec<ElfRuntimeSymbol>, LoadError> {
    let Ok(symbols) = elf::collect_dynamic_symbols(file, object) else { return Ok(Vec::new()) };
    symbols.into_iter().map(|symbol| Ok(ElfRuntimeSymbol {
        name: symbol.name.to_vec(),
        address: bias.checked_add(symbol.value).ok_or(LoadError::Einval)?,
    })).collect()
}

fn rollback(as_: &AddressSpace, mapped: &[MappedUnixlibObject]) {
    for object in mapped {
        if let Some(addr) = UserVirtAddr::new(object.mapped_start) {
            let size = object.image.end.checked_sub(object.mapped_start)
                .and_then(|size| usize::try_from(size).ok());
            if let Some(size) = size { let _ = as_.munmap(addr, size); }
        }
    }
}

fn mapping_span(object: &SharedObject<'_>) -> Option<(u64, u64)> {
    let min = object.parsed.loads.iter().map(|s| align_down(s.vaddr)).min()?;
    let max = object.parsed.loads.iter()
        .filter_map(|s| s.vaddr.checked_add(s.mem_sz).and_then(align_up)).max()?;
    Some((min, max))
}

fn segment_protection(flags: PFlags) -> VmaProt {
    let mut prot = VmaProt::empty();
    if flags.contains(PFlags::R) { prot |= VmaProt::READ; }
    if flags.contains(PFlags::W) { prot |= VmaProt::WRITE; }
    if flags.contains(PFlags::X) { prot |= VmaProt::EXEC; }
    prot
}

fn align_down(value: u64) -> u64 { value & !(PAGE - 1) }
fn align_up(value: u64) -> Option<u64> { value.checked_add(PAGE - 1).map(|v| v & !(PAGE - 1)) }

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    const EHDR: usize = 64;
    const PHENT: usize = 56;

    fn minimal_object() -> Vec<u8> {
        let mut file = vec![0u8; 0x200];
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&3u16.to_le_bytes());
        file[18..20].copy_from_slice(&ARCH_MACHINE.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes());
        file[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
        file[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
        file[56..58].copy_from_slice(&2u16.to_le_bytes());
        let ph = |file: &mut [u8], index: usize, kind: u32, flags: u32, off: u64,
                  va: u64, file_size: u64, mem_size: u64, align: u64| {
            let at = EHDR + index * PHENT;
            file[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            file[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
            file[at + 24..at + 32].copy_from_slice(&va.to_le_bytes());
            file[at + 32..at + 40].copy_from_slice(&file_size.to_le_bytes());
            file[at + 40..at + 48].copy_from_slice(&mem_size.to_le_bytes());
            file[at + 48..at + 56].copy_from_slice(&align.to_le_bytes());
        };
        ph(&mut file, 0, 1, 5, 0, 0, 0x200, 0x3000, PAGE);
        ph(&mut file, 1, 2, 4, 0x100, 0x100, 0x60, 0x60, 8);
        let dynv = |file: &mut [u8], index: usize, tag: u64, value: u64| {
            let at = 0x100 + index * 16;
            file[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        };
        dynv(&mut file, 0, 5, 0x180);
        dynv(&mut file, 1, 10, 1);
        dynv(&mut file, 2, 7, 0x190);
        dynv(&mut file, 3, 8, 24);
        dynv(&mut file, 4, 9, 24);
        dynv(&mut file, 5, 0, 0);
        file[0x190..0x198].copy_from_slice(&0x1c0u64.to_le_bytes());
        file[0x198..0x1a0].copy_from_slice(&8u64.to_le_bytes());
        file[0x1a0..0x1a8].copy_from_slice(&0x24i64.to_le_bytes());
        file[0x1c0..0x1c8].copy_from_slice(&0x24u64.to_le_bytes());
        file
    }

    fn source(name: &[u8], file: Vec<u8>) -> UnixlibSourceObject {
        let mut path = vec![b'/'];
        path.extend_from_slice(name);
        UnixlibSourceObject { name: name.to_vec(), path, file }
    }

    #[test]
    fn context_maps_dependency_images_and_seals_final_permissions() {
        let object = minimal_object();
        let context = UnixlibLoadContext { root_name: b"root.so".to_vec(), objects: vec![
            source(b"dep.so", object.clone()), source(b"root.so", object),
        ] };
        let as_ = AddressSpace::new(0x7_5000).unwrap();
        let mapped = map_load_context(&context, &as_).unwrap();
        assert_eq!(mapped.len(), 2);
        assert_eq!(as_.vma_count(), 2);
        for image in mapped {
            let vma = as_.find_vma(UserVirtAddr::new(image.image.base + 0x100).unwrap()).unwrap();
            assert!(vma.prot.contains(VmaProt::READ));
            assert!(vma.prot.contains(VmaProt::EXEC));
            assert!(!vma.prot.contains(VmaProt::WRITE));
        }
        crate::elf_modules::clear(as_.root_pa());
    }

    #[test]
    fn context_applies_relative_relocations_before_publication() {
        let context = UnixlibLoadContext { root_name: b"root.so".to_vec(),
            objects: vec![source(b"root.so", minimal_object())] };
        let as_ = AddressSpace::new(0x7_8000).unwrap();
        let mapped = map_load_context(&context, &as_).unwrap();
        let image = &mapped[0].image;
        let vma = as_.find_vma(UserVirtAddr::new(image.base + 0x1c0).unwrap()).unwrap();
        let VmaBacking::KernelBytes { data, off } = vma.backing else { panic!("expected staged ELF bytes") };
        let at = (image.base + 0x1c0 - vma.start.as_u64()) as usize + off;
        let value = u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
        assert_eq!(value, image.base + 0x24);
        crate::elf_modules::clear(as_.root_pa());
    }

    #[test]
    fn late_object_failure_rolls_back_every_prior_mapping() {
        let context = UnixlibLoadContext { root_name: b"root.so".to_vec(), objects: vec![
            source(b"dep.so", minimal_object()), source(b"root.so", vec![0u8; 8]),
        ] };
        let as_ = AddressSpace::new(0x7_6000).unwrap();
        assert!(map_load_context(&context, &as_).is_err());
        assert_eq!(as_.vma_count(), 0);
        assert_eq!(crate::elf_modules::resolve_symbol(as_.root_pa(), b"anything"), None);
    }

    #[test]
    fn overflowing_load_span_is_rejected_without_a_reservation() {
        let mut object = minimal_object();
        let mem_size = u64::MAX;
        object[EHDR + 40..EHDR + 48].copy_from_slice(&mem_size.to_le_bytes());
        let context = UnixlibLoadContext { root_name: b"root.so".to_vec(),
            objects: vec![source(b"root.so", object)] };
        let as_ = AddressSpace::new(0x7_7000).unwrap();
        assert!(map_load_context(&context, &as_).is_err());
        assert_eq!(as_.vma_count(), 0);
    }
}
