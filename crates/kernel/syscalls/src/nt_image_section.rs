//! Glue between an NT section handle and the image owners: the PE crate lays
//! the image out, `elf_load::nt_image_section` installs the view's
//! protections, and `sched::nt_object` owns the section object. What lives
//! here is only the handle, file and address-space plumbing between them; the
//! decisions are in `nt_section_image`.
#![cfg(target_os = "oxide-kernel")]
use alloc::{sync::Arc, vec::Vec};
use crate::nt_section_image as decide;

const FILE_READ_DATA: u32 = 0x0001;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const READ_CHUNK_BYTES: usize = 0x1_0000;

/// Build an image-attributed section object over one file handle. # C: O(file size)
pub(crate) fn create(table: &sched::nt_object::NtHandleTable, file: u32, requested: u64, flags: u32)
    -> Result<Arc<sched::nt_object::NtObject>, u64> {
    let native = sched::nt_object::NtHandle::from_raw(file);
    let Some(object) = table.get(native, 0) else { return Err(crate::nt_dispatch::STATUS_INVALID_PARAMETER); };
    if object.kind() != sched::nt_object::NtObjectType::File { return Err(crate::nt_dispatch::STATUS_INVALID_PARAMETER); }
    let granted = table.access(native).unwrap_or(0);
    if granted & (FILE_READ_DATA | GENERIC_READ | FILE_GENERIC_READ) == 0 { return Err(decide::STATUS_INVALID_PARAMETER); }
    let Some(file) = object.file() else { return Err(crate::nt_dispatch::STATUS_INVALID_PARAMETER); };
    let size = vfs::generic_fillattr(file.inode(), &vfs::IDENTITY).size as u64;
    if size == 0 { return Err(decide::STATUS_INVALID_FILE_FOR_SECTION); }
    let blob = read_file(&file, size).ok_or(decide::STATUS_INVALID_FILE_FOR_SECTION)?;
    let image = pe::image_section(&blob, size).map_err(|_| decide::STATUS_INVALID_IMAGE_FORMAT)?;
    decide::image_section_size(requested, image.size() as u64)?;
    Ok(table.new_image_section(Arc::new(image), file, flags, None))
}

/// Map one image section's view into the current address space, placing every
/// span at its own relative address under its own protection. Returns the
/// status the view carries: a view away from the preferred base is reported,
/// not refused. # C: O(SizeOfImage)
pub(crate) fn map_view(mm: &vmm::AddressSpace, image: &pe::ImageSection, requested: Option<hal::UserVirtAddr>)
    -> Result<(hal::UserVirtAddr, usize, u64), u64> {
    let len = image.size();
    let placement = match requested {
        Some(address) => vmm::MmapPlacement::FixedNoReplace(address),
        None => match hal::UserVirtAddr::new(image.preferred_base) {
            Some(preferred) => vmm::MmapPlacement::Advisory(Some(preferred)),
            None => vmm::MmapPlacement::Advisory(None),
        },
    };
    let widest = elf_load::nt_image_section::span_protection(image.max_prot()) | vmm::VmaProt::WRITE;
    let mapped = match mm.mmap_with_may_at(placement, len, vmm::VmaProt::READ, widest,
        vmm::VmaFlags::PRIVATE | vmm::VmaFlags::NT_SECTION_VIEW,
        vmm::VmaBacking::KernelBytes { data: Arc::clone(&image.bytes), off: 0 }) {
        Ok(mapped) => mapped,
        Err(vmm::MmapError::Exists) => return Err(crate::nt_dispatch::STATUS_CONFLICTING_ADDRESSES),
        Err(vmm::MmapError::Vmm(_)) => return Err(crate::nt_dispatch::STATUS_NO_MEMORY),
    };
    if !mm.set_mapping_origin(mapped) { let _ = mm.munmap(mapped, len); return Err(crate::nt_dispatch::STATUS_NO_MEMORY); }
    if elf_load::nt_image_section::protect_view(mm, mapped, &image.spans).is_err() {
        let _ = mm.munmap(mapped, len);
        return Err(decide::STATUS_INVALID_IMAGE_FORMAT);
    }
    Ok((mapped, len, decide::map_view_status(image.at_preferred_base(mapped.as_u64()))))
}

fn read_file(file: &Arc<vfs::File>, size: u64) -> Option<Vec<u8>> {
    let len = usize::try_from(size).ok()?;
    let mut blob = Vec::new();
    blob.try_reserve_exact(len).ok()?;
    blob.resize(len, 0);
    let backing = crate::mmap_file::InodeFileBacking::new(file.inode().clone());
    let mut at = 0usize;
    while at < len {
        let end = (at + READ_CHUNK_BYTES).min(len);
        let read = vmm::FileBacking::read_at(&*backing, at as u64, &mut blob[at..end]).ok()?;
        if read == 0 { return None; }
        at += read;
    }
    Some(blob)
}
