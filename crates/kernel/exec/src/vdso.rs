// Complete vDSO image publication into the canonical address space.
use alloc::sync::Arc;
use hal::{UserVirtAddr, PAGE_SIZE_BYTES};
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn image_size(blob: &[u8], machine: u16) -> Option<usize> {
    let image = elf::parse(blob, machine).ok()?;
    if image.elf_type != elf::ElfType::Dyn || image.loads.len() != 1 { return None; }
    let load = image.loads[0];
    if load.file_off != 0 || load.vaddr != 0 || load.file_sz != load.mem_sz
        || load.flags != (elf::PFlags::R | elf::PFlags::X) { return None; }
    blob.len().checked_add(PAGE - 1).map(|len| len & !(PAGE - 1))
}

/// Publish the complete image and its preceding data page. # C: O(image + N_vmas)
pub fn map_into(mm: &AddressSpace, blob: &[u8], machine: u16, vvar_pa: u64) -> Option<u64> {
    if vvar_pa == 0 { return None; }
    let total = image_size(blob, machine)?;
    let reserve = PAGE.checked_add(total)?;
    let vvar_va = mm.get_unmapped_area(reserve).ok()?.as_u64();
    let base = vvar_va.checked_add(PAGE_SIZE_BYTES)?;
    let end = base.checked_add(total as u64)?;
    let vvar_hint = UserVirtAddr::new(vvar_va)?;
    let image_hint = UserVirtAddr::new(base)?;
    // Preserve bytes outside PT_LOAD too: the mapped ELF header advertises
    // section names and headers used by debugger symbol readers.
    let data = Arc::<[u8]>::from(blob);
    mm.mmap(Some(vvar_hint), PAGE, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::KernelFrame { pa: vvar_pa }, true).ok()?;
    mm.mmap(Some(image_hint), total, VmaProt::READ | VmaProt::EXEC, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data, off: 0 }, true).ok()?;
    mm.set_vdso_range(vvar_va, end);
    Some(base)
}

