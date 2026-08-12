//! DRM GEM VMA setup and mapping-reference ownership.

use super::*;

const LINUX_EINVAL: i32 = 22;
const PAGE_SIZE: u64 = 4096;
const LINUX_FILE_PRIVATE_OFF: usize = 24;
const VMA_START_OFF: usize = 0;
const VMA_END_OFF: usize = 8;
const VMA_FLAGS_OFF: usize = 32;
const VMA_OPS_OFF: usize = 72;
const VMA_PGOFF_OFF: usize = 80;
const VMA_PRIVATE_OFF: usize = 96;
const GEM_REFCOUNT_OFF: usize = 0;
const GEM_SIZE_OFF: usize = 216;
const GEM_FUNCS_OFF: usize = 352;
const GEM_FUNCS_MMAP_OFF: usize = 80;
const GEM_FUNCS_VM_OPS_OFF: usize = 104;
const VM_PFNMAP: u64 = 1 << 10;
const VM_IO: u64 = 1 << 14;
const VM_DONTEXPAND: u64 = 1 << 18;
const VM_DONTDUMP: u64 = 1 << 26;
type GemMmap = unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32;

#[repr(C)]
pub(super) struct GemVmOps { _open: Option<unsafe extern "C" fn(*mut c_void)>, close: Option<unsafe extern "C" fn(*mut c_void)> }

pub(super) static SHMEM_VM_OPS: GemVmOps = GemVmOps { _open: None, close: Some(drm_gem_vm_close) };

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_mmap_obj", drm_gem_mmap_obj as *const () as usize, false);
    crate::symtab::export("drm_gem_mmap", drm_gem_mmap as *const () as usize, false);
}

/// Bind a validated GEM object to one VMA and acquire its mapping reference. # C: O(1)
pub(super) extern "C" fn drm_gem_mmap_obj(object: *mut c_void, object_size: usize, vma: *mut c_void) -> i32 {
    if object.is_null() || vma.is_null() { return -LINUX_EINVAL; }
    // SAFETY: the VMA is supplied by the mmap owner and its start/end fields are the complete ABI range.
    let (start, end) = unsafe { (read(vma.cast::<u8>().add(VMA_START_OFF).cast::<u64>()), read(vma.cast::<u8>().add(VMA_END_OFF).cast::<u64>())) };
    let Some(length) = end.checked_sub(start) else { return -LINUX_EINVAL; };
    if length == 0 || length > object_size as u64 { return -LINUX_EINVAL; }
    // SAFETY: this extra reference belongs to the installed VMA and is returned by its vm close operation.
    unsafe { let refs = read(object.cast::<u8>().add(GEM_REFCOUNT_OFF).cast::<i32>()); if refs <= 0 { return -LINUX_EINVAL; } write(object.cast::<u8>().add(GEM_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); }
    // SAFETY: function-table, VMA private-data, and vm-ops fields are verified ABI slots for this live mapping setup.
    let (funcs, mmap, vm_ops) = unsafe { let funcs = read(object.cast::<u8>().add(GEM_FUNCS_OFF).cast::<*const u8>()); if funcs.is_null() { gem::object_put(object); return -LINUX_EINVAL; } let mmap = read(funcs.add(GEM_FUNCS_MMAP_OFF).cast::<Option<GemMmap>>()); let vm_ops = read(funcs.add(GEM_FUNCS_VM_OPS_OFF).cast::<*const c_void>()); write(vma.cast::<u8>().add(VMA_PRIVATE_OFF).cast::<*mut c_void>(), object); write(vma.cast::<u8>().add(VMA_OPS_OFF).cast::<*const c_void>(), vm_ops); (funcs, mmap, vm_ops) };
    let _ = funcs;
    if let Some(mmap) = mmap {
        // SAFETY: object functions receive the retained GEM object and the VMA initialized above.
        let rc = unsafe { mmap(object, vma) }; if rc == 0 { return 0; } gem::object_put(object); return rc;
    }
    if vm_ops.is_null() { gem::object_put(object); return -LINUX_EINVAL; }
    // SAFETY: no object-specific mmap exists, so the generic path installs the immutable non-expandable PFN VMA class.
    unsafe { let flags = read(vma.cast::<u8>().add(VMA_FLAGS_OFF).cast::<u64>()); write(vma.cast::<u8>().add(VMA_FLAGS_OFF).cast::<u64>(), flags | VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP); }
    0
}

/// Resolve a file-authorized fake offset and bind its GEM object to the VMA. # C: O(N_offsets)
pub(super) extern "C" fn drm_gem_mmap(filp: *mut c_void, vma: *mut c_void) -> i32 {
    if filp.is_null() || vma.is_null() { return -LINUX_EINVAL; }
    // SAFETY: external file private_data holds its drm_file context from drm_open; VMA fields are stable during mmap setup.
    let (file, start, end, pgoff) = unsafe { (read(filp.cast::<u8>().add(LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>()), read(vma.cast::<u8>().add(VMA_START_OFF).cast::<u64>()), read(vma.cast::<u8>().add(VMA_END_OFF).cast::<u64>()), read(vma.cast::<u8>().add(VMA_PGOFF_OFF).cast::<u64>())) };
    let Some(length) = end.checked_sub(start) else { return -LINUX_EINVAL; }; if length == 0 || length % PAGE_SIZE != 0 { return -LINUX_EINVAL; }
    let object = gem::mmap_object_lookup(file, pgoff, length / PAGE_SIZE); if object.is_null() { return -LINUX_EINVAL; }
    // SAFETY: lookup retained object and its immutable size is read before the temporary lookup reference is released.
    let size = unsafe { read(object.cast::<u8>().add(GEM_SIZE_OFF).cast::<usize>()) }; let rc = drm_gem_mmap_obj(object, size, vma); gem::object_put(object); rc
}

/// Release the mapping reference installed by `drm_gem_mmap_obj`. # C: O(1)
pub(super) extern "C" fn drm_gem_vm_close(vma: *mut c_void) {
    if vma.is_null() { return; }
    // SAFETY: vm_private_data is the mapping-owned GEM reference installed by drm_gem_mmap_obj exactly once.
    let object = unsafe { read(vma.cast::<u8>().add(VMA_PRIVATE_OFF).cast::<*mut c_void>()) }; if object.is_null() { return; }
    // SAFETY: clearing the VMA slot first makes repeated close callbacks a no-op before releasing the object.
    unsafe { write(vma.cast::<u8>().add(VMA_PRIVATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); }
    gem::object_put(object);
}

/// Return the shmem GEM object retained by one successfully established VMA. # C: O(1)
pub(crate) fn shmem_mapping_object(vma: *mut c_void) -> Option<*mut c_void> {
    if vma.is_null() { return None; }
    // SAFETY: the mapper owns the complete ABI VMA until this handoff finishes.
    let object = unsafe { read(vma.cast::<u8>().add(VMA_PRIVATE_OFF).cast::<*mut c_void>()) };
    if object.is_null() { return None; }
    // SAFETY: GEM function-table pointer is immutable for this established object.
    let funcs = unsafe { read(object.cast::<u8>().add(GEM_FUNCS_OFF).cast::<*const c_void>()) };
    let shmem: *const c_void = (&gem::SHMEM_OBJECT_FUNCS as *const gem::GemObjectFuncs).cast();
    if funcs == shmem { Some(object) } else { None }
}

/// Size and PMM frame of one shmem-GEM page. # C: O(log N)
pub(crate) fn shmem_mapping_frame(object: *mut c_void, off: u64) -> Option<(u64, u64)> {
    if object.is_null() || off % PAGE_SIZE != 0 { return None; }
    // SAFETY: established shmem GEM object's immutable size/backing slots are valid through its mapping reference.
    let (size, backing) = unsafe { (read(object.cast::<u8>().add(GEM_SIZE_OFF).cast::<u64>()), read(object.cast::<u8>().add(432).cast::<*mut u8>())) };
    if off >= size { return None; }
    #[cfg(target_os = "oxide-kernel")]
    { crate::linux_alloc::vmalloc_page_pa(backing, off as usize).map(|pa| (size, pa)) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = backing; None }
}

/// Size of one established shmem GEM mapping. # C: O(1)
pub(crate) fn shmem_mapping_size(object: *mut c_void) -> Option<u64> {
    if object.is_null() { return None; }
    // SAFETY: established object's immutable size field is valid through its mapping reference.
    Some(unsafe { read(object.cast::<u8>().add(GEM_SIZE_OFF).cast::<u64>()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gem_mmap_binds_the_exact_authorized_object_to_the_vma() {
        let _modules = crate::test_serial::claim(); let mut file = [0u8; 416]; let mut filp = [0u8; 192]; let mut dev = [0u8; 64]; let mut args = [0u8; 32]; let mut vma = [0u8; 192]; let mut offset = 0u64;
        assert!(gem::file_init(file.as_mut_ptr().cast()));
        // SAFETY: arrays reserve one shmem GEM, external file context, and complete VMA layout fields.
        unsafe { write(args.as_mut_ptr().add(0).cast::<u32>(), 4); write(args.as_mut_ptr().add(4).cast::<u32>(), 8); write(args.as_mut_ptr().add(8).cast::<u32>(), 32); write(filp.as_mut_ptr().add(LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>(), file.as_mut_ptr().cast()); write(vma.as_mut_ptr().add(VMA_START_OFF).cast::<u64>(), 0x4000_0000); write(vma.as_mut_ptr().add(VMA_END_OFF).cast::<u64>(), 0x4000_1000); }
        assert_eq!(gem::drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), args.as_mut_ptr().cast()), 0); let handle = unsafe { read(args.as_ptr().add(16).cast::<u32>()) };
        assert_eq!(gem::drm_gem_dumb_map_offset(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), handle, &mut offset), 0); unsafe { write(vma.as_mut_ptr().add(VMA_PGOFF_OFF).cast::<u64>(), offset / PAGE_SIZE); }
        assert_eq!(drm_gem_mmap(filp.as_mut_ptr().cast(), vma.as_mut_ptr().cast()), 0); assert!(!unsafe { read(vma.as_ptr().add(VMA_PRIVATE_OFF).cast::<*mut c_void>()) }.is_null()); assert_eq!(unsafe { read(vma.as_ptr().add(VMA_FLAGS_OFF).cast::<u64>()) } & (VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP), VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP); drm_gem_vm_close(vma.as_mut_ptr().cast()); assert!(unsafe { read(vma.as_ptr().add(VMA_PRIVATE_OFF).cast::<*mut c_void>()) }.is_null()); gem::file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
    }
}
