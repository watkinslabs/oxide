use alloc::sync::Arc;
use core::ffi::c_void;
use core::ptr::write;
use core::sync::atomic::{AtomicUsize, Ordering};
use vfs::File;

use super::{file_for_call, store_file_private};
use super::super::types::{LinuxFile, LinuxFileOperations};

pub(super) struct LinuxGemMmapBacking {
    pub(super) ops: usize,
    pub(super) file: Arc<File>,
    pub(super) offset: u64,
    pub(super) object: AtomicUsize,
    pub(super) opens: AtomicUsize,
}

impl vmm::FileBacking for LinuxGemMmapBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Err(vmm::FileBackingError::Io) }
    fn size_hint(&self) -> u64 { crate::linux_drm::shmem_mapping_size(self.object.load(Ordering::Acquire) as *mut c_void).unwrap_or(0) }
    fn shared_frame(&self, off: u64) -> Result<Option<vmm::SharedFrame>, vmm::FileBackingError> {
        Ok(crate::linux_drm::shmem_mapping_frame(self.object.load(Ordering::Acquire) as *mut c_void, off).map(|(_, pa)| vmm::SharedFrame { pa, map_ref_held: false }))
    }
    fn mmap_setup(&self, setup: &mut vmm::FileMmapSetup) -> Result<(), vmm::FileBackingError> {
        if self.object.load(Ordering::Acquire) != 0 { return Err(vmm::FileBackingError::Inval); }
        let ops = self.ops as *const LinuxFileOperations;
        // SAFETY: adapter owns this temporary ABI VMA throughout the registered f_op->mmap callback.
        let mmap = unsafe { (*ops).mmap }.ok_or(vmm::FileBackingError::Inval)?;
        let mut lf = file_for_call(0, Some(&self.file)); lf.f_op = ops;
        let mut vma = [0u8; 192];
        // SAFETY: VMA slots are the verified Linux ABI layout and carry VMM's final placement.
        unsafe { write(vma.as_mut_ptr().add(0).cast::<u64>(), setup.start().as_u64()); write(vma.as_mut_ptr().add(8).cast::<u64>(), setup.end().as_u64()); write(vma.as_mut_ptr().add(80).cast::<u64>(), self.offset / 4096); write(vma.as_mut_ptr().add(88).cast::<*mut c_void>(), (&mut lf as *mut LinuxFile).cast()); }
        // SAFETY: mmap is the registered external file-operation callback with valid file and VMA ABI storage.
        let rc = unsafe { mmap(&mut lf, vma.as_mut_ptr().cast()) }; store_file_private(&self.file, &lf);
        if rc != 0 { return Err(vmm::FileBackingError::Inval); }
        let object = crate::linux_drm::shmem_mapping_object(vma.as_mut_ptr().cast()).ok_or(vmm::FileBackingError::Inval)?;
        if self.object.compare_exchange(0, object as usize, Ordering::AcqRel, Ordering::Acquire).is_err() { crate::linux_drm::object_put(object); return Err(vmm::FileBackingError::Inval); }
        Ok(())
    }
    fn vma_open(&self) {
        let was = self.opens.fetch_add(1, Ordering::AcqRel);
        if was != 0 { let _ = crate::linux_drm::object_get(self.object.load(Ordering::Acquire) as *mut c_void); }
    }
    fn vma_close(&self) {
        if self.opens.fetch_sub(1, Ordering::AcqRel) != 0 { crate::linux_drm::object_put(self.object.load(Ordering::Acquire) as *mut c_void); }
    }
}
