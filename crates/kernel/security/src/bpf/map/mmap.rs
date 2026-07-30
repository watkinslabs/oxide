//! Canonical frame-backed storage for mmapable array maps.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::Spinlock;
use syscall::errno::Errno;
use vfs::{AddressSpaceOps, KResult, SharedFrame, VfsError};

const MAP_METADATA_PAGES: usize = 1;
const VALUE_ALIGNMENT: usize = 8;
const PAGE_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;

enum ValueBacking {
    Heap(Spinlock<Vec<u8>, sync::TaskList>),
    Mapped { array: Arc<MmapArray>, offset: usize, len: usize },
}

/// One map value, backed either by private storage or the map's mapped frames.
pub(crate) struct BpfMapValue { backing: ValueBacking }

impl BpfMapValue {
    pub(crate) fn heap(bytes: Vec<u8>) -> Self { Self { backing: ValueBacking::Heap(Spinlock::new(bytes)) } }
    fn mapped(array: Arc<MmapArray>, offset: usize, len: usize) -> Self {
        Self { backing: ValueBacking::Mapped { array, offset, len } }
    }
    pub(crate) fn len(&self) -> usize {
        match &self.backing {
            ValueBacking::Heap(bytes) => bytes.lock().len(),
            ValueBacking::Mapped { len, .. } => *len,
        }
    }
    pub(crate) fn copy_out(&self) -> Result<Vec<u8>, Errno> {
        let mut out = super::zeroed_vec(self.len())?;
        self.copy_into(&mut out)?;
        Ok(out)
    }
    fn copy_into(&self, dst: &mut [u8]) -> Result<(), Errno> {
        if dst.len() != self.len() { return Err(Errno::Einval); }
        match &self.backing {
            ValueBacking::Heap(bytes) => dst.copy_from_slice(&bytes.lock()),
            ValueBacking::Mapped { array, offset, len } => array.copy_into(*offset, &mut dst[..*len])?,
        }
        Ok(())
    }
    pub(crate) fn replace(&self, src: &[u8]) -> Result<(), Errno> {
        if src.len() != self.len() { return Err(Errno::Einval); }
        match &self.backing {
            ValueBacking::Heap(bytes) => *bytes.lock() = super::copy_vec(src)?,
            ValueBacking::Mapped { array, offset, len } => array.copy_from(*offset, &src[..*len])?,
        }
        Ok(())
    }
    pub(crate) fn copy_to_user(&self, ptr: u64) -> Result<(), Errno> {
        crate::bpf::user::write_bytes(ptr, &self.copy_out()?)
    }
    pub(crate) fn read_range(&self, offset: usize, dst: &mut [u8]) -> Option<()> {
        if offset.checked_add(dst.len())? > self.len() { return None; }
        match &self.backing {
            ValueBacking::Heap(bytes) => dst.copy_from_slice(&bytes.lock()[offset..offset + dst.len()]),
            ValueBacking::Mapped { array, offset: base, .. } => array.copy_into(base.checked_add(offset)?, dst).ok()?,
        }
        Some(())
    }
    pub(crate) fn write_range(&self, offset: usize, src: &[u8]) -> Option<()> {
        if offset.checked_add(src.len())? > self.len() { return None; }
        match &self.backing {
            ValueBacking::Heap(bytes) => bytes.lock()[offset..offset + src.len()].copy_from_slice(src),
            ValueBacking::Mapped { array, offset: base, .. } => array.copy_from(base.checked_add(offset)?, src).ok()?,
        }
        Some(())
    }
    pub(crate) fn atomic_add(&self, offset: usize, size: usize, add: i64) -> Option<()> {
        if offset.checked_add(size)? > self.len() { return None; }
        match &self.backing {
            ValueBacking::Heap(bytes) => atomic_add_bytes(&mut bytes.lock()[offset..offset + size], add),
            ValueBacking::Mapped { array, offset: base, .. } => array.atomic_add(base.checked_add(offset)?, size, add),
        }
    }
}

fn atomic_add_bytes(bytes: &mut [u8], add: i64) -> Option<()> {
    match bytes.len() {
        4 => {
            let old = u32::from_le_bytes(bytes.try_into().ok()?);
            bytes.copy_from_slice(&old.wrapping_add(add as u32).to_le_bytes());
        }
        8 => {
            let old = u64::from_le_bytes(bytes.try_into().ok()?);
            bytes.copy_from_slice(&old.wrapping_add(add as u64).to_le_bytes());
        }
        _ => return None,
    }
    Some(())
}

pub(crate) struct MmapArray {
    frames: Vec<u64>,
    bytes: usize,
    gate: Spinlock<(), sync::TaskList>,
}

impl MmapArray {
    pub(crate) fn allocate(value_size: usize, max_entries: usize) -> Result<Arc<Self>, Errno> {
        let stride = value_size.checked_add(VALUE_ALIGNMENT - 1)
            .map(|size| size & !(VALUE_ALIGNMENT - 1)).ok_or(Errno::E2big)?;
        let values = stride.checked_mul(max_entries).ok_or(Errno::E2big)?;
        let used = MAP_METADATA_PAGES.checked_mul(PAGE_BYTES).and_then(|head| head.checked_add(values))
            .ok_or(Errno::E2big)?;
        let pages = used.checked_add(PAGE_BYTES - 1).map(|n| n / PAGE_BYTES).ok_or(Errno::E2big)?;
        let bytes = pages.checked_mul(PAGE_BYTES).ok_or(Errno::E2big)?;
        let mut frames = Vec::new();
        frames.try_reserve_exact(pages).map_err(|_| Errno::Enomem)?;
        for _ in 0..pages {
            let Some(pa) = pmm::setup::alloc_object_frame() else {
                for pa in frames {
                    // SAFETY: every unpublished frame owns exactly one allocation reference.
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                }
                return Err(Errno::Enomem);
            };
            frames.push(pa);
        }
        Ok(Arc::new(Self { frames, bytes, gate: Spinlock::new(()) }))
    }
    pub(crate) fn value(&self, value_size: usize, index: usize, this: &Arc<Self>) -> Result<Arc<BpfMapValue>, Errno> {
        let stride = value_size.checked_add(VALUE_ALIGNMENT - 1)
            .map(|size| size & !(VALUE_ALIGNMENT - 1)).ok_or(Errno::E2big)?;
        let offset = MAP_METADATA_PAGES.checked_mul(PAGE_BYTES).and_then(|head| head.checked_add(stride.checked_mul(index)?))
            .ok_or(Errno::E2big)?;
        Arc::try_new(BpfMapValue::mapped(Arc::clone(this), offset, value_size)).map_err(|_| Errno::Enomem)
    }
    pub(crate) fn size(&self) -> u64 { self.bytes as u64 }
    fn copy_into(&self, offset: usize, dst: &mut [u8]) -> Result<(), Errno> {
        let _gate = self.gate.lock();
        self.read_bytes(offset, dst)
    }
    fn copy_from(&self, offset: usize, src: &[u8]) -> Result<(), Errno> {
        let _gate = self.gate.lock();
        self.write_bytes(offset, src)
    }
    fn atomic_add(&self, offset: usize, size: usize, add: i64) -> Option<()> {
        let _gate = self.gate.lock();
        let mut bytes = super::zeroed_vec(size).ok()?;
        self.read_bytes(offset, &mut bytes).ok()?;
        atomic_add_bytes(&mut bytes, add)?;
        self.write_bytes(offset, &bytes).ok()
    }
    fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<(), Errno> {
        if offset.checked_add(dst.len()).ok_or(Errno::E2big)? > self.bytes { return Err(Errno::Einval); }
        let mut done = 0;
        while done < dst.len() {
            let pos = offset + done;
            let ptr = pmm::setup::frame_ptr(self.frames[pos / PAGE_BYTES]).ok_or(Errno::Eio)?;
            let page_off = pos % PAGE_BYTES;
            let len = core::cmp::min(PAGE_BYTES - page_off, dst.len() - done);
            // SAFETY: checked range stays in a map-owned frame and `chunk` fits the remaining page.
            let source = unsafe { core::slice::from_raw_parts(ptr.add(page_off), len) };
            dst[done..done + len].copy_from_slice(source);
            done += len;
        }
        Ok(())
    }
    fn write_bytes(&self, offset: usize, src: &[u8]) -> Result<(), Errno> {
        if offset.checked_add(src.len()).ok_or(Errno::E2big)? > self.bytes { return Err(Errno::Einval); }
        let mut done = 0;
        while done < src.len() {
            let pos = offset + done;
            let ptr = pmm::setup::frame_ptr(self.frames[pos / PAGE_BYTES]).ok_or(Errno::Eio)?;
            let page_off = pos % PAGE_BYTES;
            let len = core::cmp::min(PAGE_BYTES - page_off, src.len() - done);
            // SAFETY: checked range stays in a map-owned frame and `chunk` fits the remaining page.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().add(done), ptr.add(page_off), len); }
            done += len;
        }
        Ok(())
    }
}

impl Drop for MmapArray {
    fn drop(&mut self) {
        for &pa in &self.frames {
            // SAFETY: map ownership holds one allocation reference for every listed frame.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
        }
    }
}

impl AddressSpaceOps for MmapArray {
    fn shared_frame(&self, off: u64) -> KResult<Option<SharedFrame>> {
        let offset = usize::try_from(off).map_err(|_| VfsError::Einval)?;
        if offset >= self.bytes || offset % PAGE_BYTES != 0 { return Ok(None); }
        let pa = self.frames[offset / PAGE_BYTES];
        // SAFETY: the backing keeps this frame allocated until its mapping reference releases.
        unsafe { pmm::setup::inc_ref(pa); }
        Ok(Some(SharedFrame { pa, map_ref_held: true }))
    }
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        let offset = usize::try_from(off).map_err(|_| VfsError::Einval)?;
        if offset >= self.bytes { return Ok(0); }
        let len = core::cmp::min(dst.len(), self.bytes - offset);
        self.copy_into(offset, &mut dst[..len]).map_err(|_| VfsError::Eio)?;
        Ok(len)
    }
    fn size(&self) -> u64 { self.size() }
}
