//! PCM mmap ownership: one status page and one control page per substream.

use crate::uapi::{PCM_MMAP_OFFSET_CONTROL, PCM_MMAP_OFFSET_CONTROL_OLD,
    PCM_MMAP_OFFSET_STATUS, PCM_MMAP_OFFSET_STATUS_OLD};

#[derive(Default)]
pub(crate) struct Pages {
    #[cfg(target_os = "oxide-kernel")]
    status_pa: u64,
    #[cfg(target_os = "oxide-kernel")]
    control_pa: u64,
}

fn is_status(off: u64) -> bool { off == PCM_MMAP_OFFSET_STATUS || off == PCM_MMAP_OFFSET_STATUS_OLD }
fn is_control(off: u64) -> bool { off == PCM_MMAP_OFFSET_CONTROL || off == PCM_MMAP_OFFSET_CONTROL_OLD }

impl Pages {
    /// Return the sound-core page selected by a Linux PCM mmap offset.
    /// # C: O(1)
    pub(crate) fn frame(&mut self, off: u64) -> Option<u64> {
        if !is_status(off) && !is_control(off) { return None; }
        #[cfg(target_os = "oxide-kernel")]
        {
            let slot = if is_status(off) { &mut self.status_pa } else { &mut self.control_pa };
            if *slot == 0 {
                let pa = pmm::setup::alloc_object_frame()?;
                if !pmm::setup::zero_frame(pa) {
                    pmm::setup::release_object_frame(pa);
                    return None;
                }
                *slot = pa;
            }
            return Some(*slot);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        { None }
    }

    /// Release the object-owned status/control pages after the substream is gone.
    /// # C: O(1)
    pub(crate) fn release(&mut self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            if self.status_pa != 0 { pmm::setup::release_object_frame(self.status_pa); self.status_pa = 0; }
            if self.control_pa != 0 { pmm::setup::release_object_frame(self.control_pa); self.control_pa = 0; }
        }
    }
}

/// Publish the runtime words userspace reads from the status page.
/// # C: O(1)
pub(crate) fn publish_status(pages: &Pages, state: u32, appl: u64, hw: u64, avail: u64) {
    write_u32(pages, crate::uapi::ST_STATE, state);
    write_u64(pages, crate::uapi::ST_APPL_PTR, appl);
    write_u64(pages, crate::uapi::ST_HW_PTR, hw);
    write_u64(pages, crate::uapi::ST_AVAIL, avail);
    write_u64(pages, crate::uapi::ST_AVAIL_MAX, avail);
}

/// Read the application pointer userspace advanced in the control page.
/// # C: O(1)
pub(crate) fn control_appl(pages: &Pages) -> Option<u64> {
    #[cfg(target_os = "oxide-kernel")]
    {
        if pages.control_pa == 0 { return None; }
        let p = pmm::setup::frame_ptr(pages.control_pa)?;
        // SAFETY: PMM owns the control page for this live substream and the
        // offset is within its one-page allocation.
        return Some(unsafe { core::ptr::read_volatile(p.add(crate::uapi::SP_CONTROL_APPL_PTR) as *const u64) });
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = pages; None }
}

#[cfg(target_os = "oxide-kernel")]
fn write_u32(pages: &Pages, off: usize, value: u32) {
    if pages.status_pa == 0 || off + 4 > hal::PAGE_SIZE_BYTES as usize { return; }
    let Some(p) = pmm::setup::frame_ptr(pages.status_pa) else { return; };
    // SAFETY: PMM owns the status page and the bounded offset stays in it.
    unsafe { core::ptr::write_volatile(p.add(off) as *mut u32, value); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn write_u32(_pages: &Pages, _off: usize, _value: u32) {}

#[cfg(target_os = "oxide-kernel")]
fn write_u64(pages: &Pages, off: usize, value: u64) {
    if pages.status_pa == 0 || off + 8 > hal::PAGE_SIZE_BYTES as usize { return; }
    let Some(p) = pmm::setup::frame_ptr(pages.status_pa) else { return; };
    // SAFETY: PMM owns the status page and the bounded offset stays in it.
    unsafe { core::ptr::write_volatile(p.add(off) as *mut u64, value); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn write_u64(_pages: &Pages, _off: usize, _value: u64) {}
