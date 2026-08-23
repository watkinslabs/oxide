//! Plane memory: refcounted kernel RAM pages, one per buffer page.
//!
//! These pages are handed to userspace through the shared-frame mapping path,
//! which takes a reference per page-table entry. A page freed here while a
//! mapping still covers it therefore stays alive until that mapping goes — the
//! opposite of a physical-range mapping, which counts nothing and would free
//! the page underneath the application.

use alloc::vec::Vec;

use crate::vb2::PlaneAlloc;

/// Bytes per frame the allocator deals in.
pub const PAGE_BYTES: u32 = 4096;

/// The video core's plane allocator.
pub struct FrameAlloc;

impl PlaneAlloc for FrameAlloc {
    /// # C: O(pages)
    fn alloc(&self, bytes: u32) -> Option<Vec<u64>> {
        let pages = bytes.div_ceil(PAGE_BYTES).max(1);
        let mut frames = Vec::new();
        for _ in 0..pages {
            match pmm::setup::alloc_object_frame() {
                Some(pa) => frames.push(pa),
                None => {
                    for got in frames.iter() { pmm::setup::release_object_frame(*got); }
                    return None;
                }
            }
        }
        Some(frames)
    }

    /// # C: O(pages)
    fn free(&self, frames: &[u64]) {
        for pa in frames { pmm::setup::release_object_frame(*pa); }
    }

    /// # C: O(1)
    fn page_bytes(&self) -> u32 { PAGE_BYTES }
}

/// Write `src` into the plane's pages starting at byte `off`, stopping at the
/// end of the plane. Used by a driver that produces frames in software.
/// # C: O(src.len)
pub fn write_plane(frames: &[u64], off: usize, src: &[u8]) -> usize {
    let page = PAGE_BYTES as usize;
    let mut written = 0usize;
    while written < src.len() {
        let at = off + written;
        let index = at / page;
        let Some(pa) = frames.get(index) else { break };
        let Some(base) = pmm::setup::frame_ptr(*pa) else { break };
        let within = at % page;
        let take = core::cmp::min(page - within, src.len() - written);
        // SAFETY: `pa` is a frame this allocator owns for the lifetime of the
        // plane and `within + take` is bounded by the page size, so the write
        // stays inside the one frame `frame_ptr` resolved.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().add(written), base.add(within), take); }
        written += take;
    }
    written
}

/// Read bytes from a plane's pages into kernel-owned storage. # C: O(dst.len)
pub fn read_plane(frames: &[u64], off: usize, dst: &mut [u8]) -> usize {
    let page = PAGE_BYTES as usize;
    let mut read = 0usize;
    while read < dst.len() {
        let at = off + read;
        let index = at / page;
        let Some(pa) = frames.get(index) else { break };
        let Some(base) = pmm::setup::frame_ptr(*pa) else { break };
        let within = at % page;
        let take = core::cmp::min(page - within, dst.len() - read);
        // SAFETY: `pa` is a frame this allocator owns for the lifetime of the
        // plane and `within + take` is bounded by the page size, so the read
        // stays inside the one frame `frame_ptr` resolved.
        unsafe { core::ptr::copy_nonoverlapping(base.add(within), dst.as_mut_ptr().add(read), take); }
        read += take;
    }
    read
}

/// Fill the whole plane with one byte value. # C: O(pages)
pub fn fill_plane(frames: &[u64], value: u8) {
    for pa in frames {
        let Some(base) = pmm::setup::frame_ptr(*pa) else { continue };
        // SAFETY: one whole frame this allocator owns; the length is exactly
        // the frame size `frame_ptr` resolved.
        unsafe { core::ptr::write_bytes(base, value, PAGE_BYTES as usize); }
    }
}
