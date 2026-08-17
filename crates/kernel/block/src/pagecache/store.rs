//! One cached page's storage, and the frame provider that lets a cached page
//! BE a machine frame.
//!
//! A cached page's bytes live in exactly ONE place. Which place depends on
//! whether anything has asked to MAP the page: a page nobody maps is a heap
//! buffer, and a page a user page table must point at is a machine frame. The
//! conversion is IN PLACE and one-way — the bytes are moved into the frame and
//! the heap buffer is dropped in the same step — so there is never a moment at
//! which two copies of one page exist, and once [`PageBuf::pa`] answers it
//! keeps answering the same frame for as long as the page is resident.
//!
//! Why this is not the default representation: a frame costs the whole
//! frame-lifetime contract (a refcount every mapper holds, a mapcount the
//! eviction guard reads, a buddy round trip on free) and the overwhelming
//! majority of cached pages are read and written by `read(2)`/`write(2)` and
//! never mapped. Converting on demand pays that cost per MAPPED page instead
//! of per cached page, and leaves the un-mapped path byte-identical to what it
//! was.
//!
//! Why it exists at all: without it a shared writable `mmap` of a file whose
//! pages live here cannot be satisfied. The fault path falls back to a private
//! copy-on-write page, the store lands in that copy, and an `msync` reports
//! success having persisted nothing — silent loss of a write the caller was
//! told had succeeded.
//!
//! The provider is INSTALLED rather than called directly because the frame
//! allocator's crate depends on this one, not the other way round; the machine
//! installs it on the way up, exactly as it installs the managed-page count
//! the dirty thresholds are a percentage of (`global`). A build with no
//! provider installed — a hosted test, or the window before the allocator is
//! up — keeps every page on the heap and answers `None` for its address,
//! which is the honest answer: there is no frame.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::types::PAGE_BYTES;

/// How the page cache reaches the machine's frame allocator.
///
/// Function pointers rather than a trait object so the record is a `&'static`
/// constant in the installing crate and the page cache never allocates to
/// reach it.
pub struct FrameProvider {
    /// One frame owned by a kernel object, refcount 1, mapcount 0.
    pub alloc: fn() -> Option<u64>,
    /// The kernel-side pointer for a frame the caller owns.
    pub ptr: fn(u64) -> Option<*mut u8>,
    /// Return the object's reference. Frees the frame only once every mapper
    /// has dropped its own reference too.
    /// # Safety: `pa` must be a frame this cache owns a reference to.
    pub release: unsafe fn(u64),
    /// Whether any user page table maps this frame right now.
    pub mapped: fn(u64) -> bool,
}

static PROVIDER: AtomicPtr<FrameProvider> = AtomicPtr::new(core::ptr::null_mut());

/// Name the machine's frame allocator, so a cached page can become a frame a
/// user page table may point at. Installed once, on the way up. # C: O(1)
pub fn install_frame_provider(provider: &'static FrameProvider) {
    PROVIDER.store(provider as *const FrameProvider as *mut FrameProvider, Ordering::Release);
}

/// # C: O(1)
fn provider() -> Option<&'static FrameProvider> {
    // SAFETY: the pointer is either null or the address of a `&'static
    // FrameProvider` passed to `install_frame_provider`, which never dangles.
    unsafe { PROVIDER.load(Ordering::Acquire).as_ref() }
}

/// Whether a cached page can be made mappable at all. # C: O(1)
pub fn frames_available() -> bool { provider().is_some() }

/// One cached page's bytes: a heap buffer, or a machine frame.
///
/// Exactly one of the two at any moment. `frame` is zero while the bytes are
/// on the heap, and `heap` is empty once they are in a frame.
pub struct PageBuf {
    frame: u64,
    heap:  Vec<u8>,
}

impl PageBuf {
    /// A zeroed page on the heap. # C: O(page)
    pub fn zeroed() -> Self { Self { frame: 0, heap: vec![0u8; PAGE_BYTES] } }

    /// Take ownership of `bytes` as a page's storage. # C: O(1)
    pub fn from_vec(bytes: Vec<u8>) -> Self { Self { frame: 0, heap: bytes } }

    /// The frame holding these bytes, or `None` while they are on the heap.
    /// # C: O(1)
    pub fn pa(&self) -> Option<u64> { if self.frame == 0 { None } else { Some(self.frame) } }

    /// Move these bytes into a machine frame, if they are not already in one,
    /// and report its address.
    ///
    /// One-way and in place: on success the heap buffer is released in the same
    /// call that publishes the frame, so no caller can ever observe both. On
    /// failure the bytes stay exactly where they were and the page stays
    /// unmappable rather than becoming a second copy.
    /// # C: O(page)
    pub fn to_frame(&mut self) -> Option<u64> {
        if self.frame != 0 { return Some(self.frame); }
        let p = provider()?;
        let pa = (p.alloc)()?;
        let base = match (p.ptr)(pa) {
            Some(base) => base,
            None => {
                // SAFETY: `pa` came from this provider's `alloc` and nothing
                // else has seen it, so this cache holds its only reference.
                unsafe { (p.release)(pa); }
                return None;
            }
        };
        let n = core::cmp::min(self.heap.len(), PAGE_BYTES);
        // SAFETY: `base` is the kernel-side mapping of a PAGE_BYTES frame this
        // call owns; `self.heap` is a distinct heap allocation of at most that
        // many bytes, so the two do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(self.heap.as_ptr(), base, n);
            if n < PAGE_BYTES { core::ptr::write_bytes(base.add(n), 0, PAGE_BYTES - n); }
        }
        self.heap = Vec::new();
        self.frame = pa;
        Some(pa)
    }

    /// Whether a user page table maps this page's frame right now.
    ///
    /// A page in that state may not be dropped from the cache on a HINT: the
    /// mapper would keep writing a frame the cache no longer knows about, and
    /// the next fill of the same offset would hand out a different frame — the
    /// two would then disagree about the file for as long as both existed.
    /// # C: O(1)
    pub fn user_mapped(&self) -> bool {
        match (self.pa(), provider()) { (Some(pa), Some(p)) => (p.mapped)(pa), _ => false }
    }

    /// # C: O(1)
    fn bytes(&self) -> &[u8] {
        match (self.frame, provider()) {
            (0, _) => &self.heap,
            // SAFETY: a non-zero `frame` was produced by the installed
            // provider's `alloc`, is owned by this page for its whole life, and
            // `ptr` returns the kernel-side mapping of its PAGE_BYTES span.
            (pa, Some(p)) => match (p.ptr)(pa) { Some(b) => unsafe { core::slice::from_raw_parts(b, PAGE_BYTES) }, None => &[] },
            (_, None) => &[],
        }
    }

    /// # C: O(1)
    fn bytes_mut(&mut self) -> &mut [u8] {
        match (self.frame, provider()) {
            (0, _) => &mut self.heap,
            // SAFETY: as `bytes`, and `&mut self` excludes every other holder
            // of this page's storage for the borrow.
            (pa, Some(p)) => match (p.ptr)(pa) { Some(b) => unsafe { core::slice::from_raw_parts_mut(b, PAGE_BYTES) }, None => &mut [] },
            (_, None) => &mut [],
        }
    }
}

impl Deref for PageBuf {
    type Target = [u8];
    /// # C: O(1)
    fn deref(&self) -> &[u8] { self.bytes() }
}

impl DerefMut for PageBuf {
    /// # C: O(1)
    fn deref_mut(&mut self) -> &mut [u8] { self.bytes_mut() }
}

impl PartialEq<[u8]> for PageBuf {
    /// # C: O(page)
    fn eq(&self, other: &[u8]) -> bool { self.bytes() == other }
}

impl PartialEq<Vec<u8>> for PageBuf {
    /// # C: O(page)
    fn eq(&self, other: &Vec<u8>) -> bool { self.bytes() == other.as_slice() }
}

impl PartialEq for PageBuf {
    /// # C: O(page)
    fn eq(&self, other: &Self) -> bool { self.bytes() == other.bytes() }
}

impl core::fmt::Debug for PageBuf {
    /// # C: O(1)
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(if self.frame == 0 { "PageBuf(heap)" } else { "PageBuf(frame)" })
    }
}

impl Drop for PageBuf {
    /// Return the object reference this page held.
    ///
    /// The frame is freed only once every mapper has dropped its own reference
    /// as well, which is what makes dropping a still-mapped page safe rather
    /// than a use-after-free: the mapper's reference outlives the cache's.
    /// # C: O(1)
    fn drop(&mut self) {
        if self.frame == 0 { return; }
        let Some(p) = provider() else { return; };
        // SAFETY: this page owns the reference `to_frame` took and drops it
        // exactly once; the frame itself survives while any mapper holds one.
        unsafe { (p.release)(self.frame); }
        self.frame = 0;
    }
}

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
