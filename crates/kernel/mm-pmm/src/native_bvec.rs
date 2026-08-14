// Native page-vector ABI bridge.
//
// `NativeBioVec` and `NativeIovIter` cross the native-driver boundary.  The
// iterator is always BVEC-shaped: its segment pointer names `NativeBioVec`,
// never an iovec-shaped substitute.  `NativeBvecPin` owns the references for
// a registered buffer; the bvec storage and its pin must outlive every I/O
// which receives `NativeIovIter`.

use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use crate::{NativePage, setup};

/// BVEC iterator kind in the native iterator ABI.
pub const ITER_BVEC: u8 = 2;
/// Iterator direction for data supplied to a device.
pub const ITER_SOURCE: u8 = 1;
/// Iterator direction for data received from a device.
pub const ITER_DEST: u8 = 0;

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// One contiguous physical-memory segment for a native block request.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NativeBioVec {
    pub bv_page:   *mut NativePage,
    pub bv_len:    u32,
    pub bv_offset: u32,
}

// SAFETY: NativeBioVec is immutable descriptor data after publication; its
// page pointer targets PMM's stable descriptor array and NativeBvecPin holds
// the matching atomic page/object references for every cross-thread user.
unsafe impl Send for NativeBioVec {}
// SAFETY: NativeBioVec exposes no mutable page access; PMM refcounts are
// atomic and descriptor lifetime is retained by NativeBvecPin ownership.
unsafe impl Sync for NativeBioVec {}

impl NativeBioVec {
    /// Build one native page-vector entry.  The caller supplies a descriptor
    /// from PMM's published native-page array.
    /// # C: O(1)
    pub const fn new(bv_page: *mut NativePage, bv_len: u32, bv_offset: u32) -> Self {
        Self { bv_page, bv_len, bv_offset }
    }
}

/// Native iterator ABI.  `bvec` is valid exactly while its backing bvec slice
/// and the corresponding [`NativeBvecPin`] remain live.
#[repr(C)]
pub struct NativeIovIter {
    pub iter_type:   u8,
    pub nofault:     u8,
    pub data_source: u8,
    _pad:            [u8; 5],
    pub iov_offset:  usize,
    pub bvec:        *const NativeBioVec,
    pub count:       usize,
    pub nr_segs:     usize,
}

// SAFETY: NativeIovIter only borrows immutable NativeBioVec storage.  The
// owner retains that storage and its NativeBvecPin for its complete lifetime.
unsafe impl Send for NativeIovIter {}
// SAFETY: NativeIovIter carries no mutable cursor state across the ABI; each
// native request owns its own iterator instance and retained bvec storage.
unsafe impl Sync for NativeIovIter {}

impl NativeIovIter {
    /// An empty BVEC iterator.  It carries the real BVEC tag even though no
    /// segment storage is needed.
    /// # C: O(1)
    pub const fn empty(direction: u8) -> Self {
        Self { iter_type: ITER_BVEC, nofault: 0, data_source: direction, _pad: [0; 5], iov_offset: 0, bvec: core::ptr::null(), count: 0, nr_segs: 0 }
    }
}

/// Construction failure before native memory has been exposed to a driver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NativeBvecError {
    BadDirection,
    CountExceedsSegments,
    NullPage,
    OffsetLengthOverflow,
    UnpublishedPage,
}

/// Borrowed typed owner for one ABI iterator.  It prevents safe code from
/// retaining the raw iterator after the bvec table has gone away.
pub struct NativeBvecIter<'a> {
    abi: NativeIovIter,
    _bvecs: PhantomData<&'a [NativeBioVec]>,
}

impl<'a> NativeBvecIter<'a> {
    /// Construct a BVEC iterator over the leading `count` bytes.
    /// # C: O(N_bvec)
    pub fn new(direction: u8, bvecs: &'a [NativeBioVec], count: usize) -> Result<Self, NativeBvecError> {
        if direction != ITER_SOURCE && direction != ITER_DEST { return Err(NativeBvecError::BadDirection); }
        let covered = bvecs.iter().try_fold(0usize, |sum, bv| sum.checked_add(bv.bv_len as usize)).ok_or(NativeBvecError::CountExceedsSegments)?;
        if count > covered { return Err(NativeBvecError::CountExceedsSegments); }
        let abi = if count == 0 { NativeIovIter::empty(direction) } else {
            NativeIovIter { iter_type: ITER_BVEC, nofault: 0, data_source: direction, _pad: [0; 5], iov_offset: 0, bvec: bvecs.as_ptr(), count, nr_segs: bvecs.len() }
        };
        Ok(Self { abi, _bvecs: PhantomData })
    }

    /// Mutable ABI view for one synchronous native-driver call.
    /// # C: O(1)
    pub fn abi_mut(&mut self) -> &mut NativeIovIter { &mut self.abi }

    /// Immutable ABI view for inspection or copy into driver-owned request state.
    /// # C: O(1)
    pub fn abi(&self) -> &NativeIovIter { &self.abi }
}

/// Reference lease for all pages covered by a registered native bvec table.
/// Drop releases exactly the PMM and descriptor references acquired by
/// [`Self::acquire`].  It is deliberately separate from `NativeBvecIter`:
/// imports only borrow an already-registered, pinned table and must not take
/// a second pin for every request.
pub struct NativeBvecPin<'a> {
    bvecs: &'a [NativeBioVec],
}

impl<'a> NativeBvecPin<'a> {
    /// Validate and pin every page covered by `bvecs`.
    /// # C: O(N_pages)
    pub fn acquire(bvecs: &'a [NativeBioVec]) -> Result<Self, NativeBvecError> {
        for bv in bvecs { for_each_page(*bv, validate_page)?; }
        for bv in bvecs { for_each_page(*bv, pin_page)?; }
        Ok(Self { bvecs })
    }
}

impl Drop for NativeBvecPin<'_> {
    fn drop(&mut self) {
        for bv in self.bvecs { let _ = for_each_page(*bv, unpin_page); }
    }
}

fn pages_in(bv: NativeBioVec) -> Result<usize, NativeBvecError> {
    if bv.bv_len == 0 { return Ok(0); }
    if bv.bv_page.is_null() { return Err(NativeBvecError::NullPage); }
    let end = u64::from(bv.bv_offset).checked_add(u64::from(bv.bv_len)).ok_or(NativeBvecError::OffsetLengthOverflow)?;
    Ok(((end + PAGE_BYTES - 1) / PAGE_BYTES) as usize)
}

fn for_each_page(mut bv: NativeBioVec, mut f: impl FnMut(*mut NativePage) -> Result<(), NativeBvecError>) -> Result<(), NativeBvecError> {
    let pages = pages_in(bv)?;
    for _ in 0..pages {
        f(bv.bv_page)?;
        // SAFETY: pages_in bounds this walk to descriptors of a validated
        // native-page run; each successor is checked before it is dereferenced.
        bv.bv_page = unsafe { bv.bv_page.add(1) };
    }
    Ok(())
}

fn validate_page(page: *mut NativePage) -> Result<(), NativeBvecError> {
    if page.is_null() { return Err(NativeBvecError::NullPage); }
    setup::native_page_pa(page).ok_or(NativeBvecError::UnpublishedPage).map(|_| ())
}

fn pin_page(page: *mut NativePage) -> Result<(), NativeBvecError> {
    let pa = setup::native_page_pa(page).ok_or(NativeBvecError::UnpublishedPage)?;
    // SAFETY: validate_page established that page points into PMM's stable
    // native descriptor array; this lease owns the matching decrement below.
    unsafe { (*page).refcount.fetch_add(1, Ordering::AcqRel); }
    // SAFETY: the descriptor resolves to a managed PMM page and this lease
    // retains exactly one non-PTE PMM reference until its Drop implementation.
    unsafe { setup::inc_object_ref(pa); }
    Ok(())
}

fn unpin_page(page: *mut NativePage) -> Result<(), NativeBvecError> {
    let pa = setup::native_page_pa(page).ok_or(NativeBvecError::UnpublishedPage)?;
    // SAFETY: NativeBvecPin::acquire incremented this exact native descriptor
    // once, and Drop runs once, so the atomic decrement has a matching owner.
    let prev = unsafe { (*page).refcount.fetch_sub(1, Ordering::AcqRel) };
    debug_assert!(prev > 0, "native bvec pin underflow");
    // SAFETY: NativeBvecPin::acquire took this matching non-PTE PMM reference.
    unsafe { setup::dec_object_ref_and_maybe_free_frame(pa); }
    Ok(())
}

const _: () = {
    assert!(core::mem::size_of::<NativeBioVec>() == 16);
    assert!(core::mem::offset_of!(NativeBioVec, bv_page) == 0);
    assert!(core::mem::offset_of!(NativeBioVec, bv_len) == 8);
    assert!(core::mem::offset_of!(NativeBioVec, bv_offset) == 12);
    assert!(core::mem::size_of::<NativeIovIter>() == 40);
    assert!(core::mem::offset_of!(NativeIovIter, bvec) == 16);
    assert!(core::mem::offset_of!(NativeIovIter, count) == 24);
    assert!(core::mem::offset_of!(NativeIovIter, nr_segs) == 32);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_layouts_and_bvec_tag_are_pinned() {
        assert_eq!(core::mem::size_of::<NativeBioVec>(), 16);
        assert_eq!(core::mem::size_of::<NativeIovIter>(), 40);
        assert_eq!(core::mem::offset_of!(NativeIovIter, iov_offset), 8);
        assert_eq!(core::mem::offset_of!(NativeIovIter, bvec), 16);
        assert_eq!(ITER_BVEC, 2);
    }

    #[test]
    fn native_abi_descriptors_cross_the_registered_buffer_owner() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NativeBioVec>();
        assert_send_sync::<NativeIovIter>();
    }

    #[test]
    fn iterator_uses_the_bvec_table_never_iovec_storage() {
        let page = core::ptr::NonNull::<NativePage>::dangling().as_ptr();
        let bvecs = [NativeBioVec::new(page, 512, 0), NativeBioVec::new(page, 512, 512)];
        let mut iter = NativeBvecIter::new(ITER_SOURCE, &bvecs, 768).unwrap();
        let abi = iter.abi_mut();
        assert_eq!(abi.iter_type, ITER_BVEC);
        assert_eq!(abi.bvec, bvecs.as_ptr());
        assert_eq!(abi.count, 768);
        assert_eq!(abi.nr_segs, 2);
    }

    #[test]
    fn iterator_rejects_bad_direction_and_uncovered_count() {
        let bvecs = [NativeBioVec::new(core::ptr::null_mut(), 4, 0)];
        assert_eq!(NativeBvecIter::new(9, &bvecs, 0).err(), Some(NativeBvecError::BadDirection));
        assert_eq!(NativeBvecIter::new(ITER_DEST, &bvecs, 5).err(), Some(NativeBvecError::CountExceedsSegments));
    }

    #[test]
    fn pin_rejects_unpublished_descriptors_before_acquiring_any_reference() {
        let bvecs = [NativeBioVec::new(core::ptr::null_mut(), 1, 0)];
        assert_eq!(NativeBvecPin::acquire(&bvecs).err(), Some(NativeBvecError::NullPage));
    }

    #[test]
    fn page_span_accounts_for_a_nonzero_first_offset() {
        let bv = NativeBioVec::new(core::ptr::NonNull::<NativePage>::dangling().as_ptr(), PAGE_BYTES as u32, 1);
        assert_eq!(pages_in(bv), Ok(2));
    }
}
