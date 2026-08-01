// The BSS-resident boot heap handed to `KAlloc::init_static`.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

use crate::limits::STATIC_HEAP_SIZE;

/// Bump-aligned BSS storage. `align(4096)` keeps the heap page-aligned
/// so future mappings can be relaxed at page granularity.
#[repr(C, align(4096))]
pub(crate) struct StaticHeap(pub(crate) UnsafeCell<MaybeUninit<[u8; STATIC_HEAP_SIZE]>>);

// SAFETY: cross-thread access is mediated by `KAlloc`'s internal
// Spinlock; the raw bytes are uninitialized BSS and only handed out
// via `KAlloc::init_static`.
unsafe impl Sync for StaticHeap {}

pub(crate) static STATIC_HEAP: StaticHeap = StaticHeap(UnsafeCell::new(MaybeUninit::uninit()));
