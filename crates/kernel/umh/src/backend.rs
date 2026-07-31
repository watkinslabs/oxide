// The installable spawn backend.
//
// `exec.rs` owns every decision a caller can observe; this is the one piece
// that needs a live kernel (a worker thread, an address space, an ELF loader, a
// runqueue). It is installed once at boot, and replaced by a recording stub in
// hosted tests, so the decision logic above it is exercised without a kernel.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::info::SubprocessInfo;

/// What a backend did with the request.
pub enum HelperRun {
    /// The backend finished with the request and hands it back. `retval` inside
    /// it is the value the waiting caller reports.
    Done(Box<SubprocessInfo>),
    /// The backend took ownership and will release the request itself once the
    /// helper thread is done with it. Only legal for `UMH_NO_WAIT`, which is
    /// the mode that promises the caller no result.
    Detached,
}

/// Run one request. `info.wait` is already set to the submitted mode.
pub type HelperSpawnFn = fn(Box<SubprocessInfo>) -> HelperRun;

static BACKEND: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the backend. # C: O(1)
pub fn install(f: HelperSpawnFn) {
    BACKEND.store(f as *mut (), Ordering::Release);
}

/// True once a backend can run helpers. # C: O(1)
pub fn installed() -> bool { !BACKEND.load(Ordering::Acquire).is_null() }

/// Fetch the installed backend. # C: O(1)
pub fn get() -> Option<HelperSpawnFn> {
    let p = BACKEND.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: the slot only ever holds a `HelperSpawnFn` stored by `install`, and is cleared only by `clear_for_test`, so a non-null value is a live fn pointer of that exact type.
    Some(unsafe { core::mem::transmute::<*mut (), HelperSpawnFn>(p) })
}

/// Test-only: drop the installed backend so a test can assert the
/// no-backend path.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    BACKEND.store(core::ptr::null_mut(), Ordering::Release);
}
