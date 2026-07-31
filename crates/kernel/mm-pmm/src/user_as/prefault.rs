// Eager population of a range in an address space that is not the running
// task's (Linux `setup_arg_pages`' populate step).
//
// Every writer of a fresh initial stack runs in kernel context: the demand
// fault handler resolves against the RUNNING task's address space, which for a
// boot path or a worker thread is not the one being written. Populating up
// front is what makes those writes land.

use core::sync::atomic::Ordering;

use hal::UserVirtAddr;
use vmm::AddressSpace;

use super::fault::do_handle;
use super::{FaultAccess, FaultKind, HHDM_OFFSET};

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// Fault in every page of `[top - len, top)` in `as_`.
/// # C: O(len / PAGE)
pub fn prefault_stack(as_: &AddressSpace, top: u64, len: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut va = top.saturating_sub(len) & !PAGE_MASK;
    while va < top {
        if let Some(uva) = UserVirtAddr::new(va) {
            // Kernel-initiated prefault, so the user-mode fault flag is clear —
            // only an architecture fault vector sets it.
            let _ = do_handle(as_, uva, FaultKind::NotPresent { access: FaultAccess::Write }, hhdm, false);
        }
        va += PAGE_BYTES;
    }
}
