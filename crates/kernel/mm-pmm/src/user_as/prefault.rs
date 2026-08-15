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

/// Populate every page overlapping `[start, start + len)` in `as_`.
///
/// The caller supplies the destination mm explicitly because this path runs
/// before a new image can safely perform direct writes through its user VAs.
/// # C: O(len / PAGE)
pub fn prefault_user_range(as_: &AddressSpace, start: u64, len: u64) -> Result<(), vmm::Error> {
    if len == 0 { return Ok(()); }
    let end = start.checked_add(len).ok_or(vmm::Error::Inval)?;
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut va = start & !PAGE_MASK;
    while va < end {
        let uva = UserVirtAddr::new(va).ok_or(vmm::Error::Inval)?;
        // Kernel-initiated population, so the user-mode fault flag is clear —
        // only an architecture fault vector sets it.
        do_handle(as_, uva, FaultKind::NotPresent { access: FaultAccess::Write }, hhdm, false)?;
        va = va.checked_add(PAGE_BYTES).ok_or(vmm::Error::Inval)?;
    }
    Ok(())
}

/// Fault in every page of `[top - len, top)` in `as_`.
/// # C: O(len / PAGE)
pub fn prefault_stack(as_: &AddressSpace, top: u64, len: u64) {
    if let Some(start) = top.checked_sub(len) { let _ = prefault_user_range(as_, start, len); }
}
