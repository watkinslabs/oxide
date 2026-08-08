// The range validators every userfaultfd op begins with.

use syscall::errno::Errno;

/// Page mask used by the range validators.
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

/// The first VA above the user half for a native 64-bit task.
#[inline]
fn task_size() -> u64 { hal::USER_VA_END }

/// `len` must be a non-zero page multiple and `[start, start+len)` must fit
/// below the task's address-space end; `start` itself may be unaligned (only a
/// copy's SOURCE uses this variant). Every failure is EINVAL.
/// # C: O(1)
pub fn validate_unaligned_range(start: u64, len: u64) -> Result<(), Errno> {
    if len & !PAGE_MASK != 0 { return Err(Errno::Einval); }
    if len == 0 { return Err(Errno::Einval); }
    if start >= task_size() { return Err(Errno::Einval); }
    if len > task_size() - start { return Err(Errno::Einval); }
    if start.checked_add(len).is_none_or(|end| end <= start) { return Err(Errno::Einval); }
    Ok(())
}

/// [`validate_unaligned_range`] plus a page-aligned `start`. Used for every
/// range a uffd op INSTALLS into, PROTECTS, MOVES or REGISTERS.
/// # C: O(1)
pub fn validate_range(start: u64, len: u64) -> Result<(), Errno> {
    if start & !PAGE_MASK != 0 { return Err(Errno::Einval); }
    validate_unaligned_range(start, len)
}
