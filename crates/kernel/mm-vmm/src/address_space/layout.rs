use hal::{UserVirtAddr, PAGE_SIZE_BYTES};

use crate::{Error, KResult};

#[inline]
pub(super) fn is_aligned(va: UserVirtAddr) -> bool {
    va.as_u64() % PAGE_SIZE_BYTES == 0
}

#[inline]
pub(super) fn validate_aligned(va: UserVirtAddr) -> KResult<()> {
    if is_aligned(va) { Ok(()) } else { Err(Error::Inval) }
}

#[inline]
pub(super) fn validate_len(len: usize) -> KResult<()> {
    if len == 0 || (len as u64) % PAGE_SIZE_BYTES != 0 {
        Err(Error::Inval)
    } else {
        Ok(())
    }
}

#[inline]
pub(super) fn end_of(start: UserVirtAddr, len: u64) -> KResult<UserVirtAddr> {
    let end = start.as_u64().checked_add(len).ok_or(Error::Inval)?;
    UserVirtAddr::new(end).ok_or(Error::Inval)
}
