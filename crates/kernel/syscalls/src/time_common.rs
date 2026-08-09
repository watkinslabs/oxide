// Production wrapper: unit tests belong to this canonical module only.
// Integration harnesses that need the implementation directly include
// `time_common/core.rs`, so their crate-level `cfg(test)` cannot replay this
// unit-test manifest.

include!("time_common/core.rs");

/// Read a user `struct timespec` (Linux `get_timespec64`).
///
/// Goes through the exception-table copy, so an address that is inside the
/// user range but not mapped answers `EFAULT` instead of faulting the kernel
/// at a raw dereference. A range check alone cannot do this: it proves only
/// that the number is small enough, not that anything is there.
///
/// Lives in this wrapper and not in `core.rs`: that file is `#[path]`-included
/// by harnesses in other crates, which do not depend on `uaccess` and must not
/// have to. The layout half stays there as `decode_timespec`, where they can
/// still reach and test it.
/// # C: O(1)
pub(crate) fn read_user_timespec(ptr: u64) -> Result<(i64, i64), Errno> {
    let mut raw = [0u8; TIMESPEC_BYTES];
    uaccess::copy_from_user(&mut raw, ptr)?;
    Ok(decode_timespec(&raw))
}

#[cfg(test)]
#[path = "time_common/tests.rs"]
mod tests;
