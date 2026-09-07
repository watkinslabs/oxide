//! Input-context ordinals: create, destroy, query, update, associate, list,
//! the thread IME disable, and the IME status notification. Every decision
//! here is the reference's; the objects themselves belong to the canonical
//! per-process input-context owner.
pub(crate) const ASSOCIATE_ORDINAL: u64 = 0x1321;
pub(crate) const BUILD_HIMC_LIST_ORDINAL: u64 = 0x132c;
pub(crate) const CREATE_ORDINAL: u64 = 0x1364;
pub(crate) const DESTROY_ORDINAL: u64 = 0x1381;
pub(crate) const DISABLE_THREAD_IME_ORDINAL: u64 = 0x1389;
pub(crate) const NOTIFY_IME_STATUS_ORDINAL: u64 = 0x14be;
pub(crate) const QUERY_ORDINAL: u64 = 0x14dd;
pub(crate) const UPDATE_ORDINAL: u64 = 0x15e5;

/// The handle-based ordinals report this Win32 error for a handle the
/// input-context object type does not own.
pub(crate) const ERROR_INVALID_HANDLE: u64 = 6;

pub(crate) const STATUS_SUCCESS: u64 = 0;
pub(crate) const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
pub(crate) const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

/// A HIMC is a user handle; the client passes the whole machine word.
/// # C: O(1)
pub(crate) fn handle_index(himc: u64) -> Option<u32> { u32::try_from(himc).ok().filter(|raw| *raw != 0) }

/// `NtUserBuildHimcList` reads the calling thread when the client names no
/// thread, exactly as the reference substitutes the current thread id. # C: O(1)
pub(crate) fn list_thread(requested: u64, current_tid: u64) -> u64 {
    if requested as u32 == 0 { current_tid } else { requested as u32 as u64 }
}

/// The count argument is a UINT element count; a buffer word is eight bytes
/// wide and the total must not wrap the address space. # C: O(1)
pub(crate) fn list_bounds(buffer: u64, count: u64) -> Option<(u64, usize)> {
    if buffer == 0 { return None; }
    let count = count as u32 as usize;
    let bytes = u64::try_from(count).ok()?.checked_mul(HIMC_BYTES)?;
    buffer.checked_add(bytes)?;
    Some((buffer, count))
}

/// One HIMC element in the client's list buffer.
pub(crate) const HIMC_BYTES: u64 = 8;

#[cfg(target_os = "oxide-kernel")]
#[path = "input_context/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/input_context.rs"]
mod tests;
