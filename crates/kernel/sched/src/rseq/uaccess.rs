// User access for the rseq paths.
//
// Every access goes through the exception-table-backed `uaccess` crate
// (`hal_{x86_64,aarch64}::raw_copy_{to,from}_user`), never a raw CPL=0
// dereference: `rseq_ptr` is validated once at registration but user space
// can `munmap`/`mprotect` the area afterwards, and the `rseq_cs` descriptor
// address is entirely user-controlled. A bare volatile store through either
// would #PF in the kernel with no recovery — here an unmapped page is just
// `Err(Efault)`, exactly as Linux's `unsafe_put_user(..., efault)` labels.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::rseq as abi;

/// Linux `access_ok`: `[ptr, ptr+len)` lies inside the user half. Says
/// nothing about whether the pages are mapped — the copy helpers report
/// that. # C: O(1)
pub fn user_range_ok(ptr: u64, len: u64) -> bool {
    if ptr == 0 { return false; }
    if len == 0 { return ptr < hal::USER_VA_END; }
    ptr < hal::USER_VA_END
        && ptr.checked_add(len).map(|e| e <= hal::USER_VA_END).unwrap_or(false)
}

/// Linux `unsafe_get_user(u32)`. # C: O(1)
pub fn get_u32(va: u64) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    ::uaccess::copy_from_user(&mut b, va)?;
    Ok(u32::from_ne_bytes(b))
}

/// Linux `unsafe_get_user(u64)`. # C: O(1)
pub fn get_u64(va: u64) -> Result<u64, Errno> {
    let mut b = [0u8; 8];
    ::uaccess::copy_from_user(&mut b, va)?;
    Ok(u64::from_ne_bytes(b))
}

/// Linux `unsafe_put_user(u32)`. # C: O(1)
pub fn put_u32(va: u64, v: u32) -> Result<(), Errno> {
    ::uaccess::copy_to_user(va, &v.to_ne_bytes())
}

/// Linux `unsafe_put_user(u64)`. # C: O(1)
pub fn put_u64(va: u64, v: u64) -> Result<(), Errno> {
    ::uaccess::copy_to_user(va, &v.to_ne_bytes())
}

/// Publish the four kernel-owned id fields. Shared by registration,
/// unregistration and the exit-to-user writeback so the offsets appear once.
/// # C: O(1)
pub fn put_ids(ptr: u64, cpu_id: u32, node_id: u32, mm_cid: u32) -> Result<(), Errno> {
    put_u32(ptr + abi::RSEQ_OFF_CPU_ID_START, cpu_id)?;
    put_u32(ptr + abi::RSEQ_OFF_CPU_ID, cpu_id)?;
    put_u32(ptr + abi::RSEQ_OFF_NODE_ID, node_id)?;
    put_u32(ptr + abi::RSEQ_OFF_MM_CID, mm_cid)
}

/// Linux `rseq_register`'s user-side initialisation: drop any stale
/// `rseq_cs` (older libcs recycle the area for new threads without clearing
/// it, and a stale descriptor would fault the first abort), publish the
/// feature-flag word, and park the ids at the "uninitialised" sentinel until
/// `super::exit::rseq_writeback` fills them in.
///
/// Returns false when the area is not writable — the caller reports EFAULT.
/// # C: O(1)
pub fn init_area(ptr: u64) -> bool {
    let done = put_u64(ptr + abi::RSEQ_OFF_RSEQ_CS, 0)
        // No slice-extension feature bits: oxide never advertises
        // RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE, so the word stays clear.
        .and_then(|()| put_u32(ptr + abi::RSEQ_OFF_FLAGS, 0))
        .and_then(|()| put_ids(ptr, abi::RSEQ_CPU_ID_UNINITIALIZED, 0, 0));
    done.is_ok()
}

/// Linux `rseq_reset_ids`, run on unregistration. # C: O(1)
pub fn reset_ids(ptr: u64) -> bool {
    put_ids(ptr, abi::RSEQ_CPU_ID_UNINITIALIZED, 0, 0).is_ok()
}

/// Mark the registration permanently failed. Linux force-`SIGSEGV`s the task
/// on a bad `rseq_cs`; the area keeps `RSEQ_CPU_ID_REGISTRATION_FAILED` so a
/// surviving sibling reading the same TLS copy cannot mistake it for a cpu
/// number. Best effort — the area may already be gone, which is often why
/// the task is dying. # C: O(1)
pub fn mark_registration_failed(cur: &crate::Task) {
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return; }
    let _ = put_u32(ptr + abi::RSEQ_OFF_CPU_ID_START, abi::RSEQ_CPU_ID_REGISTRATION_FAILED);
    let _ = put_u32(ptr + abi::RSEQ_OFF_CPU_ID, abi::RSEQ_CPU_ID_REGISTRATION_FAILED);
}
