// Whole-record transfers for the ABI structs a slot exchanges with its caller.
//
// A `repr(C)` record with no padding-sensitive invariant is bytes on the wire;
// moving it through the fault-recoverable usercopy costs one stack copy and
// buys the `__ex_table` recovery a typed dereference can never have.

use core::mem::{MaybeUninit, size_of};
use syscall::errno::Errno;

/// Marker for a record that is safe to materialise from arbitrary caller bytes:
/// `repr(C)`, every bit pattern valid, no pointer or reference field.
///
/// # Safety
/// Implementor asserts every byte pattern of `size_of::<Self>()` bytes is a
/// valid value of the type.
pub(crate) unsafe trait UserPod: Copy {}

// SAFETY: integer and byte-array records below have no invalid bit pattern.
unsafe impl UserPod for u8 {}
// SAFETY: as above.
unsafe impl UserPod for i8 {}
// SAFETY: as above.
unsafe impl UserPod for u32 {}
// SAFETY: as above.
unsafe impl UserPod for u64 {}

/// Fetch one caller record. # C: O(size_of::<T>())
pub(crate) fn get_pod<T: UserPod>(addr: u64) -> Result<T, Errno> {
    let mut v: MaybeUninit<T> = MaybeUninit::uninit();
    // SAFETY: the slice spans exactly the record's own storage, which is live and
    // uninitialised until copy_from_user fills or zeroes every byte of it.
    let dst = unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, size_of::<T>()) };
    uaccess::copy_from_user(dst, addr)?;
    // SAFETY: copy_from_user wrote every byte on success, and T admits any bit pattern.
    Ok(unsafe { v.assume_init() })
}

/// Store one caller record. # C: O(size_of::<T>())
pub(crate) fn put_pod<T: UserPod>(addr: u64, v: T) -> Result<(), Errno> {
    // SAFETY: the slice spans the live local's own storage for exactly its size.
    let src = unsafe { core::slice::from_raw_parts(&v as *const T as *const u8, size_of::<T>()) };
    uaccess::copy_to_user(addr, src)
}
