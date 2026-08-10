// The UFFDIO_* request objects and the handful of helpers every handler uses
// to read one in and write its reply field back.

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::userfaultfd::UfData;

/// `struct uffdio_api` — `{ api, features, ioctls }`. The 24 in the request
/// encoding is the authority on this size; a two-field version would leave
/// `ioctls` unwritten in every monitor's buffer.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct UffdioApi { pub api: u64, pub features: u64, pub ioctls: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioRange { pub start: u64, pub len: u64 }

/// `struct uffdio_register` — 32 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioRegister { pub range: UffdioRange, pub mode: u64, pub ioctls: u64 }

/// `struct uffdio_copy` — 40 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioCopy { pub dst: u64, pub src: u64, pub len: u64, pub mode: u64, pub copy: u64 }

/// `struct uffdio_zeropage`, `uffdio_continue` and `uffdio_poison` share this
/// shape: a range, a mode word, and one trailing reply field.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioRangeOp { pub range: UffdioRange, pub mode: u64, pub reply: u64 }

/// `struct uffdio_writeprotect` — 24 bytes, no reply field.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioWriteprotect { pub range: UffdioRange, pub mode: u64 }

/// `struct uffdio_move` — 40 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdioMove { pub dst: u64, pub src: u64, pub len: u64, pub mode: u64, pub moved: u64 }

/// Negative errno in syscall encoding. # C: O(1)
#[inline]
pub fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read a request object in, Linux `copy_from_user`. The range check every
/// caller runs first proves the address is inside the user half; it proves
/// nothing about a page being under it, so the copy itself carries the
/// `__ex_table` fixup and an unmapped object answers EFAULT.
///
/// `T` is one of the plain integer `uffdio_*` structs, so an all-zero value is
/// a valid `T` and the destination needs no other initialisation.
/// # C: O(size_of::<T>)
pub fn read_req<T: Copy>(arg: u64) -> Result<T, Errno> {
    let mut val = core::mem::MaybeUninit::<T>::zeroed();
    // SAFETY: `val` owns size_of::<T>() writable bytes and T is a plain integer struct, so any byte pattern is a valid T.
    let dst = unsafe {
        core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, core::mem::size_of::<T>())
    };
    uaccess::copy_from_user(dst, arg)?;
    // SAFETY: the copy above filled every byte, and a zeroed T is valid regardless.
    Ok(unsafe { val.assume_init() })
}

/// Write one whole request object back, Linux `copy_to_user`. # C: O(size_of::<T>)
pub fn write_req<T: Copy>(arg: u64, val: &T) -> Result<(), Errno> {
    // SAFETY: `val` is a live T and every byte of a plain integer struct is initialised.
    let src = unsafe {
        core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
    };
    uaccess::copy_to_user(arg, src)
}

/// Write one trailing reply word into a request object, Linux `put_user`.
/// The monitor reads its byte count — or its errno — out of this slot, so a
/// write that cannot land is reported, never swallowed.
/// # C: O(1)
pub fn write_reply(slot: u64, value: i64) -> Result<(), Errno> {
    uaccess::copy_to_user(slot, &value.to_ne_bytes())
}

/// Whether the running task holds the capability the handshake's fork-event
/// arm requires; false when there is no current task (hosted tests).
/// # C: O(1)
pub fn cur_cap_sys_ptrace() -> bool {
    sched::current().map(|c| crate::userfaultfd::capable_sys_ptrace(&c)).unwrap_or(false)
}

/// Identity between a VMA's context and this one. Identity, not mere presence:
/// an op that publishes pages at an address must be issued by the monitor
/// responsible for that address.
/// # C: O(1)
pub fn ctx_is(vma_ctx: &Arc<dyn vmm::UffdContext>, ufd: &Arc<UfData>) -> bool {
    core::ptr::eq(Arc::as_ptr(vma_ctx) as *const u8, Arc::as_ptr(ufd) as *const u8)
}

#[cfg(test)]
#[path = "structs_tests.rs"]
mod tests;
