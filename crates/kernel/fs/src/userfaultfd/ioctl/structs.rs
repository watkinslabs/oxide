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

/// Read a request object out of already-validated user memory.
/// # SAFETY: `arg` must have been validated for at least `size_of::<T>()` bytes.
/// # C: O(size_of::<T>)
pub unsafe fn read_req<T>(arg: u64) -> T {
    // SAFETY: per fn contract the caller validated `arg` for the whole object; the read is unaligned-safe.
    unsafe { core::ptr::read_unaligned(arg as *const T) }
}

/// Write one trailing reply word into an already-validated request object.
/// # C: O(1)
pub fn write_reply(slot: u64, value: i64) {
    // SAFETY: `slot` is the trailing reply word inside a request object the caller already validated writable for its full size.
    unsafe { core::ptr::write_unaligned(slot as *mut i64, value); }
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
