// Memory-management syscall wrappers (docs/59§6 G8): madvise, mlock family,
// msync, mremap, sbrk, valloc. Thin: parse args, syscall, errno=-ret &
// return -1 on negative. Constants live in posix::mman. Both arches share
// the slots. sbrk tracks the program break via a process-global cell seeded
// from brk(0); valloc = aligned_alloc(pagesize, len) through the crate heap.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys0, sys1, sys2, sys3, sys5};
use crate::internal::errno::{ret_isize, set};
use crate::internal::nr;
use core::sync::atomic::{AtomicUsize, Ordering};

const ENOMEM: i32 = 12;
const PAGE_SIZE: usize = 4096;

// # C: int madvise(void *addr, size_t len, int advice)
#[no_mangle]
pub unsafe extern "C" fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32 {
    // SAFETY: madvise(2) takes a scalar addr/len/advice; the kernel validates
    // the range against the caller mapping and never writes through addr.
    ret_isize(unsafe { sys3(nr::MADVISE, addr as usize, len, advice as usize) }) as i32
}
// # C: int posix_madvise(void *addr, size_t len, int advice) — returns errno.
#[no_mangle]
pub unsafe extern "C" fn posix_madvise(addr: *mut u8, len: usize, advice: i32) -> i32 {
    // SAFETY: same kernel call as madvise; POSIX form returns the errno value
    // directly (0 on success) rather than via the errno cell.
    let r = unsafe { sys3(nr::MADVISE, addr as usize, len, advice as usize) };
    if r < 0 { -r as i32 } else { 0 }
}
// # C: int mlock(const void *addr, size_t len)
#[no_mangle]
pub unsafe extern "C" fn mlock(addr: *const u8, len: usize) -> i32 {
    // SAFETY: mlock(2) takes a scalar addr/len; the kernel validates the range.
    ret_isize(unsafe { sys2(nr::MLOCK, addr as usize, len) }) as i32
}
// # C: int munlock(const void *addr, size_t len)
#[no_mangle]
pub unsafe extern "C" fn munlock(addr: *const u8, len: usize) -> i32 {
    // SAFETY: munlock(2) takes a scalar addr/len; the kernel validates the range.
    ret_isize(unsafe { sys2(nr::MUNLOCK, addr as usize, len) }) as i32
}
// # C: int mlockall(int flags)
#[no_mangle]
pub unsafe extern "C" fn mlockall(flags: i32) -> i32 {
    // SAFETY: mlockall(2) takes a scalar flags word; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::MLOCKALL, flags as usize) }) as i32
}
// # C: int munlockall(void)
#[no_mangle]
pub unsafe extern "C" fn munlockall() -> i32 {
    // SAFETY: munlockall(2) takes no args; no memory is dereferenced.
    ret_isize(unsafe { sys0(nr::MUNLOCKALL) }) as i32
}
// # C: int msync(void *addr, size_t len, int flags)
#[no_mangle]
pub unsafe extern "C" fn msync(addr: *mut u8, len: usize, flags: i32) -> i32 {
    // SAFETY: msync(2) takes a scalar addr/len/flags; the kernel validates the
    // mapped range and flushes it, never writing through addr from libc.
    ret_isize(unsafe { sys3(nr::MSYNC, addr as usize, len, flags as usize) }) as i32
}
// # C: void *mremap(void *old, size_t oldsz, size_t newsz, int flags, ... /* new_addr */)
#[no_mangle]
pub unsafe extern "C" fn mremap(old: *mut u8, oldsz: usize, newsz: usize, flags: i32, new_addr: *mut u8) -> *mut u8 {
    // SAFETY: mremap(2); the 5th arg (new_addr) is only consulted for
    // MREMAP_FIXED, otherwise ignored by the kernel; addr/sizes are scalars
    // and the kernel never writes through them from libc.
    let r = unsafe { sys5(nr::MREMAP, old as usize, oldsz, newsz, flags as usize, new_addr as usize) };
    if (-4095..=-1).contains(&r) { set(-r as i32); usize::MAX as *mut u8 } else { r as *mut u8 }
}

// Program break tracker for sbrk(3). Seeded lazily from brk(0).
static CURBRK: AtomicUsize = AtomicUsize::new(0);

// # C: void *sbrk(intptr_t incr) — return old break, or (void*)-1 + errno.
#[no_mangle]
pub unsafe extern "C" fn sbrk(incr: isize) -> *mut u8 {
    // SAFETY: brk(2) returns the resulting program break (a scalar); no memory
    // is dereferenced. We snapshot the break, request old+incr, and verify the
    // kernel honoured it before publishing the new value.
    unsafe {
        let mut cur = CURBRK.load(Ordering::Relaxed);
        if cur == 0 {
            cur = sys1(nr::BRK, 0) as usize;
            CURBRK.store(cur, Ordering::Relaxed);
        }
        if incr == 0 { return cur as *mut u8; }
        let want = (cur as isize).wrapping_add(incr) as usize;
        let got = sys1(nr::BRK, want) as usize;
        if got < want { set(ENOMEM); return usize::MAX as *mut u8; }
        CURBRK.store(got, Ordering::Relaxed);
        cur as *mut u8
    }
}

// # C: void *valloc(size_t size) — page-aligned allocation via the crate heap.
#[no_mangle]
pub unsafe extern "C" fn valloc(size: usize) -> *mut u8 {
    // SAFETY: routes to the crate allocator's page-aligned path; PAGE_SIZE is a
    // power of two so the alignment contract of aligned_alloc holds.
    unsafe { crate::malloc::api::aligned_alloc(PAGE_SIZE, size) }
}
// # C: void *pvalloc(size_t size) — page-aligned, size rounded up to a page.
#[no_mangle]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut u8 {
    // legacy glibc pvalloc rounds the request up to a whole page.
    let rounded = size.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    // SAFETY: PAGE_SIZE is a power of two so the alignment contract of
    // aligned_alloc holds; routes to the crate allocator's page-aligned path.
    unsafe { crate::malloc::api::aligned_alloc(PAGE_SIZE, rounded) }
}
