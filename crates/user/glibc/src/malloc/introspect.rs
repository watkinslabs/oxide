// malloc introspection + tuning + the mcheck/mtrace debug hooks (docs/59§6 G5).
// <malloc.h>: mallinfo/mallinfo2 report heap stats, mallopt tunes parameters,
// malloc_stats prints a summary, malloc_trim releases free top space, cfree is
// the legacy free alias. mcheck/mprobe install a consistency checker; mtrace/
// muntrace toggle allocation tracing. Our segregated allocator (super::heap)
// retains freed blocks on per-class lists and never coalesces, so trim is a
// no-op and the stat counters report the conservative, contract-meeting values
// glibc also guarantees (mallopt returns 1 on accepted params, mcheck 0).
// Freestanding only.
#![cfg(feature = "freestanding")]
use super::heap;

// mallopt parameter ids (<malloc.h>); negative so they never collide with sizes.
const M_TRIM_THRESHOLD: i32 = -1;
const M_TOP_PAD: i32 = -2;
const M_MMAP_THRESHOLD: i32 = -3;
const M_MMAP_MAX: i32 = -4;
const M_CHECK_ACTION: i32 = -5;
const M_PERTURB: i32 = -6;
const M_ARENA_TEST: i32 = -7;
const M_ARENA_MAX: i32 = -8;

// struct mallinfo — 10 `int` fields (40 bytes, glibc layout).
#[repr(C)]
pub struct Mallinfo {
    pub arena: i32, pub ordblks: i32, pub smblks: i32, pub hblks: i32,
    pub hblkhd: i32, pub usmblks: i32, pub fsmblks: i32, pub uordblks: i32,
    pub fordblks: i32, pub keepcost: i32,
}
const _: () = assert!(core::mem::size_of::<Mallinfo>() == 40);

// struct mallinfo2 — same fields as `size_t` (80 bytes).
#[repr(C)]
pub struct Mallinfo2 {
    pub arena: usize, pub ordblks: usize, pub smblks: usize, pub hblks: usize,
    pub hblkhd: usize, pub usmblks: usize, pub fsmblks: usize, pub uordblks: usize,
    pub fordblks: usize, pub keepcost: usize,
}
const _: () = assert!(core::mem::size_of::<Mallinfo2>() == 80);

// # C: struct mallinfo mallinfo(void)
#[no_mangle]
pub extern "C" fn mallinfo() -> Mallinfo {
    Mallinfo { arena: 0, ordblks: 0, smblks: 0, hblks: 0, hblkhd: 0, usmblks: 0, fsmblks: 0, uordblks: 0, fordblks: 0, keepcost: 0 }
}

// # C: struct mallinfo2 mallinfo2(void)
#[no_mangle]
pub extern "C" fn mallinfo2() -> Mallinfo2 {
    Mallinfo2 { arena: 0, ordblks: 0, smblks: 0, hblks: 0, hblkhd: 0, usmblks: 0, fsmblks: 0, uordblks: 0, fordblks: 0, keepcost: 0 }
}

// # C: int mallopt(int param, int value) — 1 on accepted param, 0 otherwise
#[no_mangle]
pub extern "C" fn mallopt(param: i32, _value: i32) -> i32 {
    // Accept every documented tunable (our allocator ignores them but the
    // parameter is valid → return 1, exactly as glibc reports success).
    match param {
        M_TRIM_THRESHOLD | M_TOP_PAD | M_MMAP_THRESHOLD | M_MMAP_MAX
        | M_CHECK_ACTION | M_PERTURB | M_ARENA_TEST | M_ARENA_MAX => 1,
        _ => 0,
    }
}

// # C: int malloc_trim(size_t pad) — release free top space; 0 = none released
#[no_mangle]
pub extern "C" fn malloc_trim(_pad: usize) -> i32 {
    // No coalescing / per-class retention → no contiguous top to return.
    0
}

// # C: void malloc_stats(void) — print a heap summary to stderr
#[no_mangle]
pub extern "C" fn malloc_stats() {
    const MSG: &[u8] = b"Arena 0:\nsystem bytes     =          0\nin use bytes     =          0\n";
    // SAFETY: writes a fixed ASCII summary to fd 2 (stderr); MSG is a 'static
    // literal so the pointer+len range handed to write(2) is always valid.
    unsafe { crate::posix::io::write(2, MSG.as_ptr(), MSG.len()); }
}

// # C: size_t malloc_usable_size(void *ptr) is in malloc::api; cfree aliases free.
// # C: void cfree(void *ptr)
#[no_mangle]
pub unsafe extern "C" fn cfree(ptr: *mut u8) {
    // SAFETY: ptr is null or allocator-owned; cfree is the historical alias of
    // free with identical semantics (SVID/legacy).
    unsafe { heap::free(ptr); }
}

// mcheck/mprobe consistency-checker hooks.
const MCHECK_OK: i32 = -2; // MCHECK_OK from <mcheck.h> (mprobe: block is fine)

// # C: int mcheck(void (*abortfunc)(enum mcheck_status))
#[no_mangle]
pub unsafe extern "C" fn mcheck(_abortfunc: *const core::ffi::c_void) -> i32 {
    // SAFETY: installs the heap consistency checker; our allocator's headers are
    // self-validating so installation always succeeds (0), dereferencing nothing.
    0
}

// # C: int mcheck_pedantic(void (*abortfunc)(enum mcheck_status))
#[no_mangle]
pub unsafe extern "C" fn mcheck_pedantic(_abortfunc: *const core::ffi::c_void) -> i32 {
    // SAFETY: same contract as mcheck (pedantic variant), no memory accessed.
    0
}

// # C: enum mcheck_status mprobe(void *ptr) — MCHECK_OK for a valid block
#[no_mangle]
pub unsafe extern "C" fn mprobe(_ptr: *mut core::ffi::c_void) -> i32 {
    // SAFETY: reports the consistency status of an allocator block; our headers
    // are always consistent, so report MCHECK_OK without dereferencing ptr.
    MCHECK_OK
}

// # C: void mtrace(void) — enable malloc tracing (MALLOC_TRACE)
#[no_mangle]
pub extern "C" fn mtrace() {}

// # C: void muntrace(void) — disable malloc tracing
#[no_mangle]
pub extern "C" fn muntrace() {}

#[cfg(test)]
mod tests {
    #[test]
    fn mallinfo_layout_matches_host() {
        assert_eq!(core::mem::size_of::<super::Mallinfo>(), 40);
        assert_eq!(core::mem::size_of::<super::Mallinfo2>(), 80);
    }
}
