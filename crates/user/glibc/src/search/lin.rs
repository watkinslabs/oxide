// lsearch(3)/lfind(3) (docs/59§6 G8): linear search over a flat array of
// `*nmemb` elements each `size` bytes. lfind is lookup-only; lsearch appends
// the key (and bumps *nmemb) when absent. C ABI only.
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

type Cmp = extern "C" fn(*const c_void, *const c_void) -> i32;

// # C: void *lfind(const void *key, const void *base, size_t *nmemb, size_t size, cmp)
#[no_mangle]
pub unsafe extern "C" fn lfind(key: *const c_void, base: *const c_void, nmemb: *const usize, size: usize, cmp: Cmp) -> *mut c_void {
    // SAFETY: base holds *nmemb elements of `size` bytes; key/cmp are valid.
    // Returns the first matching element or null without modifying the array.
    unsafe {
        let n = *nmemb;
        let mut i = 0;
        while i < n {
            let e = (base as *const u8).add(i * size) as *const c_void;
            if cmp(key, e) == 0 { return e as *mut c_void; }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

// # C: void *lsearch(const void *key, void *base, size_t *nmemb, size_t size, cmp)
#[no_mangle]
pub unsafe extern "C" fn lsearch(key: *const c_void, base: *mut c_void, nmemb: *mut usize, size: usize, cmp: Cmp) -> *mut c_void {
    // SAFETY: base has room for at least (*nmemb)+1 elements of `size` bytes
    // (lsearch contract); key/cmp valid. On a miss, append key by value and
    // bump *nmemb, returning the new element; on a hit, return the match.
    unsafe {
        let found = lfind(key, base, nmemb, size, cmp);
        if !found.is_null() { return found; }
        let n = *nmemb;
        let slot = (base as *mut u8).add(n * size);
        core::ptr::copy_nonoverlapping(key as *const u8, slot, size);
        *nmemb = n + 1;
        slot as *mut c_void
    }
}
