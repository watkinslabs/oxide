// Freestanding mem primitives for the rtld (docs/59§5). The compiler lowers
// slice copies/compares to memcpy/memset/memmove/memcmp/bcmp/strlen; the
// dynamic linker is self-contained (runs before libc) so it provides its own,
// like glibc's ld.so. Simple byte loops — correctness over speed (the rtld
// moves little data). Defined #[no_mangle] so the compiler's calls resolve.
#![cfg(feature = "freestanding")]

/// # C: void *memcpy(void *d, const void *s, size_t n)
#[no_mangle]
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller guarantees d/s are valid for n bytes and non-overlapping.
    unsafe {
        let mut i = 0;
        while i < n { *d.add(i) = *s.add(i); i += 1; }
        d
    }
}

/// # C: void *memmove(void *d, const void *s, size_t n)
#[no_mangle]
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller guarantees d/s valid for n bytes; copies in the safe
    // direction for overlap.
    unsafe {
        if (d as usize) < (s as usize) {
            let mut i = 0;
            while i < n { *d.add(i) = *s.add(i); i += 1; }
        } else {
            let mut i = n;
            while i > 0 { i -= 1; *d.add(i) = *s.add(i); }
        }
        d
    }
}

/// # C: void *memset(void *d, int c, size_t n)
#[no_mangle]
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: caller guarantees d is valid for n bytes.
    unsafe {
        let b = c as u8;
        let mut i = 0;
        while i < n { *d.add(i) = b; i += 1; }
        d
    }
}

/// # C: int memcmp(const void *a, const void *b, size_t n)
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: caller guarantees a/b valid for n bytes.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return x as i32 - y as i32; }
            i += 1;
        }
        0
    }
}

/// # C: int bcmp(const void *a, const void *b, size_t n)
#[no_mangle]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: caller guarantees a/b valid for n bytes.
    unsafe { memcmp(a, b, n) }
}

/// getauxval stub for the rtld. compiler-builtins' aarch64 CPU-feature /
/// FMV code references it; returning 0 (no HWCAP) selects the safe
/// non-LSE atomic fallbacks. The rtld doesn't need real auxv here.
/// # C: unsigned long getauxval(unsigned long type)
#[no_mangle]
pub extern "C" fn getauxval(_typ: usize) -> usize { 0 }

/// # C: size_t strlen(const char *s)
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    // SAFETY: s is a NUL-terminated C string.
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 { n += 1; }
        n
    }
}
