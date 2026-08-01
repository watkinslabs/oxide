use core::ptr::copy_nonoverlapping;
use crate::linux_errno;
use syscall::errno::Errno;

const CTYPE_UPPER: u8 = 0x01;
const CTYPE_LOWER: u8 = 0x02;
const CTYPE_DIGIT: u8 = 0x04;
const CTYPE_SPACE: u8 = 0x20;
const CTYPE_XDIGIT: u8 = 0x40;

#[repr(align(1))]
pub(crate) struct CtypeTable([u8; 256]);

pub(crate) static CTYPE: CtypeTable = CtypeTable(build_ctype());

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    export("_ctype", CTYPE.0.as_ptr() as usize, false);
    for (name, addr) in [
        ("strlen",       strlen       as *const () as usize),
        ("strnlen",      strnlen      as *const () as usize),
        ("strcmp",       strcmp       as *const () as usize),
        ("strncmp",      strncmp      as *const () as usize),
        ("strncasecmp",  strncasecmp  as *const () as usize),
        ("strcpy",       strcpy       as *const () as usize),
        ("strncpy",      strncpy      as *const () as usize),
        ("strchr",       strchr       as *const () as usize),
        ("strstr",       strstr       as *const () as usize),
        ("strsep",       strsep       as *const () as usize),
        ("strim",        strim        as *const () as usize),
        ("sized_strscpy", sized_strscpy as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) unsafe extern "C" fn strlen(s: *const u8) -> usize {
    // SAFETY: strlen's KPI contract gives s as a NUL-terminated C string, which is c_strlen's precondition.
    unsafe { c_strlen(s) }
}

pub(crate) unsafe extern "C" fn strnlen(s: *const u8, max: usize) -> usize {
    if s.is_null() { return 0; }
    let mut n = 0usize;
    // SAFETY: s was null-checked; the scan stops at n == max or at the NUL, so it never exceeds strnlen's promise of max readable bytes or an earlier terminator.
    unsafe { while n < max && *s.add(n) != 0 { n += 1; } }
    n
}

pub(crate) unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0usize;
    loop {
        // SAFETY: i only advances past a byte pair that compared equal and non-NUL, so a+i is at worst a's terminator.
        let av = unsafe { *a.add(i) };
        // SAFETY: same index as the a read above; b+i is at worst b's terminator because b[i-1] was equal to a[i-1] and non-NUL.
        let bv = unsafe { *b.add(i) };
        if av != bv || av == 0 { return av as i32 - bv as i32; }
        i += 1;
    }
}

pub(crate) unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: i < n and the loop returns at the first NUL, so the read stays inside strncmp's n-byte promise for a.
        let av = unsafe { *a.add(i) };
        // SAFETY: i < n and the loop returns at the first NUL, so the read stays inside strncmp's n-byte promise for b.
        let bv = unsafe { *b.add(i) };
        if av != bv || av == 0 { return av as i32 - bv as i32; }
    }
    0
}

pub(crate) unsafe extern "C" fn strncasecmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: i < n and the loop returns at the first NUL, so the read stays inside strncasecmp's n-byte promise for a.
        let av = to_lower(unsafe { *a.add(i) });
        // SAFETY: i < n and the loop returns at the first NUL, so the read stays inside strncasecmp's n-byte promise for b.
        let bv = to_lower(unsafe { *b.add(i) });
        if av != bv || av == 0 { return av as i32 - bv as i32; }
    }
    0
}

pub(crate) unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: strcpy's contract gives src as a NUL-terminated C string, which is c_strlen's precondition.
    let len = unsafe { c_strlen(src) } + 1;
    // SAFETY: len is strlen(src)+1 and strcpy's contract obliges the caller to size dst for src including its terminator.
    unsafe { copy_nonoverlapping(src, dst, len); }
    dst
}

pub(crate) unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0usize;
    while i < n {
        // SAFETY: i < n and the loop breaks once the NUL is copied, so the read stays inside src's string.
        let b = unsafe { *src.add(i) };
        // SAFETY: i < n, so the write stays inside the n writable bytes strncpy's contract gives dst.
        unsafe { *dst.add(i) = b; }
        i += 1;
        if b == 0 { break; }
    }
    while i < n {
        // SAFETY: i < n in the pad loop too, so the zero fill stays inside dst's n writable bytes.
        unsafe { *dst.add(i) = 0; }
        i += 1;
    }
    dst
}

pub(crate) unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
    let needle = c as u8;
    let mut i = 0usize;
    loop {
        // SAFETY: i only advances past bytes proven non-NUL, so s+i is at worst the terminator of strchr's C string.
        let b = unsafe { *s.add(i) };
        // SAFETY: index i was just read as part of the same string, so s+i is a pointer into it (possibly at its terminator, which strchr is defined to find).
        if b == needle { return unsafe { s.add(i) as *mut u8 }; }
        if b == 0 { return core::ptr::null_mut(); }
        i += 1;
    }
}

pub(crate) unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    // SAFETY: strstr's contract gives needle as a NUL-terminated C string, which is c_strlen's precondition.
    let nlen = unsafe { c_strlen(needle) };
    if nlen == 0 { return haystack as *mut u8; }
    // SAFETY: strstr's contract gives haystack as a NUL-terminated C string, which is c_strlen's precondition.
    let hlen = unsafe { c_strlen(haystack) };
    if nlen > hlen { return core::ptr::null_mut(); }
    for i in 0..=hlen - nlen {
        // SAFETY: nlen <= hlen and i <= hlen-nlen, so haystack+i has at least nlen bytes before its terminator, satisfying strncmp's n-byte requirement for both operands.
        if unsafe { strncmp(haystack.add(i), needle, nlen) } == 0 { return unsafe { haystack.add(i) as *mut u8 }; }
    }
    core::ptr::null_mut()
}

pub(crate) unsafe extern "C" fn strsep(sp: *mut *mut u8, delim: *const u8) -> *mut u8 {
    if sp.is_null() { return core::ptr::null_mut(); }
    // SAFETY: sp was null-checked and strsep's contract makes it caller-owned storage holding the string cursor.
    let s = unsafe { *sp };
    if s.is_null() { return core::ptr::null_mut(); }
    let mut i = 0usize;
    loop {
        // SAFETY: s was null-checked and i only advances past bytes proven neither NUL nor a delimiter, so s+i is at worst the terminator.
        let b = unsafe { *s.add(i) };
        if b == 0 {
            // SAFETY: sp was null-checked above and is the caller's own cursor slot, cleared here to report the final token.
            unsafe { *sp = core::ptr::null_mut(); }
            return s;
        }
        // SAFETY: strsep's contract gives delim as a NUL-terminated C string, which is strchr's requirement.
        if unsafe { strchr(delim, b as i32) }.is_null() {
            i += 1;
        } else {
            // SAFETY: b is non-NUL (the b == 0 arm returned), so index i is a real byte of the caller's mutable string and i+1 is at worst its terminator.
            unsafe { *s.add(i) = 0; *sp = s.add(i + 1); }
            return s;
        }
    }
}

pub(crate) unsafe extern "C" fn strim(s: *mut u8) -> *mut u8 {
    if s.is_null() { return s; }
    // SAFETY: s was null-checked and strim's contract makes it a NUL-terminated mutable C string, which is c_strlen's precondition.
    let len = unsafe { c_strlen(s) };
    let mut start = 0usize;
    // SAFETY: the start < len guard short-circuits first, so every byte read precedes the terminator at index len.
    while start < len && is_space(unsafe { *s.add(start) }) { start += 1; }
    let mut end = len;
    // SAFETY: the end > start guard short-circuits first and end <= len, so index end-1 is a real byte of the string.
    while end > start && is_space(unsafe { *s.add(end - 1) }) { end -= 1; }
    // SAFETY: end <= len == strlen(s), so index end is at worst the terminator slot of the caller's mutable buffer.
    unsafe { *s.add(end) = 0; }
    // SAFETY: start <= len == strlen(s), so s+start is at worst the terminator — a pointer inside the same buffer.
    unsafe { s.add(start) }
}

pub(crate) unsafe extern "C" fn sized_strscpy(dst: *mut u8, src: *const u8, count: usize) -> isize {
    if dst.is_null() || src.is_null() || count == 0 { return linux_errno(Errno::E2big) as isize; }
    let mut i = 0usize;
    while i + 1 < count {
        // SAFETY: src was null-checked and the loop returns once the NUL is copied, so the read stays inside src's string.
        let b = unsafe { *src.add(i) };
        // SAFETY: i+1 < count so index i is inside the count writable bytes strscpy's contract gives dst.
        unsafe { *dst.add(i) = b; }
        if b == 0 { return i as isize; }
        i += 1;
    }
    // SAFETY: count != 0 was checked on entry, so index count-1 is the last of dst's count writable bytes.
    unsafe { *dst.add(count - 1) = 0; }
    linux_errno(Errno::E2big) as isize
}

// Precondition: `s` is null or a NUL-terminated C string.
pub(crate) unsafe fn c_strlen(s: *const u8) -> usize {
    if s.is_null() { return 0; }
    let mut n = 0usize;
    // SAFETY: s was null-checked and the caller's precondition puts a NUL in the buffer, so n only advances past bytes proven non-NUL.
    unsafe { while *s.add(n) != 0 { n += 1; } }
    n
}

pub(crate) fn to_lower(b: u8) -> u8 {
    if b'A' <= b && b <= b'Z' { b + 32 } else { b }
}

pub(crate) fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

const fn build_ctype() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut c = 0usize;
    while c < 256 {
        let b = c as u8;
        if b'A' <= b && b <= b'Z' { t[c] |= CTYPE_UPPER; }
        if b'a' <= b && b <= b'z' { t[c] |= CTYPE_LOWER; }
        if b'0' <= b && b <= b'9' { t[c] |= CTYPE_DIGIT | CTYPE_XDIGIT; }
        if (b'A' <= b && b <= b'F') || (b'a' <= b && b <= b'f') { t[c] |= CTYPE_XDIGIT; }
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0x0b || b == 0x0c { t[c] |= CTYPE_SPACE; }
        c += 1;
    }
    t
}
