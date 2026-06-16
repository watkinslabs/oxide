// libresolv ns_* wire helpers (docs/59§6 §9.1, <arpa/nameser.h>): RFC1035 name
// codec primitives. Pure — no network. ns_name_ntop/pton convert between the
// label wire format and presentation text (with glibc's escaping); ns_name_skip
// walks a wire name (following a compression pointer's first byte). The big-
// endian ns_get*/ns_put* accessors round out the RR-field codec.
#![cfg(feature = "freestanding")]
use core::ffi::c_char;

const NS_CMPRSFLGS: u8 = 0xc0; // top 2 bits set ⇒ compression pointer
const EMSGSIZE: i32 = 90;

// glibc ns_name.c special(): chars that get a backslash escape in presentation.
fn special(c: u8) -> bool { matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') }
// printable per glibc: strictly between SP and DEL.
fn printable(c: u8) -> bool { c > 0x20 && c < 0x7f }

// # C: unsigned ns_get16(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get16(src: *const u8) -> u32 {
    // SAFETY: src points at ≥2 readable bytes of an RR field.
    unsafe { ((*src as u32) << 8) | *src.add(1) as u32 }
}
// # C: unsigned long ns_get32(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get32(src: *const u8) -> u64 {
    // SAFETY: src points at ≥4 readable bytes of an RR field.
    unsafe { ((*src as u64) << 24) | ((*src.add(1) as u64) << 16) | ((*src.add(2) as u64) << 8) | *src.add(3) as u64 }
}
// # C: void ns_put16(unsigned src, unsigned char *dst)
#[no_mangle]
pub unsafe extern "C" fn ns_put16(src: u32, dst: *mut u8) {
    // SAFETY: dst points at ≥2 writable bytes.
    unsafe { *dst = (src >> 8) as u8; *dst.add(1) = src as u8; }
}
// # C: void ns_put32(unsigned long src, unsigned char *dst)
#[no_mangle]
pub unsafe extern "C" fn ns_put32(src: u64, dst: *mut u8) {
    // SAFETY: dst points at ≥4 writable bytes.
    unsafe { *dst = (src >> 24) as u8; *dst.add(1) = (src >> 16) as u8; *dst.add(2) = (src >> 8) as u8; *dst.add(3) = src as u8; }
}

// # C: int ns_name_ntop(const unsigned char *src, char *dst, size_t dstsiz)
// Wire name → presentation text. Returns the bytes written incl the NUL, or -1
// (EMSGSIZE) if a compression pointer appears in the name or dst overflows.
#[no_mangle]
pub unsafe extern "C" fn ns_name_ntop(src: *const u8, dst: *mut c_char, dstsiz: usize) -> i32 {
    // SAFETY: src is a NUL-terminated wire name (no pointers); dst is dstsiz bytes.
    unsafe {
        let d0 = dst as *mut u8;
        let mut cp = src;
        let mut dn = 0usize; // bytes written to dst
        loop {
            let n = *cp; cp = cp.add(1);
            if n == 0 { break; }
            if n & NS_CMPRSFLGS != 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
            if dn != 0 { if dn + 1 >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; } *d0.add(dn) = b'.'; dn += 1; }
            for _ in 0..n {
                let c = *cp; cp = cp.add(1);
                if special(c) {
                    if dn + 2 >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
                    *d0.add(dn) = b'\\'; dn += 1; *d0.add(dn) = c; dn += 1;
                } else if !printable(c) {
                    if dn + 4 >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
                    *d0.add(dn) = b'\\'; dn += 1;
                    *d0.add(dn) = b'0' + c / 100; dn += 1;
                    *d0.add(dn) = b'0' + (c / 10) % 10; dn += 1;
                    *d0.add(dn) = b'0' + c % 10; dn += 1;
                } else {
                    if dn + 1 >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
                    *d0.add(dn) = c; dn += 1;
                }
            }
        }
        if dn == 0 { if dn + 1 >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; } *d0.add(dn) = b'.'; dn += 1; }
        if dn >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
        *d0.add(dn) = 0; dn += 1;
        dn as i32
    }
}

// # C: int ns_name_pton(const char *src, unsigned char *dst, size_t dstsiz)
// Presentation text → wire name. Returns 1 if fully qualified (trailing dot /
// root), 0 if not, -1 (EMSGSIZE) on overflow or a malformed escape / "..".
#[no_mangle]
pub unsafe extern "C" fn ns_name_pton(src: *const c_char, dst: *mut u8, dstsiz: usize) -> i32 {
    // SAFETY: src is a NUL-terminated presentation name; dst is dstsiz bytes. bp
    // is the write cursor, `label` the index of the pending length byte.
    unsafe {
        let s = src as *const u8;
        let mut i = 0usize;
        let mut bp = 1usize;            // dst[0] reserved for the first length byte
        let mut label = 0usize;        // index of the current label's length byte
        if dstsiz == 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
        loop {
            let mut c = *s.add(i); i += 1;
            if c == 0 { break; }
            if c == b'\\' {
                c = *s.add(i); i += 1;
                if c == 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
                if c.is_ascii_digit() {
                    let mut n = (c - b'0') as u32 * 100;
                    let c2 = *s.add(i); i += 1;
                    if !c2.is_ascii_digit() { crate::internal::errno::set(EMSGSIZE); return -1; }
                    n += (c2 - b'0') as u32 * 10;
                    let c3 = *s.add(i); i += 1;
                    if !c3.is_ascii_digit() { crate::internal::errno::set(EMSGSIZE); return -1; }
                    n += (c3 - b'0') as u32;
                    if n > 255 { crate::internal::errno::set(EMSGSIZE); return -1; }
                    c = n as u8;
                }
            } else if c == b'.' {
                let llen = bp - label - 1;
                if llen as u8 & NS_CMPRSFLGS != 0 || label >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
                *dst.add(label) = llen as u8;
                if *s.add(i) == 0 {           // trailing dot ⇒ fully qualified
                    if llen != 0 {
                        if bp >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
                        *dst.add(bp) = 0; bp += 1;
                    }
                    return 1;
                }
                if llen == 0 { crate::internal::errno::set(EMSGSIZE); return -1; } // ".." illegal
                label = bp; bp += 1;
                continue;
            }
            if bp >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
            *dst.add(bp) = c; bp += 1;
        }
        let llen = bp - label - 1;
        if llen as u8 & NS_CMPRSFLGS != 0 || label >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
        *dst.add(label) = llen as u8;
        if llen != 0 {
            if bp >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
            *dst.add(bp) = 0; bp += 1;
        }
        let _ = bp;
        0
    }
}

// # C: int ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom)
// Advance *ptrptr past one wire name (a compression pointer ends it). 0 / -1.
#[no_mangle]
pub unsafe extern "C" fn ns_name_skip(ptrptr: *mut *const u8, eom: *const u8) -> i32 {
    // SAFETY: *ptrptr points within a message bounded by eom; walk labels until
    // root(0) or a 0xc0 pointer (consume its 2nd byte), never reading past eom.
    unsafe {
        let mut cp = *ptrptr;
        while cp < eom {
            let n = *cp; cp = cp.add(1);
            if n == 0 { break; }
            match n & NS_CMPRSFLGS {
                0 => cp = cp.add(n as usize),
                NS_CMPRSFLGS => { cp = cp.add(1); break; }
                _ => { crate::internal::errno::set(EMSGSIZE); return -1; }
            }
        }
        if cp > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        *ptrptr = cp;
        0
    }
}
