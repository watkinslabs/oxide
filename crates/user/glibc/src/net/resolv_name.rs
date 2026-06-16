// DNS domain-name codec (docs/59§6 §9.1, <resolv.h>): dn_comp/dn_expand/
// dn_skipname over the RFC 1035 label wire format. dn_comp does not emit
// compression pointers (always full labels — valid; glibc compresses only when
// dnptrs offers a match). dn_expand FOLLOWS pointers within the message.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};

// # C: int dn_skipname(const unsigned char *src, const unsigned char *eom)
// Bytes occupied by the encoded name at src (a pointer ends it). -1 if malformed.
#[no_mangle]
pub unsafe extern "C" fn dn_skipname(src: *const u8, eom: *const u8) -> i32 {
    // SAFETY: src/eom bound a region of a DNS message; we walk labels until the
    // root(0) or a compression pointer, never reading past eom.
    unsafe {
        let mut p = src;
        while p < eom {
            let b = *p;
            if b == 0 { return (p.offset(1) as usize - src as usize) as i32; }
            if b & 0xc0 == 0xc0 {
                if p.add(1) >= eom { return -1; }
                return (p.offset(2) as usize - src as usize) as i32;
            }
            if b & 0xc0 != 0 { return -1; }
            p = p.add(1 + b as usize);
        }
        -1
    }
}

// # C: int dn_expand(const unsigned char *msg, const unsigned char *eom,
//                    const unsigned char *src, char *dst, int dstsiz)
#[no_mangle]
pub unsafe extern "C" fn dn_expand(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut c_char, dstsiz: i32) -> i32 {
    // SAFETY: msg/eom bound the message; src points within it; dst is dstsiz
    // bytes. We accumulate labels into dst joined by '.', following compression
    // pointers (bounded hop count) and returning the bytes consumed at src.
    unsafe {
        let d = dst as *mut u8;
        let cap = if dstsiz > 0 { dstsiz as usize } else { return -1 };
        let mut p = src;
        let mut consumed: isize = -1; // length at `src` until the first jump
        let mut dpos = 0usize;
        let mut hops = 0;
        loop {
            if p < msg || p >= eom { return -1; }
            let b = *p;
            if b == 0 {
                if consumed < 0 { consumed = p.offset(1) as isize - src as isize; }
                break;
            }
            if b & 0xc0 == 0xc0 {
                if p.add(1) >= eom { return -1; }
                let off = (((b & 0x3f) as usize) << 8) | *p.add(1) as usize;
                if consumed < 0 { consumed = p.offset(2) as isize - src as isize; }
                hops += 1;
                if hops > 128 { return -1; } // pointer loop guard
                p = msg.add(off);
                continue;
            }
            if b & 0xc0 != 0 { return -1; }
            let n = b as usize;
            p = p.add(1);
            if p.add(n) > eom { return -1; }
            if dpos > 0 { if dpos + 1 > cap { return -1; } *d.add(dpos) = b'.'; dpos += 1; }
            if dpos + n + 1 > cap { return -1; }
            core::ptr::copy_nonoverlapping(p, d.add(dpos), n);
            dpos += n;
            p = p.add(n);
        }
        *d.add(dpos) = 0;
        consumed as i32
    }
}

// # C: int dn_comp(const char *src, unsigned char *dst, int dstsiz,
//                  unsigned char **dnptrs, unsigned char **lastdnptr)
#[no_mangle]
pub unsafe extern "C" fn dn_comp(src: *const c_char, dst: *mut u8, dstsiz: i32, _dnptrs: *mut *mut c_void, _lastdnptr: *mut *mut c_void) -> i32 {
    // SAFETY: src is a NUL-terminated dotted name; dst is dstsiz bytes. We emit
    // RFC1035 labels (len+bytes, root 0); no compression pointers. -1 on a
    // label >63, total >255, or insufficient dst.
    unsafe {
        let s = src as *const u8;
        let cap = if dstsiz > 0 { dstsiz as usize } else { return -1 };
        let mut out = 0usize;
        let mut i = 0usize;
        loop {
            // measure the next label up to '.' or NUL
            let mut n = 0usize;
            while *s.add(i + n) != 0 && *s.add(i + n) != b'.' { n += 1; }
            if n > 63 { return -1; }
            if n > 0 {
                if out + 1 + n > cap || out + 1 + n > 255 { return -1; }
                *dst.add(out) = n as u8; out += 1;
                core::ptr::copy_nonoverlapping(s.add(i), dst.add(out), n); out += n;
            }
            i += n;
            if *s.add(i) == 0 { break; }
            i += 1; // skip '.'
            if *s.add(i) == 0 { break; } // trailing dot
        }
        if out + 1 > cap { return -1; }
        *dst.add(out) = 0; out += 1; // root label
        out as i32
    }
}
