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

// # C: int ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
//                         u_char *dst, size_t dstsiz)
// Expand the (possibly compressed) wire name at src into UNCOMPRESSED wire form
// in dst, following pointers. Returns the bytes consumed at src, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn ns_name_unpack(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut u8, dstsiz: usize) -> i32 {
    // SAFETY: msg/eom bound the message; src points within it; dst is dstsiz
    // bytes. Pointers are followed with a checked-byte budget to bar loops.
    unsafe {
        let dstlim = dst as usize + dstsiz;
        let mut dstp = dst;
        let mut srcp = src;
        let mut len: isize = -1;
        let mut checked: isize = 0;
        if (srcp as usize) < msg as usize || srcp >= eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        loop {
            let n = *srcp; srcp = srcp.add(1);
            if n == 0 { break; }
            match n & NS_CMPRSFLGS {
                0 => {
                    if dstp as usize + n as usize + 1 >= dstlim || srcp.add(n as usize) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
                    checked += n as isize + 1;
                    *dstp = n; dstp = dstp.add(1);
                    core::ptr::copy_nonoverlapping(srcp, dstp, n as usize);
                    dstp = dstp.add(n as usize); srcp = srcp.add(n as usize);
                }
                NS_CMPRSFLGS => {
                    if srcp >= eom { crate::internal::errno::set(EMSGSIZE); return -1; }
                    if len < 0 { len = srcp as isize - src as isize + 1; }
                    let off = (((n & 0x3f) as usize) << 8) | *srcp as usize;
                    srcp = msg.add(off);
                    if (srcp as usize) < msg as usize || srcp >= eom { crate::internal::errno::set(EMSGSIZE); return -1; }
                    checked += 2;
                    if checked >= eom as isize - msg as isize { crate::internal::errno::set(EMSGSIZE); return -1; }
                }
                _ => { crate::internal::errno::set(EMSGSIZE); return -1; }
            }
        }
        if dstp as usize >= dstlim { crate::internal::errno::set(EMSGSIZE); return -1; }
        *dstp = 0;
        if len < 0 { len = srcp as isize - src as isize; }
        len as i32
    }
}

// # C: int ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src,
//                             char *dst, size_t dstsiz)
// ns_name_unpack then ns_name_ntop: compressed wire → presentation text.
#[no_mangle]
pub unsafe extern "C" fn ns_name_uncompress(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut c_char, dstsiz: usize) -> i32 {
    // SAFETY: forwards to unpack (into a 255-byte wire scratch) then ntop.
    unsafe {
        let mut tmp = [0u8; 255];
        let n = ns_name_unpack(msg, eom, src, tmp.as_mut_ptr(), tmp.len());
        if n < 0 { return -1; }
        if ns_name_ntop(tmp.as_ptr(), dst, dstsiz) < 0 { return -1; }
        n
    }
}

unsafe fn nlen(s: *const u8) -> usize { let mut n = 0; unsafe { while *s.add(n) != 0 { n += 1; } } n }
fn lc(c: u8) -> u8 { if c.is_ascii_uppercase() { c + 32 } else { c } }

// # C: int ns_makecanon(const char *src, char *dst, size_t dstsize)
// Strip trailing unescaped dots, then append exactly one canonical trailing dot.
#[no_mangle]
pub unsafe extern "C" fn ns_makecanon(src: *const c_char, dst: *mut c_char, dstsize: usize) -> i32 {
    // SAFETY: src is NUL-terminated; dst is dstsize bytes (need strlen+2).
    unsafe {
        let s = src as *const u8; let d = dst as *mut u8;
        let mut n = nlen(s);
        if n + 2 > dstsize { crate::internal::errno::set(EMSGSIZE); return -1; }
        core::ptr::copy_nonoverlapping(s, d, n); *d.add(n) = 0;
        while n >= 1 && *d.add(n - 1) == b'.' {
            if n >= 2 && *d.add(n - 2) == b'\\' && (n < 3 || *d.add(n - 3) != b'\\') { break; }
            n -= 1; *d.add(n) = 0;
        }
        *d.add(n) = b'.'; n += 1; *d.add(n) = 0;
        0
    }
}

// # C: int ns_samename(const char *a, const char *b) — caseless equality of the
// canonical forms. 1 equal, 0 not, -1 on a name too long to canonicalize.
#[no_mangle]
pub unsafe extern "C" fn ns_samename(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: a/b NUL-terminated; canonicalize each into a 1025-byte scratch.
    unsafe {
        let mut ta = [0u8; 1025]; let mut tb = [0u8; 1025];
        if ns_makecanon(a, ta.as_mut_ptr() as *mut c_char, ta.len()) < 0 { return -1; }
        if ns_makecanon(b, tb.as_mut_ptr() as *mut c_char, tb.len()) < 0 { return -1; }
        let mut i = 0;
        loop {
            let (x, y) = (lc(ta[i]), lc(tb[i]));
            if x != y { return 0; }
            if x == 0 { return 1; }
            i += 1;
        }
    }
}

// # C: int ns_samedomain(const char *a, const char *b) — is name `a` within
// domain `b` (equal counts)? Trailing unescaped dots are ignored on both.
#[no_mangle]
pub unsafe extern "C" fn ns_samedomain(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: a/b NUL-terminated; only indexed reads within their lengths.
    unsafe {
        let pa = a as *const u8; let pb = b as *const u8;
        let mut la = nlen(pa); let mut lb = nlen(pb);
        // strip an unescaped trailing dot from a
        if la != 0 && *pa.add(la - 1) == b'.' {
            let mut esc = false; let mut j = la as isize - 2;
            while j >= 0 && *pa.add(j as usize) == b'\\' { esc = !esc; j -= 1; }
            if !esc { la -= 1; }
        }
        if lb != 0 && *pb.add(lb - 1) == b'.' {
            let mut esc = false; let mut j = lb as isize - 2;
            while j >= 0 && *pb.add(j as usize) == b'\\' { esc = !esc; j -= 1; }
            if !esc { lb -= 1; }
        }
        if lb == 0 { return 1; }                 // b is the root
        if lb > la { return 0; }
        let caseless_eq = |off: usize, len: usize| -> bool {
            for k in 0..len { if lc(*pa.add(off + k)) != lc(*pb.add(k)) { return false; } }
            true
        };
        if lb == la { return caseless_eq(0, lb) as i32; }
        // lb < la: a must end with b, preceded by an unescaped dot
        if *pa.add(la - lb - 1) != b'.' { return 0; }
        let mut esc = false; let mut j = la as isize - lb as isize - 2;
        while j >= 0 && *pa.add(j as usize) == b'\\' { esc = !esc; j -= 1; }
        if esc { return 0; }
        caseless_eq(la - lb, lb) as i32
    }
}

// # C: int ns_subdomain(const char *a, const char *b) — `a` is a PROPER
// subdomain of `b` (within b but not equal).
#[no_mangle]
pub unsafe extern "C" fn ns_subdomain(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: forwards to ns_samedomain + ns_samename on NUL-terminated names.
    unsafe { (ns_samedomain(a, b) != 0 && ns_samename(a, b) == 0) as i32 }
}

const EINVAL: i32 = 22;

// # C: int ns_format_ttl(unsigned long src, char *dst, size_t dstsiz)
// Render a TTL as W/D/H/M/S units (e.g. "1d1h1m1s"); a single unit stays
// uppercase. Returns the string length, -1 (EMSGSIZE) on overflow.
#[no_mangle]
pub unsafe extern "C" fn ns_format_ttl(mut src: u64, dst: *mut c_char, dstsiz: usize) -> i32 {
    // SAFETY: dst is dstsiz bytes; fmt1 bounds every append before writing.
    unsafe {
        let d0 = dst as *mut u8;
        let mut pos = 0usize;
        let mut x = 0;
        let secs = (src % 60) as u32; src /= 60;
        let mins = (src % 60) as u32; src /= 60;
        let hours = (src % 24) as u32; src /= 24;
        let days = (src % 7) as u32; src /= 7;
        let weeks = src as u32;
        // append "<n><letter>"; bound check incl room for the NUL.
        let mut fmt1 = |n: u32, letter: u8| -> bool {
            let mut tmp = [0u8; 12]; let mut tl = 0usize; let mut v = n;
            if v == 0 { tmp[tl] = b'0'; tl += 1; }
            else { let mut digs = [0u8; 10]; let mut dn = 0; while v > 0 { digs[dn] = b'0' + (v % 10) as u8; v /= 10; dn += 1; } while dn > 0 { dn -= 1; tmp[tl] = digs[dn]; tl += 1; } }
            tmp[tl] = letter; tl += 1;
            if pos + tl + 1 > dstsiz { return false; }
            for k in 0..tl { *d0.add(pos) = tmp[k]; pos += 1; }
            true
        };
        if weeks != 0 { if !fmt1(weeks, b'W') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if days != 0  { if !fmt1(days,  b'D') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if hours != 0 { if !fmt1(hours, b'H') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if mins != 0  { if !fmt1(mins,  b'M') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if secs != 0 || (weeks == 0 && days == 0 && hours == 0 && mins == 0) {
            if !fmt1(secs, b'S') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1;
        }
        if x > 1 { for k in 0..pos { let c = *d0.add(k); if c.is_ascii_uppercase() { *d0.add(k) = c + 32; } } }
        *d0.add(pos) = 0;
        pos as i32
    }
}

// # C: int ns_parse_ttl(const char *src, unsigned long *dst)
// Parse a TTL string ("1D1H1M1S", case-insensitive) or a bare seconds count.
#[no_mangle]
pub unsafe extern "C" fn ns_parse_ttl(src: *const c_char, dst: *mut u64) -> i32 {
    // SAFETY: src NUL-terminated; dst is a writable u64. Mirrors glibc's units.
    unsafe {
        let s = src as *const u8;
        let mut ttl = 0u64; let mut tmp = 0u64; let mut digits = 0; let mut dirty = false;
        let mut i = 0;
        loop {
            let ch = *s.add(i); i += 1;
            if ch == 0 { break; }
            if !(0x20..0x7f).contains(&ch) { crate::internal::errno::set(EINVAL); return -1; }
            if ch.is_ascii_digit() { tmp = tmp * 10 + (ch - b'0') as u64; digits += 1; continue; }
            if digits == 0 { crate::internal::errno::set(EINVAL); return -1; }
            let up = if ch.is_ascii_lowercase() { ch - 32 } else { ch };
            match up {
                b'W' => tmp *= 7 * 24 * 60 * 60,
                b'D' => tmp *= 24 * 60 * 60,
                b'H' => tmp *= 60 * 60,
                b'M' => tmp *= 60,
                b'S' => {}
                _ => { crate::internal::errno::set(EINVAL); return -1; }
            }
            ttl += tmp; tmp = 0; digits = 0; dirty = true;
        }
        if digits > 0 { if dirty { crate::internal::errno::set(EINVAL); return -1; } ttl += tmp; }
        else if !dirty { crate::internal::errno::set(EINVAL); return -1; }
        *dst = ttl;
        0
    }
}
// ns_datetosecs deferred: host glibc's range validation rejects dates beyond a
// (time/version-dependent) recent-past cutoff, so it is not safely diffable yet.
