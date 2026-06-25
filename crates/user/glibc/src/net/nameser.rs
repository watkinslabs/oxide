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

// SAFETY: generated aliases preserve each target's caller contract unchanged.
macro_rules! alias_unsafe {
    ($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $target:ident;) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
            // SAFETY: generated alias forwards the same C ABI contract unchanged.
            unsafe { $target($($arg),*) }
        }
    };
}

// # C: unsigned ns_get16(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get16(src: *const u8) -> u32 {
    // SAFETY: src points at ≥2 readable bytes of an RR field.
    unsafe { ((*src as u32) << 8) | *src.add(1) as u32 }
}
alias_unsafe!(__ns_get16(src: *const u8) -> u32 = ns_get16;);
// # C: unsigned long ns_get32(const unsigned char *src)
#[no_mangle]
pub unsafe extern "C" fn ns_get32(src: *const u8) -> u64 {
    // SAFETY: src points at ≥4 readable bytes of an RR field.
    unsafe { ((*src as u64) << 24) | ((*src.add(1) as u64) << 16) | ((*src.add(2) as u64) << 8) | *src.add(3) as u64 }
}
alias_unsafe!(__ns_get32(src: *const u8) -> u64 = ns_get32;);
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
alias_unsafe!(__ns_name_ntop(src: *const u8, dst: *mut c_char, dstsiz: usize) -> i32 = ns_name_ntop;);
// # C: int ns_name_ntol(const unsigned char *src, unsigned char *dst, size_t dstsiz)
// Wire name → wire name, lowercasing label bytes. Compression is rejected.
#[no_mangle]
pub unsafe extern "C" fn ns_name_ntol(src: *const u8, dst: *mut u8, dstsiz: usize) -> i32 {
    // SAFETY: src is a NUL-terminated uncompressed wire name; dst is dstsiz
    // bytes. The loop validates each label length before copying bytes.
    unsafe {
        if dstsiz == 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
        let mut cp = src;
        let mut dn = 0usize;
        loop {
            let n = *cp;
            cp = cp.add(1);
            if n & NS_CMPRSFLGS != 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
            if dn >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
            *dst.add(dn) = n;
            dn += 1;
            if n == 0 { return dn as i32; }
            if dn + n as usize >= dstsiz { crate::internal::errno::set(EMSGSIZE); return -1; }
            for _ in 0..n {
                let c = *cp;
                cp = cp.add(1);
                *dst.add(dn) = lc(c);
                dn += 1;
            }
        }
    }
}
alias_unsafe!(__ns_name_ntol(src: *const u8, dst: *mut u8, dstsiz: usize) -> i32 = ns_name_ntol;);
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
alias_unsafe!(__ns_name_pton(src: *const c_char, dst: *mut u8, dstsiz: usize) -> i32 = ns_name_pton;);
// # C: int ns_name_pack(const u_char *src, u_char *dst, int dstsiz,
//                       const u_char **dnptrs, const u_char **lastdnptr)
// Pack an uncompressed wire name into dst. Like dn_comp, no compression pointers
// are emitted (always full labels — wire-legal; matches glibc when dnptrs==NULL),
// so the dnptr args are accepted and unused. -1 (EMSGSIZE) on a compressed src,
// an over-long name (>255), or insufficient dst.
#[no_mangle]
pub unsafe extern "C" fn ns_name_pack(src: *const u8, dst: *mut u8, dstsiz: i32, _dnptrs: *mut *const u8, _lastdnptr: *mut *const u8) -> i32 {
    // SAFETY: src is a NUL-terminated uncompressed wire name; dst is dstsiz bytes.
    unsafe {
        let cap = if dstsiz > 0 { dstsiz as usize } else { crate::internal::errno::set(EMSGSIZE); return -1; };
        // validate: total length ≤ 255, no compression flag in any label length.
        let mut l = 0usize; let mut p = src;
        loop {
            let n = *p;
            if n & NS_CMPRSFLGS != 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
            l += n as usize + 1;
            if l > 255 { crate::internal::errno::set(EMSGSIZE); return -1; }
            p = p.add(n as usize + 1);
            if n == 0 { break; }
        }
        if l > cap { crate::internal::errno::set(EMSGSIZE); return -1; }
        core::ptr::copy_nonoverlapping(src, dst, l);
        l as i32
    }
}
alias_unsafe!(__ns_name_pack(src: *const u8, dst: *mut u8, dstsiz: i32, dnptrs: *mut *const u8, lastdnptr: *mut *const u8) -> i32 = ns_name_pack;);
// # C: int ns_name_compress(const char *src, u_char *dst, size_t dstsiz,
//                           const u_char **dnptrs, const u_char **lastdnptr)
// ns_name_pton then ns_name_pack: presentation → wire (uncompressed).
#[no_mangle]
pub unsafe extern "C" fn ns_name_compress(src: *const c_char, dst: *mut u8, dstsiz: usize, dnptrs: *mut *const u8, lastdnptr: *mut *const u8) -> i32 {
    // SAFETY: src presentation name → 255-byte wire scratch → pack into dst.
    unsafe {
        let mut tmp = [0u8; 255];
        if ns_name_pton(src, tmp.as_mut_ptr(), tmp.len()) < 0 { return -1; }
        ns_name_pack(tmp.as_ptr(), dst, dstsiz as i32, dnptrs, lastdnptr)
    }
}
alias_unsafe!(__ns_name_compress(src: *const c_char, dst: *mut u8, dstsiz: usize, dnptrs: *mut *const u8, lastdnptr: *mut *const u8) -> i32 = ns_name_compress;);
// # C: void ns_name_rollback(const unsigned char *src,
//                            const unsigned char **dnptrs,
//                            const unsigned char **lastdnptr)
#[no_mangle]
pub unsafe extern "C" fn ns_name_rollback(src: *const u8, mut dnptrs: *mut *const u8, lastdnptr: *mut *const u8) {
    // SAFETY: dnptrs..lastdnptr is a caller-owned pointer table; stop at the
    // first null entry or at lastdnptr, matching glibc's compression rollback.
    unsafe {
        while dnptrs < lastdnptr && !(*dnptrs).is_null() {
            if *dnptrs >= src {
                *dnptrs = core::ptr::null();
                break;
            }
            dnptrs = dnptrs.add(1);
        }
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
alias_unsafe!(__ns_name_skip(ptrptr: *mut *const u8, eom: *const u8) -> i32 = ns_name_skip;);
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
alias_unsafe!(__ns_name_unpack(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut u8, dstsiz: usize) -> i32 = ns_name_unpack;);
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
alias_unsafe!(__ns_name_uncompress(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut c_char, dstsiz: usize) -> i32 = ns_name_uncompress;);
unsafe fn nlen(s: *const u8) -> usize { let mut n = 0; unsafe { while *s.add(n) != 0 { n += 1; } } n }
fn lc(c: u8) -> u8 { if c.is_ascii_uppercase() { c + 32 } else { c } }

fn res_printable(c: u8) -> bool { (0x21..0x7f).contains(&c) }
fn host_char(c: u8) -> bool { c.is_ascii_alphanumeric() || c == b'-' || c == b'_' }

unsafe fn label_ok<F>(s: *const u8, start: usize, end: usize, pred: F) -> bool
where
    F: Fn(u8, bool) -> bool,
{
    let mut i = start;
    let mut len = 0usize;
    // SAFETY: caller supplies label byte offsets within the same NUL-terminated
    // domain string; this loop reads only bytes before `end`.
    unsafe {
        while i < end {
            let mut escaped = false;
            let mut c = *s.add(i);
            i += 1;
            if c == b'\\' {
                if i >= end { return false; }
                escaped = true;
                c = *s.add(i);
                i += 1;
            }
            if !pred(c, escaped) { return false; }
            len += 1;
            if len > 63 { return false; }
        }
    }
    true
}

unsafe fn domain_ok<F>(name: *const c_char, pred: F) -> bool
where
    F: Copy + Fn(u8, bool) -> bool,
{
    // SAFETY: `name` is a caller NUL-terminated domain string; all helper
    // calls and indexed reads stay within the measured string length.
    unsafe {
        if name.is_null() { return false; }
        let s = name as *const u8;
        let n = nlen(s);
        if n == 0 { return true; }
        let mut total = 1usize; // final root label.
        let mut start = 0usize;
        let mut i = 0usize;
        while i <= n {
            let at_end = i == n;
            let c = if at_end { 0 } else { *s.add(i) };
            if at_end || c == b'.' {
                if i == start {
                    return n == 1 && start == 0 || at_end && start == n;
                }
                if !label_ok(s, start, i, pred) { return false; }
                total += i - start + 1;
                if total > 255 { return false; }
                start = i + 1;
            } else if c == b'\\' {
                i += 1;
                if i >= n { return false; }
            }
            i += 1;
        }
        true
    }
}

unsafe fn first_unescaped_dot(name: *const u8, n: usize) -> Option<usize> {
    let mut i = 0usize;
    // SAFETY: caller passes the measured byte length of `name`; this scan reads
    // only indexes below that length while handling escaped bytes.
    unsafe {
        while i < n {
            let c = *name.add(i);
            if c == b'.' { return Some(i); }
            if c == b'\\' {
                i += 1;
                if i >= n { return None; }
            }
            i += 1;
        }
    }
    None
}

// # C: int res_dnok(const char *dn)
#[no_mangle]
pub unsafe extern "C" fn res_dnok(dn: *const c_char) -> i32 {
    // SAFETY: dn is a caller NUL-terminated name; validation performs bounded
    // byte walks and rejects whitespace/control characters and bad labels.
    unsafe { domain_ok(dn, |c, _| res_printable(c)) as i32 }
}
alias_unsafe!(__res_dnok(dn: *const c_char) -> i32 = res_dnok;);
// # C: int res_hnok(const char *dn)
#[no_mangle]
pub unsafe extern "C" fn res_hnok(dn: *const c_char) -> i32 {
    // SAFETY: dn is a caller NUL-terminated host name.
    unsafe {
        if dn.is_null() { return 0; }
        let s = dn as *const u8;
        let c = *s;
        if c != 0 && c != b'.' && c != b'_' && !c.is_ascii_alphanumeric() { return 0; }
        domain_ok(dn, |c, escaped| host_char(c) && !(escaped && c == b'.')) as i32
    }
}
alias_unsafe!(__res_hnok(dn: *const c_char) -> i32 = res_hnok;);
// # C: int res_ownok(const char *dn)
#[no_mangle]
pub unsafe extern "C" fn res_ownok(dn: *const c_char) -> i32 {
    // SAFETY: dn is a caller NUL-terminated owner name. A leading "*." wildcard
    // is accepted in addition to the host-name subset.
    unsafe {
        if dn.is_null() { return 0; }
        let s = dn as *const u8;
        if *s == b'*' && *s.add(1) == b'.' {
            return domain_ok(s.add(2) as *const c_char, |c, escaped| host_char(c) && !(escaped && c == b'.')) as i32;
        }
        res_hnok(dn)
    }
}
alias_unsafe!(__res_ownok(dn: *const c_char) -> i32 = res_ownok;);
// # C: int res_mailok(const char *dn)
#[no_mangle]
pub unsafe extern "C" fn res_mailok(dn: *const c_char) -> i32 {
    // SAFETY: dn is a caller NUL-terminated mailbox name. The first label is
    // the local part and may contain printable punctuation; the remaining
    // suffix must be a valid general DNS domain.
    unsafe {
        if dn.is_null() { return 0; }
        let s = dn as *const u8;
        let n = nlen(s);
        if n == 0 || (n == 1 && *s == b'.') { return 1; }
        if !domain_ok(dn, |c, _| res_printable(c)) { return 0; }
        let Some(dot) = first_unescaped_dot(s, n) else { return 0; };
        if dot + 1 == n { return 0; }
        if dot == 0 || !label_ok(s, 0, dot, |c, _| res_printable(c)) { return 0; }
        domain_ok(s.add(dot + 1) as *const c_char, |c, escaped| host_char(c) && !(escaped && c == b'.')) as i32
    }
}
alias_unsafe!(__res_mailok(dn: *const c_char) -> i32 = res_mailok;);
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

// --- DNS message parser (ns_msg/ns_rr) -------------------------------------
const ENODEV: i32 = 19;

// ns_msg — 80-byte ABI per <arpa/nameser.h>. Macros (ns_msg_id/count/...) read
// these fields directly in the caller, so only the layout must match.
#[repr(C)]
pub struct NsMsg {
    msg: *const u8,            // @0  _msg
    eom: *const u8,            // @8  _eom
    id: u16,                   // @16 _id
    flags: u16,                // @18 _flags
    counts: [u16; 4],          // @20 _counts
    sections: [*const u8; 4],  // @32 _sections
    sect: i32,                 // @64 _sect
    rrnum: i32,                // @68 _rrnum
    msg_ptr: *const u8,        // @72 _msg_ptr
}

// ns_rr — 1048-byte ABI. name[1025] then type/class/ttl/rdlength/rdata.
#[repr(C)]
pub struct NsRr {
    name: [u8; 1025],          // @0
    rtype: u16,                // @1026
    rr_class: u16,             // @1028
    ttl: u32,                  // @1032
    rdlength: u16,             // @1036
    rdata: *const u8,          // @1040
}

// (mask, shift) per ns_flag (qr,opcode,aa,tc,rd,ra,z,ad,cd,rcode); glibc table.
const FLAGDATA: [(u16, u32); 10] = [
    (0x8000, 15), (0x7800, 11), (0x0400, 10), (0x0200, 9), (0x0100, 8),
    (0x0080, 7), (0x0040, 6), (0x0020, 5), (0x0010, 4), (0x000f, 0),
];

struct Out {
    buf: *mut u8,
    cap: usize,
    pos: usize,
    col: usize,
    ok: bool,
}

impl Out {
    fn new(buf: *mut c_char, cap: usize) -> Self {
        Self { buf: buf as *mut u8, cap, pos: 0, col: 0, ok: true }
    }
    unsafe fn byte(&mut self, b: u8) {
        if !self.ok { return; }
        if self.pos + 1 >= self.cap { self.ok = false; return; }
        // SAFETY: pos+1 < cap keeps room for the final NUL.
        unsafe { *self.buf.add(self.pos) = b; }
        self.pos += 1;
        self.col = if b == b'\n' { 0 } else if b == b'\t' { (self.col + 8) & !7 } else { self.col + 1 };
    }
    unsafe fn bytes(&mut self, s: &[u8]) {
        for &b in s {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b); }
        }
    }
    unsafe fn cstr(&mut self, s: *const c_char) {
        // SAFETY: s is a NUL-terminated C string from caller or stack scratch.
        unsafe { let mut p = s as *const u8; while *p != 0 { self.byte(*p); p = p.add(1); } }
    }
    unsafe fn dec(&mut self, mut v: u64) {
        let mut d = [0u8; 20]; let mut n = 0usize;
        if v == 0 { d[n] = b'0'; n += 1; }
        while v != 0 { d[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
        while n != 0 {
            n -= 1;
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(d[n]); }
        }
    }
    unsafe fn hex2(&mut self, b: u8) {
        const H: &[u8; 16] = b"0123456789abcdef";
        // SAFETY: byte() performs the destination capacity check.
        unsafe {
            self.byte(H[(b >> 4) as usize]);
            self.byte(H[(b & 15) as usize]);
        }
    }
    unsafe fn tabs_to(&mut self, col: usize) {
        if self.col >= col {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b'\t'); }
            return;
        }
        while self.col < col {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b'\t'); }
        }
    }
    unsafe fn finish(&mut self) -> i32 {
        if !self.ok || self.cap == 0 || self.pos >= self.cap {
            crate::internal::errno::set(EMSGSIZE);
            return -1;
        }
        // SAFETY: pos < cap, so the terminator fits.
        unsafe { *self.buf.add(self.pos) = 0; }
        self.pos as i32
    }
}

fn type_name(t: u16) -> Option<&'static [u8]> {
    Some(match t {
        1 => b"A", 2 => b"NS", 5 => b"CNAME", 6 => b"SOA", 12 => b"PTR",
        15 => b"MX", 16 => b"TXT", 28 => b"AAAA", 33 => b"SRV",
        _ => return None,
    })
}

fn class_name(c: u16) -> Option<&'static [u8]> {
    Some(match c {
        1 => b"IN", 3 => b"CHAOS", 4 => b"HS", 254 => b"NONE", 255 => b"ANY",
        _ => return None,
    })
}

unsafe fn append_domain(out: &mut Out, name: *const c_char, origin: *const c_char) {
    // SAFETY: name/origin are NUL-terminated presentation names. Canonicalizing
    // first makes ns_parserr-expanded names match ns_sprintrrf caller names.
    unsafe {
        let mut canon = [0 as c_char; 1025];
        if ns_makecanon(name, canon.as_mut_ptr(), canon.len()) < 0 { out.ok = false; return; }
        if !origin.is_null() {
            let mut ocanon = [0 as c_char; 1025];
            if ns_makecanon(origin, ocanon.as_mut_ptr(), ocanon.len()) < 0 { out.ok = false; return; }
            let n = canon.as_ptr() as *const u8;
            let o = ocanon.as_ptr() as *const u8;
            let nl = nlen(n);
            let ol = nlen(o);
            if nl == ol {
                let mut same = true;
                for i in 0..ol { if lc(*n.add(i)) != lc(*o.add(i)) { same = false; break; } }
                if same { out.byte(b'@'); return; }
            }
            if ol != 0 && nl > ol && *n.add(nl - ol - 1) == b'.' {
                let mut same = true;
                for i in 0..ol { if lc(*n.add(nl - ol + i)) != lc(*o.add(i)) { same = false; break; } }
                if same { for i in 0..(nl - ol - 1) { out.byte(*n.add(i)); } return; }
            }
        }
        out.cstr(canon.as_ptr());
    }
}

unsafe fn append_owner(out: &mut Out, name: *const c_char, origin: *const c_char) {
    // SAFETY: append_domain handles canonicalization and optional origin
    // relativization; owner names then pad to the fixed RR column.
    unsafe {
        append_domain(out, name, origin);
        out.tabs_to(24);
    }
}

unsafe fn append_ttl_class_type(out: &mut Out, class_: u16, type_: u16, ttl: u64) {
    // SAFETY: writes bounded stack-rendered TTL and static class/type labels.
    unsafe {
        let mut ttlbuf = [0 as c_char; 64];
        if ns_format_ttl(ttl, ttlbuf.as_mut_ptr(), ttlbuf.len()) < 0 { out.ok = false; return; }
        out.cstr(ttlbuf.as_ptr());
        out.byte(b' ');
        if let Some(cn) = class_name(class_) { out.bytes(cn); } else { out.dec(class_ as u64); }
        out.byte(b' ');
        if let Some(tn) = type_name(type_) { out.bytes(tn); } else { out.dec(type_ as u64); }
        out.tabs_to(40);
    }
}

unsafe fn append_name_rdata(out: &mut Out, msg: *const u8, msglen: usize, rdata: *const u8, origin: *const c_char) -> bool {
    // SAFETY: rdata points inside msg..msg+msglen for compressed-name RDATA.
    unsafe {
        let mut tmp = [0 as c_char; 1025];
        let eom = msg.add(msglen);
        if ns_name_uncompress(msg, eom, rdata, tmp.as_mut_ptr(), tmp.len()) < 0 { return false; }
        append_domain(out, tmp.as_ptr(), origin);
        true
    }
}

unsafe fn append_txt(out: &mut Out, rdata: *const u8, rdlen: usize) -> bool {
    // SAFETY: rdata is readable for rdlen bytes; TXT chunks are length-prefixed.
    unsafe {
        let mut off = 0usize; let mut first = true;
        while off < rdlen {
            let n = *rdata.add(off) as usize; off += 1;
            if off + n > rdlen { return false; }
            if !first { out.byte(b' '); } first = false;
            out.byte(b'"');
            for i in 0..n {
                let c = *rdata.add(off + i);
                if c == b'"' || c == b'\\' { out.byte(b'\\'); out.byte(c); }
                else if printable(c) || c == b' ' { out.byte(c); }
                else { out.byte(b'\\'); out.byte(b'0' + c / 100); out.byte(b'0' + (c / 10) % 10); out.byte(b'0' + c % 10); }
            }
            out.byte(b'"');
            off += n;
        }
        true
    }
}

unsafe fn append_rfc3597(out: &mut Out, type_: u16, rdata: *const u8, rdlen: usize) {
    // SAFETY: rdata readable for rdlen bytes; hex dump mirrors glibc's fallback.
    unsafe {
        out.bytes(b"\\# "); out.dec(rdlen as u64); out.bytes(b" (\t; unknown RR type "); out.dec(type_ as u64); out.byte(b'\n');
        out.byte(b'\t');
        for i in 0..rdlen {
            if i != 0 { out.byte(b' '); }
            out.hex2(*rdata.add(i));
        }
        out.bytes(b" )");
        for _ in 0..5 { out.byte(b'\t'); }
        out.bytes(b"; ...");
    }
}

unsafe fn append_rdata(out: &mut Out, msg: *const u8, msglen: usize, class_: u16, type_: u16, rdata: *const u8, rdlen: usize, origin: *const c_char) {
    // SAFETY: rdata readable for rdlen bytes; compressed names use msg/eom.
    unsafe {
        let ok = match (class_, type_) {
            (1, 1) if rdlen == 4 => { out.dec(*rdata as u64); out.byte(b'.'); out.dec(*rdata.add(1) as u64); out.byte(b'.'); out.dec(*rdata.add(2) as u64); out.byte(b'.'); out.dec(*rdata.add(3) as u64); true }
            (1, 28) if rdlen == 16 => {
                let mut a = [0u8; 16]; core::ptr::copy_nonoverlapping(rdata, a.as_mut_ptr(), 16);
                let mut tmp = [0u8; 64];
                if let Some(n) = crate::net::inet::ntop6(&a, &mut tmp) { out.bytes(&tmp[..n]); true } else { false }
            }
            (1, 2 | 5 | 12) => append_name_rdata(out, msg, msglen, rdata, origin),
            (1, 15) if rdlen >= 3 => { out.dec(rd16(rdata) as u64); out.byte(b' '); append_name_rdata(out, msg, msglen, rdata.add(2), origin) }
            (1, 16) => append_txt(out, rdata, rdlen),
            _ => false,
        };
        if !ok { append_rfc3597(out, type_, rdata, rdlen); }
    }
}

unsafe fn setsection(h: &mut NsMsg, sect: i32) {
    h.sect = sect;
    if sect == 4 { h.rrnum = -1; h.msg_ptr = core::ptr::null(); }
    else { h.rrnum = 0; h.msg_ptr = h.sections[sect as usize]; }
}
unsafe fn rd16(p: *const u8) -> u16 { unsafe { ((*p as u16) << 8) | *p.add(1) as u16 } }
unsafe fn rd32(p: *const u8) -> u32 { unsafe { ((*p as u32) << 24) | ((*p.add(1) as u32) << 16) | ((*p.add(2) as u32) << 8) | *p.add(3) as u32 } }

// # C: int ns_msg_getflag(ns_msg handle, int flag) — extract a header flag bit.
#[no_mangle]
pub extern "C" fn ns_msg_getflag(handle: NsMsg, flag: i32) -> i32 {
    if flag < 0 || flag as usize >= FLAGDATA.len() { return 0; }
    let (mask, shift) = FLAGDATA[flag as usize];
    ((handle.flags & mask) >> shift) as i32
}

// # C: int ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count)
// Bytes spanned by `count` RRs of `section` (questions carry no ttl/rdata).
#[no_mangle]
pub unsafe extern "C" fn ns_skiprr(ptr: *const u8, eom: *const u8, section: i32, count: i32) -> i32 {
    // SAFETY: ptr/eom bound a DNS message; dn_skipname + rdlength advance keep
    // every read within eom.
    unsafe {
        let optr = ptr; let mut p = ptr; let mut c = count;
        while c > 0 {
            let b = crate::net::resolv_name::dn_skipname(p, eom);
            if b < 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
            p = p.add(b as usize + 4); // name + type(2) + class(2)
            if section != 0 { // not ns_s_qd
                if p.add(6) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
                p = p.add(4); // ttl
                let rdlen = rd16(p) as usize; p = p.add(2 + rdlen);
            }
            c -= 1;
        }
        if p > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        (p as usize - optr as usize) as i32
    }
}

// # C: int ns_initparse(const u_char *msg, int msglen, ns_msg *handle)
#[no_mangle]
pub unsafe extern "C" fn ns_initparse(msg: *const u8, msglen: i32, handle: *mut NsMsg) -> i32 {
    // SAFETY: msg points at msglen bytes; handle is a caller ns_msg. Header (12B)
    // + per-section skip stay within eom; sections recorded for ns_parserr.
    unsafe {
        let h = &mut *handle;
        let eom = msg.add(msglen as usize);
        h.msg = msg; h.eom = eom;
        let mut p = msg;
        if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        h.id = rd16(p); p = p.add(2);
        if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        h.flags = rd16(p); p = p.add(2);
        for i in 0..4 {
            if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            h.counts[i] = rd16(p); p = p.add(2);
        }
        for i in 0..4 {
            if h.counts[i] == 0 { h.sections[i] = core::ptr::null(); }
            else {
                let b = ns_skiprr(p, eom, i as i32, h.counts[i] as i32);
                if b < 0 { return -1; }
                h.sections[i] = p; p = p.add(b as usize);
            }
        }
        if p != eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        setsection(h, 4);
        0
    }
}

// # C: int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr)
#[no_mangle]
pub unsafe extern "C" fn ns_parserr(handle: *mut NsMsg, section: i32, rrnum: i32, rr: *mut NsRr) -> i32 {
    // SAFETY: handle was filled by ns_initparse; rr is a caller ns_rr. Names are
    // expanded via ns_name_uncompress; every field read is eom-bounded.
    unsafe {
        let h = &mut *handle; let r = &mut *rr;
        if section < 0 || section >= 4 { crate::internal::errno::set(ENODEV); return -1; }
        if section != h.sect { setsection(h, section); }
        let mut rn = rrnum;
        if rn == -1 { rn = h.rrnum; }
        if rn < 0 || rn >= h.counts[section as usize] as i32 { crate::internal::errno::set(ENODEV); return -1; }
        if rn < h.rrnum { setsection(h, section); }
        if rn > h.rrnum {
            let b = ns_skiprr(h.msg_ptr, h.eom, section, rn - h.rrnum);
            if b < 0 { return -1; }
            h.msg_ptr = h.msg_ptr.add(b as usize); h.rrnum = rn;
        }
        let b = ns_name_uncompress(h.msg, h.eom, h.msg_ptr, r.name.as_mut_ptr() as *mut c_char, r.name.len());
        if b < 0 { return -1; }
        h.msg_ptr = h.msg_ptr.add(b as usize);
        if h.msg_ptr.add(4) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        r.rtype = rd16(h.msg_ptr); r.rr_class = rd16(h.msg_ptr.add(2)); h.msg_ptr = h.msg_ptr.add(4);
        if section == 0 { r.ttl = 0; r.rdlength = 0; r.rdata = core::ptr::null(); }
        else {
            if h.msg_ptr.add(6) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            r.ttl = rd32(h.msg_ptr); r.rdlength = rd16(h.msg_ptr.add(4)); h.msg_ptr = h.msg_ptr.add(6);
            if h.msg_ptr.add(r.rdlength as usize) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            r.rdata = h.msg_ptr; h.msg_ptr = h.msg_ptr.add(r.rdlength as usize);
        }
        h.rrnum += 1;
        if h.rrnum > h.counts[section as usize] as i32 { setsection(h, 4); }
        0
    }
}

// # C: int ns_sprintrrf(const unsigned char *msg, size_t msglen, const char *name,
//                       ns_class class, ns_type type, unsigned long ttl,
//                       const unsigned char *rdata, size_t rdlen,
//                       const char *name_ctx, const char *origin, char *buf, size_t bufsiz)
#[no_mangle]
pub unsafe extern "C" fn ns_sprintrrf(msg: *const u8, msglen: usize, name: *const c_char, class_: i32, type_: i32, ttl: u64, rdata: *const u8, rdlen: usize, _name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, bufsiz: usize) -> i32 {
    // SAFETY: caller supplies a DNS message, owner name, RDATA bytes, and output
    // buffer. All appends are capacity-checked; compressed RDATA names are
    // expanded against msg..msg+msglen.
    unsafe {
        if msg.is_null() || name.is_null() || buf.is_null() || (rdlen != 0 && rdata.is_null()) { crate::internal::errno::set(EINVAL); return -1; }
        let mut out = Out::new(buf, bufsiz);
        append_owner(&mut out, name, origin);
        append_ttl_class_type(&mut out, class_ as u16, type_ as u16, ttl);
        append_rdata(&mut out, msg, msglen, class_ as u16, type_ as u16, rdata, rdlen, origin);
        out.finish()
    }
}

// # C: int ns_sprintrr(const ns_msg *handle, const ns_rr *rr,
//                      const char *name_ctx, const char *origin, char *buf, size_t bufsiz)
#[no_mangle]
pub unsafe extern "C" fn ns_sprintrr(handle: *const NsMsg, rr: *const NsRr, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, bufsiz: usize) -> i32 {
    // SAFETY: handle comes from ns_initparse and rr from ns_parserr; forwards
    // message bounds plus the RR fields to ns_sprintrrf.
    unsafe {
        if handle.is_null() || rr.is_null() { crate::internal::errno::set(EINVAL); return -1; }
        let h = &*handle; let r = &*rr;
        ns_sprintrrf(h.msg, h.eom as usize - h.msg as usize, r.name.as_ptr() as *const c_char, r.rr_class as i32, r.rtype as i32, r.ttl as u64, r.rdata, r.rdlength as usize, name_ctx, origin, buf, bufsiz)
    }
}
