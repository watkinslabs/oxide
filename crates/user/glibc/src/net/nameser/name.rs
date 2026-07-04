use super::*;
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
