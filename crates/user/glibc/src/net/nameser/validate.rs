use super::*;

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

