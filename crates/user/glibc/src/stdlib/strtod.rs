// String → floating point (docs/59§6 G7). Scans a C float token
// (sign, inf/infinity/nan, decimal mantissa + exponent), sets endptr, and
// parses with core's correctly-rounded f64 parser — so strtod matches
// host glibc bit-for-bit on the same decimal text. Hex floats (0x1.8p3)
// and the "." -mantissa edge are follow-ups. atof wraps strtod.

fn lc(b: u8) -> u8 { b | 0x20 }

// Returns (start_of_number, end_after_token, valid). `start` is the first
// byte of the numeric text (sign included) for the parser.
unsafe fn scan(s: *const u8) -> (*const u8, *const u8, bool) {
    // SAFETY: s is NUL-terminated; every advance stays before the NUL.
    unsafe {
        let mut p = s;
        while matches!(*p, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') { p = p.add(1); }
        let start = p;
        if *p == b'+' || *p == b'-' { p = p.add(1); }
        // inf / infinity
        if lc(*p) == b'i' && lc(*p.add(1)) == b'n' && lc(*p.add(2)) == b'f' {
            p = p.add(3);
            if lc(*p) == b'i' && lc(*p.add(1)) == b'n' && lc(*p.add(2)) == b'i' && lc(*p.add(3)) == b't' && lc(*p.add(4)) == b'y' { p = p.add(5); }
            return (start, p, true);
        }
        if lc(*p) == b'n' && lc(*p.add(1)) == b'a' && lc(*p.add(2)) == b'n' { p = p.add(3); return (start, p, true); }
        // decimal mantissa
        let mut any = false;
        while (*p).is_ascii_digit() { p = p.add(1); any = true; }
        if *p == b'.' { p = p.add(1); while (*p).is_ascii_digit() { p = p.add(1); any = true; } }
        if !any { return (s, s, false); }
        // exponent
        if lc(*p) == b'e' {
            let mut q = p.add(1);
            if *q == b'+' || *q == b'-' { q = q.add(1); }
            if (*q).is_ascii_digit() { while (*q).is_ascii_digit() { q = q.add(1); } p = q; }
        }
        (start, p, true)
    }
}

pub(crate) unsafe fn strtod_impl(s: *const u8, endptr: *mut *mut u8) -> f64 {
    // SAFETY: s NUL-terminated; endptr null or writable. The scanned span
    // is valid UTF-8 ASCII and a well-formed Rust float literal.
    unsafe {
        let (start, end, ok) = scan(s);
        if !endptr.is_null() { *endptr = if ok { end } else { s } as *mut u8; }
        if !ok { return 0.0; }
        let len = end as usize - start as usize;
        let bytes = core::slice::from_raw_parts(start, len);
        core::str::from_utf8(bytes).ok().and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0)
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: double strtod(const char *s, char **endptr)
    #[no_mangle]
    pub unsafe extern "C" fn strtod(s: *const u8, endptr: *mut *mut u8) -> f64 {
        // SAFETY: forwards the C strtod contract unchanged.
        unsafe { strtod_impl(s, endptr) }
    }
    // # C: float strtof(const char *s, char **endptr)
    #[no_mangle]
    pub unsafe extern "C" fn strtof(s: *const u8, endptr: *mut *mut u8) -> f32 {
        // SAFETY: forwards strtod then narrows to float.
        unsafe { strtod_impl(s, endptr) as f32 }
    }
    // # C: double atof(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn atof(s: *const u8) -> f64 {
        // SAFETY: atof == strtod(s, NULL); s is NUL-terminated.
        unsafe { strtod_impl(s, core::ptr::null_mut()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use proptest::prelude::*;

    fn ours(s: &str) -> (f64, isize) {
        let c = format!("{s}\0");
        let mut end: *mut u8 = core::ptr::null_mut();
        // SAFETY: c is NUL-terminated; end receives the stop pointer.
        let v = unsafe { strtod_impl(c.as_ptr(), &mut end) };
        (v, (end as usize as isize) - (c.as_ptr() as usize as isize))
    }
    fn host(s: &str) -> (f64, isize) {
        let c = format!("{s}\0");
        let mut end: *mut i8 = core::ptr::null_mut();
        // SAFETY: c is NUL-terminated; end receives the stop pointer.
        let v = unsafe { libc::strtod(c.as_ptr() as *const _, &mut end) };
        (v, (end as usize as isize) - (c.as_ptr() as usize as isize))
    }
    fn eq(a: (f64, isize), b: (f64, isize)) -> bool {
        a.1 == b.1 && (a.0.to_bits() == b.0.to_bits() || (a.0.is_nan() && b.0.is_nan()))
    }
    proptest! {
        #[test]
        fn strtod_matches(v in any::<f64>().prop_filter("finite", |x| x.is_finite())) {
            let s = format!("{v}");
            prop_assert!(eq(ours(&s), host(&s)), "s={:?} ours={:?} host={:?}", s, ours(&s), host(&s));
        }
        #[test]
        fn strtod_sci_and_trailing(m in -1000i64..1000, e in -20i32..20, trail in "[^0-9eE.+-]{0,3}") {
            let s = format!("{m}.5e{e}{trail}");
            prop_assert!(eq(ours(&s), host(&s)), "s={:?} ours={:?} host={:?}", s, ours(&s), host(&s));
        }
    }
}
