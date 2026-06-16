// String → floating point (docs/59§6 G7). Scans a C float token (sign,
// inf/infinity/nan, decimal OR C99 hex mantissa + exponent), sets endptr, and
// parses decimals with core's correctly-rounded f64 parser — so strtod matches
// host glibc bit-for-bit on decimal text. Hex floats are parsed directly.
// ERANGE on overflow/underflow. atof wraps strtod.

const ERANGE: i32 = 34;

// Exact 2^n: build the f64 directly for normal exponents, else scale by halving
// /doubling (each step exact until it reaches the subnormal/overflow edge).
fn pow2(n: i32) -> f64 {
    if (-1022..=1023).contains(&n) { return f64::from_bits(((n + 1023) as u64) << 52); }
    let mut v = 1.0f64;
    let mut k = n;
    while k > 0 { v *= 2.0; k -= 1; }
    while k < 0 { v *= 0.5; k += 1; }
    v
}

#[derive(PartialEq)]
enum Kind { Bad, Dec, Hex, Lit } // Lit = inf/nan (no ERANGE)

fn lc(b: u8) -> u8 { b | 0x20 }
fn hexv(b: u8) -> Option<u32> { match b { b'0'..=b'9' => Some((b - b'0') as u32), b'a'..=b'f' => Some((lc(b) - b'a' + 10) as u32), b'A'..=b'F' => Some((b - b'A' + 10) as u32), _ => None } }

// Returns (start, end, kind, nonzero). `nonzero` = the mantissa had a nonzero
// digit (so a result of 0 means underflow, not a literal zero).
unsafe fn scan(s: *const u8) -> (*const u8, *const u8, Kind, bool) {
    // SAFETY: s is NUL-terminated; every advance stays before the NUL.
    unsafe {
        let mut p = s;
        while matches!(*p, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') { p = p.add(1); }
        let start = p;
        if *p == b'+' || *p == b'-' { p = p.add(1); }
        if lc(*p) == b'i' && lc(*p.add(1)) == b'n' && lc(*p.add(2)) == b'f' {
            p = p.add(3);
            if lc(*p) == b'i' && lc(*p.add(1)) == b'n' && lc(*p.add(2)) == b'i' && lc(*p.add(3)) == b't' && lc(*p.add(4)) == b'y' { p = p.add(5); }
            return (start, p, Kind::Lit, false);
        }
        if lc(*p) == b'n' && lc(*p.add(1)) == b'a' && lc(*p.add(2)) == b'n' { p = p.add(3); return (start, p, Kind::Lit, false); }
        // C99 hex float: 0x mantissa [.frac] [p exp]
        if *p == b'0' && lc(*p.add(1)) == b'x' {
            let mut q = p.add(2);
            let (mut any, mut nz) = (false, false);
            while let Some(d) = hexv(*q) { if d != 0 { nz = true; } q = q.add(1); any = true; }
            if *q == b'.' { q = q.add(1); while let Some(d) = hexv(*q) { if d != 0 { nz = true; } q = q.add(1); any = true; } }
            if !any { return (start, p.add(1), Kind::Dec, false); } // "0x" with no digits → just "0"
            if lc(*q) == b'p' {
                let mut r = q.add(1);
                if *r == b'+' || *r == b'-' { r = r.add(1); }
                if (*r).is_ascii_digit() { while (*r).is_ascii_digit() { r = r.add(1); } q = r; }
            }
            return (start, q, Kind::Hex, nz);
        }
        // decimal mantissa
        let (mut any, mut nz) = (false, false);
        while (*p).is_ascii_digit() { if *p != b'0' { nz = true; } p = p.add(1); any = true; }
        if *p == b'.' { p = p.add(1); while (*p).is_ascii_digit() { if *p != b'0' { nz = true; } p = p.add(1); any = true; } }
        if !any { return (s, s, Kind::Bad, false); }
        if lc(*p) == b'e' {
            let mut q = p.add(1);
            if *q == b'+' || *q == b'-' { q = q.add(1); }
            if (*q).is_ascii_digit() { while (*q).is_ascii_digit() { q = q.add(1); } p = q; }
        }
        (start, p, Kind::Dec, nz)
    }
}

// Parse a scanned C99 hex-float token [sign]0x h[.h][p[±]d] to f64. Exact for
// mantissas ≤ 13 hex digits (≤52 bits); the 2^exp scale is exact via powi.
unsafe fn parse_hex(start: *const u8, end: *const u8) -> f64 {
    // SAFETY: [start,end) is a validated hex-float token within the C string.
    unsafe {
        let mut p = start;
        let neg = *p == b'-';
        if *p == b'+' || *p == b'-' { p = p.add(1); }
        p = p.add(2); // skip "0x"
        let mut mant = 0f64;
        let mut bexp = 0i32; // base-2 exponent contribution from the fraction
        while p < end { if let Some(d) = hexv(*p) { mant = mant * 16.0 + d as f64; p = p.add(1); } else { break; } }
        if p < end && *p == b'.' { p = p.add(1); while p < end { if let Some(d) = hexv(*p) { mant = mant * 16.0 + d as f64; bexp -= 4; p = p.add(1); } else { break; } } }
        if p < end && lc(*p) == b'p' {
            p = p.add(1);
            let esign = *p == b'-';
            if *p == b'+' || *p == b'-' { p = p.add(1); }
            let mut e = 0i32;
            while p < end && (*p).is_ascii_digit() { e = e * 10 + (*p - b'0') as i32; p = p.add(1); }
            bexp += if esign { -e } else { e };
        }
        let v = mant * pow2(bexp);
        if neg { -v } else { v }
    }
}

// (value, numeric?, nonzero-mantissa?) — errno left to the typed wrappers.
pub(crate) unsafe fn strtod_full(s: *const u8, endptr: *mut *mut u8) -> (f64, bool, bool) {
    // SAFETY: s NUL-terminated; endptr null or writable.
    unsafe {
        let (start, end, kind, nz) = scan(s);
        if !endptr.is_null() { *endptr = if kind == Kind::Bad { s } else { end } as *mut u8; }
        let v = match kind {
            Kind::Bad => return (0.0, false, false),
            Kind::Hex => parse_hex(start, end),
            _ => {
                let bytes = core::slice::from_raw_parts(start, end as usize - start as usize);
                core::str::from_utf8(bytes).ok().and_then(|t| t.parse::<f64>().ok()).unwrap_or(0.0)
            }
        };
        (v, kind != Kind::Lit, nz)
    }
}

pub(crate) unsafe fn strtod_impl(s: *const u8, endptr: *mut *mut u8) -> f64 {
    // SAFETY: thin value-only wrapper (atof/tests); no errno side effect.
    unsafe { strtod_full(s, endptr).0 }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::internal::errno;
    // # C: double strtod(const char *s, char **endptr)
    #[no_mangle]
    pub unsafe extern "C" fn strtod(s: *const u8, endptr: *mut *mut u8) -> f64 {
        // SAFETY: forwards the C strtod contract; sets ERANGE on overflow
        // (±inf), underflow (subnormal), or a nonzero value rounding to 0.
        unsafe {
            let (v, num, nz) = strtod_full(s, endptr);
            if num && (v.is_infinite() || (v != 0.0 && v.is_subnormal()) || (v == 0.0 && nz)) { errno::set(ERANGE); }
            v
        }
    }
    // # C: _Float64 strtof64(const char *s, char **endptr) — == strtod on LP64.
    #[no_mangle]
    pub unsafe extern "C" fn strtof64(s: *const u8, endptr: *mut *mut u8) -> f64 {
        // SAFETY: _Float64 == double; same contract as strtod.
        unsafe { strtod(s, endptr) }
    }
    // # C: float strtof(const char *s, char **endptr)
    #[no_mangle]
    pub unsafe extern "C" fn strtof(s: *const u8, endptr: *mut *mut u8) -> f32 {
        // SAFETY: parse as f64, narrow to f32, and apply ERANGE against the
        // float range (a finite f64 can overflow/underflow when narrowed).
        unsafe {
            let (v, num, nz) = strtod_full(s, endptr);
            let f = v as f32;
            if num && (f.is_infinite() || (f != 0.0 && f.is_subnormal()) || (f == 0.0 && nz)) { errno::set(ERANGE); }
            f
        }
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
