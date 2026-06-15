// String → integer (docs/59§6 G7). strtol/strtoul/strtoll/strtoull with
// base 0/2..36, leading whitespace, optional sign, 0x/0 prefixes, endptr,
// and ERANGE clamping. atoi/atol/atoll wrap them. strtod/strtof live in
// the G7b float file. Differentially tested vs host strtol/strtoul.
use crate::internal::errno;

const ERANGE: i32 = 34;

struct Parsed { val: u64, neg: bool, overflow: bool, end: *const u8, any: bool }

unsafe fn dval(c: u8) -> Option<u32> {
    match c { b'0'..=b'9' => Some((c - b'0') as u32), b'a'..=b'z' => Some((c - b'a' + 10) as u32), b'A'..=b'Z' => Some((c - b'A' + 10) as u32), _ => None }
}

unsafe fn parse(s: *const u8, mut base: i32) -> Parsed {
    // SAFETY: s is a NUL-terminated string; every read advances within it.
    unsafe {
        let mut p = s;
        while matches!(*p, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') { p = p.add(1); }
        let mut neg = false;
        if *p == b'+' || *p == b'-' { neg = *p == b'-'; p = p.add(1); }
        // A 0x/0b prefix is consumed only when a valid digit follows; otherwise
        // the leading '0' is itself the value (endptr at the 'x'/'b'). glibc
        // (2.38+) accepts the 0b/0B binary prefix in base 0 and base 2.
        let is_hex = |c: u8| matches!(dval(c), Some(d) if d < 16);
        let is_bin = |c: u8| c == b'0' || c == b'1';
        if base == 0 {
            if *p == b'0' {
                let c1 = *p.add(1);
                if (c1 == b'x' || c1 == b'X') && is_hex(*p.add(2)) { base = 16; p = p.add(2); }
                else if (c1 == b'b' || c1 == b'B') && is_bin(*p.add(2)) { base = 2; p = p.add(2); }
                else { base = 8; } // leading 0 → octal; the '0' digit is read below
            } else { base = 10; }
        } else if *p == b'0'
            && ((base == 16 && (*p.add(1) == b'x' || *p.add(1) == b'X') && is_hex(*p.add(2)))
                || (base == 2 && (*p.add(1) == b'b' || *p.add(1) == b'B') && is_bin(*p.add(2))))
        {
            p = p.add(2);
        }
        let b = base as u64;
        let mut val: u64 = 0;
        let mut overflow = false;
        let mut any = false;
        let digits_start = p;
        loop {
            match dval(*p) { Some(d) if (d as u64) < b => {
                any = true;
                let (m, o1) = val.overflowing_mul(b);
                let (a, o2) = m.overflowing_add(d as u64);
                if o1 || o2 { overflow = true; } else { val = a; }
                p = p.add(1);
            }, _ => break }
        }
        // endptr: if a 0x prefix was consumed but no hex digit followed, C
        // points end back at the '0'. Approximate: if no digits, end = s.
        let end = if any { p } else { let _ = digits_start; s };
        Parsed { val, neg, overflow, end, any }
    }
}

unsafe fn set_end(endptr: *mut *mut u8, end: *const u8) {
    // SAFETY: endptr is null or a valid out-param per the C strto* contract.
    unsafe { if !endptr.is_null() { *endptr = end as *mut u8; } }
}

pub(crate) unsafe fn strtoul_impl(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    // SAFETY: s NUL-terminated; endptr null or writable.
    unsafe {
        let r = parse(s, base);
        set_end(endptr, r.end);
        if r.overflow { errno::set(ERANGE); return u64::MAX; }
        if r.neg { 0u64.wrapping_sub(r.val) } else { r.val }
    }
}

pub(crate) unsafe fn strtol_impl(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    // SAFETY: s NUL-terminated; endptr null or writable.
    unsafe {
        let r = parse(s, base);
        set_end(endptr, r.end);
        if r.neg {
            if r.overflow || r.val > (i64::MAX as u64) + 1 { errno::set(ERANGE); return i64::MIN; }
            (0i64).wrapping_sub(r.val as i64)
        } else {
            if r.overflow || r.val > i64::MAX as u64 { errno::set(ERANGE); return i64::MAX; }
            r.val as i64
        }
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: long strtol(const char *s, char **endptr, int base)
    #[no_mangle]
    pub unsafe extern "C" fn strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: forwards the C strtol contract unchanged.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: long long strtoll(...) — same width as long on LP64
    #[no_mangle]
    pub unsafe extern "C" fn strtoll(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: LP64 long long == long; forwards strtol_impl.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: unsigned long strtoul(const char *s, char **endptr, int base)
    #[no_mangle]
    pub unsafe extern "C" fn strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: forwards the C strtoul contract unchanged.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // # C: unsigned long long strtoull(...)
    #[no_mangle]
    pub unsafe extern "C" fn strtoull(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: LP64 unsigned long long == unsigned long; forwards.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // C23 variants: glibc 2.38+ headers redirect strto{l,ll,ul,ull} to these
    // __isoc23_* symbols (they add the C23 "0b" binary-prefix rule for base
    // 0/2). Our strto*_impl already follows the standard contract; alias them.
    // # C: long __isoc23_strtol(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: same contract as strtol; forwards strtol_impl.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: long long __isoc23_strtoll(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtoll(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: LP64 long long == long; forwards strtol_impl.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: unsigned long __isoc23_strtoul(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: same contract as strtoul; forwards strtoul_impl.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // # C: unsigned long long __isoc23_strtoull(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtoull(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: LP64 unsigned long long == unsigned long; forwards.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // <inttypes.h>: intmax_t/uintmax_t are i64/u64 on LP64 == long long.
    // # C: intmax_t strtoimax(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn strtoimax(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: LP64 intmax_t == long; forwards strtol_impl.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: uintmax_t strtoumax(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn strtoumax(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: LP64 uintmax_t == unsigned long; forwards strtoul_impl.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // # C: intmax_t __isoc23_strtoimax(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtoimax(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: same contract as strtoimax; forwards strtol_impl.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: uintmax_t __isoc23_strtoumax(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn __isoc23_strtoumax(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: same contract as strtoumax; forwards strtoul_impl.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // BSD aliases (<stdlib.h>): quad_t / u_quad_t are i64/u64 == long long.
    // # C: long long strtoq(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn strtoq(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
        // SAFETY: strtoq == strtoll; forwards the signed strtol_impl unchanged.
        unsafe { strtol_impl(s, endptr, base) }
    }
    // # C: unsigned long long strtouq(const char *, char **, int)
    #[no_mangle]
    pub unsafe extern "C" fn strtouq(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
        // SAFETY: strtouq == strtoull; forwards the unsigned strtoul_impl unchanged.
        unsafe { strtoul_impl(s, endptr, base) }
    }
    // # C: int atoi(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn atoi(s: *const u8) -> i32 {
        // SAFETY: atoi == (int)strtol(s,0,10); s is NUL-terminated.
        unsafe { strtol_impl(s, core::ptr::null_mut(), 10) as i32 }
    }
    // # C: long atol(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn atol(s: *const u8) -> i64 {
        // SAFETY: atol == strtol(s,0,10); s is NUL-terminated.
        unsafe { strtol_impl(s, core::ptr::null_mut(), 10) }
    }
    // # C: long long atoll(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn atoll(s: *const u8) -> i64 {
        // SAFETY: atoll == strtoll(s,0,10); s is NUL-terminated.
        unsafe { strtol_impl(s, core::ptr::null_mut(), 10) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::String};
    use proptest::prelude::*;

    fn ours_l(s: &str, base: i32) -> (i64, isize) {
        let c = format!("{s}\0");
        let mut end: *mut u8 = core::ptr::null_mut();
        // SAFETY: c is NUL-terminated; end receives the stop pointer.
        let v = unsafe { strtol_impl(c.as_ptr(), &mut end, base) };
        (v, (end as usize as isize) - (c.as_ptr() as usize as isize))
    }
    fn host_l(s: &str, base: i32) -> (i64, isize) {
        let c = format!("{s}\0");
        let mut end: *mut i8 = core::ptr::null_mut();
        // SAFETY: c is NUL-terminated; end receives the stop pointer.
        let v = unsafe { libc::strtol(c.as_ptr() as *const _, &mut end, base) };
        (v, (end as usize as isize) - (c.as_ptr() as usize as isize))
    }
    fn ours_ul(s: &str, base: i32) -> u64 {
        let c = format!("{s}\0");
        // SAFETY: c is NUL-terminated; no endptr.
        unsafe { strtoul_impl(c.as_ptr(), core::ptr::null_mut(), base) }
    }
    fn host_ul(s: &str, base: i32) -> u64 {
        let c = format!("{s}\0");
        // SAFETY: c is NUL-terminated; no endptr.
        unsafe { libc::strtoul(c.as_ptr() as *const _, core::ptr::null_mut(), base) }
    }

    proptest! {
        #[test]
        fn strtol_dec(v in any::<i64>(), pad in 0usize..3, trail in "[^0-9]{0,3}") {
            let sp: String = core::iter::repeat(' ').take(pad).collect();
            let s = format!("{sp}{v}{trail}");
            prop_assert_eq!(ours_l(&s, 10), host_l(&s, 10), "s={:?}", s);
        }
        #[test]
        fn strtol_base0(v in any::<i32>()) {
            for s in [format!("{v}"), format!("{:#x}", v), format!("0{:o}", v.unsigned_abs())] {
                prop_assert_eq!(ours_l(&s, 0), host_l(&s, 0), "s={:?}", s);
            }
        }
        #[test]
        fn strtoul_hex(v in any::<u64>()) {
            let s = format!("{:x}", v);
            prop_assert_eq!(ours_ul(&s, 16), host_ul(&s, 16), "s={:?}", s);
        }
        #[test]
        fn strtol_overflow(s in "[0-9]{18,25}") {
            prop_assert_eq!(ours_l(&s, 10), host_l(&s, 10), "s={:?}", s);
        }
    }
}
