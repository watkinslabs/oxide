// Wide numeric conversion (docs/59§6) — wcstol/wcstoul/wcstoll/wcstoull/
// wcstoimax/wcstoumax/wcstod/wcstof. A numeric token is all-ASCII, so we
// transcode the leading run to a narrow buffer and delegate to the
// (well-tested) narrow strto* parsers, mapping the consumed count back to a
// wide endptr (1 wchar == 1 narrow byte in the token). Plus wcstok/wcswcs/
// wcscasecmp/wcsncasecmp/wmempcpy. C ABI only.
#![cfg(feature = "freestanding")]
use crate::stdlib::strto::{strtol_impl, strtoul_impl};
use crate::stdlib::strtod::strtod_impl;

// Copy the leading ASCII (<=0x7f, non-NUL) wchars into buf as bytes; NUL-term.
unsafe fn narrow(wcs: *const i32, buf: &mut [u8]) -> usize {
    // SAFETY: wcs is a 0-terminated wchar_t array; copy while bytes are ASCII.
    unsafe {
        let mut i = 0;
        while i + 1 < buf.len() {
            let c = *wcs.add(i);
            if c <= 0 || c > 0x7f { break; }
            buf[i] = c as u8;
            i += 1;
        }
        buf[i] = 0;
        i
    }
}

macro_rules! wint {
    ($(#[$m:meta])* $name:ident, $imp:path, $ret:ty) => {
        $(#[$m])*
        #[no_mangle]
        pub unsafe extern "C" fn $name(wcs: *const i32, endptr: *mut *mut i32, base: i32) -> $ret {
            // SAFETY: wcs 0-terminated; endptr null or writable. Transcode the
            // ASCII token, delegate, then map the narrow endptr back to wide.
            unsafe {
                let mut buf = [0u8; 160];
                narrow(wcs, &mut buf);
                let mut nend: *mut u8 = core::ptr::null_mut();
                let v = $imp(buf.as_ptr(), &mut nend, base);
                if !endptr.is_null() {
                    let consumed = nend as usize - buf.as_ptr() as usize;
                    *endptr = wcs.add(consumed) as *mut i32;
                }
                v as $ret
            }
        }
    };
}
wint!(/// # C: long wcstol(const wchar_t *, wchar_t **, int)
      wcstol, strtol_impl, i64);
wint!(/// # C: long long wcstoll(const wchar_t *, wchar_t **, int)
      wcstoll, strtol_impl, i64);
wint!(/// # C: intmax_t wcstoimax(const wchar_t *, wchar_t **, int)
      wcstoimax, strtol_impl, i64);
wint!(/// # C: unsigned long wcstoul(const wchar_t *, wchar_t **, int)
      wcstoul, strtoul_impl, u64);
wint!(/// # C: unsigned long long wcstoull(const wchar_t *, wchar_t **, int)
      wcstoull, strtoul_impl, u64);
wint!(/// # C: uintmax_t wcstoumax(const wchar_t *, wchar_t **, int)
      wcstoumax, strtoul_impl, u64);

// glibc 2.38+ headers redirect wcsto{l,ll,ul,ull,imax,umax} to these C23
// symbols (our parsers already follow the standard contract — alias them).
wint!(/// # C: long __isoc23_wcstol(...)
      __isoc23_wcstol, strtol_impl, i64);
wint!(/// # C: long long __isoc23_wcstoll(...)
      __isoc23_wcstoll, strtol_impl, i64);
wint!(/// # C: intmax_t __isoc23_wcstoimax(...)
      __isoc23_wcstoimax, strtol_impl, i64);
wint!(/// # C: unsigned long __isoc23_wcstoul(...)
      __isoc23_wcstoul, strtoul_impl, u64);
wint!(/// # C: unsigned long long __isoc23_wcstoull(...)
      __isoc23_wcstoull, strtoul_impl, u64);
wint!(/// # C: uintmax_t __isoc23_wcstoumax(...)
      __isoc23_wcstoumax, strtoul_impl, u64);

// # C: double wcstod(const wchar_t *, wchar_t **)
#[no_mangle]
pub unsafe extern "C" fn wcstod(wcs: *const i32, endptr: *mut *mut i32) -> f64 {
    // SAFETY: as the integer forms; delegate to the narrow strtod parser.
    unsafe {
        let mut buf = [0u8; 160];
        narrow(wcs, &mut buf);
        let mut nend: *mut u8 = core::ptr::null_mut();
        let v = strtod_impl(buf.as_ptr(), &mut nend);
        if !endptr.is_null() { *endptr = wcs.add(nend as usize - buf.as_ptr() as usize) as *mut i32; }
        v
    }
}
// # C: float wcstof(const wchar_t *, wchar_t **)
#[no_mangle]
pub unsafe extern "C" fn wcstof(wcs: *const i32, endptr: *mut *mut i32) -> f32 {
    // SAFETY: delegates to wcstod (same wcs/endptr contract), narrowed to float.
    unsafe { wcstod(wcs, endptr) as f32 }
}

#[inline]
fn lc(c: i32) -> i32 { if (0x41..=0x5a).contains(&c) { c + 32 } else { c } }

// # C: int wcscasecmp(const wchar_t *, const wchar_t *)
#[no_mangle]
pub unsafe extern "C" fn wcscasecmp(a: *const i32, b: *const i32) -> i32 {
    // SAFETY: a/b are 0-terminated wchar_t arrays; ASCII case-folded compare.
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (lc(*a.add(i)), lc(*b.add(i)));
            if x != y { return x - y; }
            if *a.add(i) == 0 { return 0; }
            i += 1;
        }
    }
}
// # C: int wcsncasecmp(const wchar_t *, const wchar_t *, size_t)
#[no_mangle]
pub unsafe extern "C" fn wcsncasecmp(a: *const i32, b: *const i32, n: usize) -> i32 {
    // SAFETY: a/b readable for up to n wchars or a 0; ASCII case-folded compare.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (lc(*a.add(i)), lc(*b.add(i)));
            if x != y { return x - y; }
            if *a.add(i) == 0 { return 0; }
            i += 1;
        }
        0
    }
}
// # C: wchar_t *wcstok(wchar_t *str, const wchar_t *delim, wchar_t **save)
#[no_mangle]
pub unsafe extern "C" fn wcstok(str: *mut i32, delim: *const i32, save: *mut *mut i32) -> *mut i32 {
    // SAFETY: str (or *save on continuation) and delim are 0-terminated; save is
    // a writable cursor. Skips leading delimiters, NUL-terminates the token.
    unsafe {
        let contains = |set: *const i32, c: i32| {
            let mut k = 0;
            loop {
                let s = *set.add(k);
                if s == 0 { return false; }
                if s == c { return true; }
                k += 1;
            }
        };
        let mut p = if str.is_null() { *save } else { str };
        if p.is_null() { return core::ptr::null_mut(); }
        while *p != 0 && contains(delim, *p) { p = p.add(1); }
        if *p == 0 { *save = p; return core::ptr::null_mut(); }
        let tok = p;
        while *p != 0 && !contains(delim, *p) { p = p.add(1); }
        if *p != 0 { *p = 0; *save = p.add(1); } else { *save = p; }
        tok
    }
}
// # C: wchar_t *wcswcs(const wchar_t *hay, const wchar_t *needle) — alias of wcsstr
#[no_mangle]
pub unsafe extern "C" fn wcswcs(hay: *const i32, needle: *const i32) -> *mut i32 {
    // SAFETY: both 0-terminated; forwards to the wcsstr implementation.
    unsafe { crate::string::wstr::wcsstr_impl(hay, needle) }
}
// # C: wchar_t *wmempcpy(wchar_t *d, const wchar_t *s, size_t n)
#[no_mangle]
pub unsafe extern "C" fn wmempcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    // SAFETY: d and s valid for n non-overlapping wchars; returns d+n.
    unsafe { core::ptr::copy_nonoverlapping(s, d, n); d.add(n) }
}
