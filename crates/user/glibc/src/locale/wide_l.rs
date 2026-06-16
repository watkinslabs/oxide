// Wide-char `_l` variants (docs/59§6 §9.1). C/POSIX locale only, so each
// delegates to the base wide fn ignoring the locale_t. <wctype.h> declares
// these as plain functions (no locale-struct inlining, unlike narrow <ctype.h>),
// so plain delegation is safe.
#![cfg(feature = "freestanding")]
use core::ffi::c_char;

extern "C" {
    fn iswalnum(c: u32) -> i32; fn iswalpha(c: u32) -> i32; fn iswblank(c: u32) -> i32;
    fn iswcntrl(c: u32) -> i32; fn iswdigit(c: u32) -> i32; fn iswgraph(c: u32) -> i32;
    fn iswlower(c: u32) -> i32; fn iswprint(c: u32) -> i32; fn iswpunct(c: u32) -> i32;
    fn iswspace(c: u32) -> i32; fn iswupper(c: u32) -> i32; fn iswxdigit(c: u32) -> i32;
    fn iswctype(c: u32, desc: u64) -> i32;
    fn towlower(c: u32) -> u32; fn towupper(c: u32) -> u32; fn towctrans(c: u32, d: isize) -> u32;
    fn wctype(name: *const u8) -> u64; fn wctrans(name: *const u8) -> isize;
    fn wcscoll(a: *const i32, b: *const i32) -> i32;
    fn wcsxfrm(d: *mut i32, s: *const i32, n: usize) -> usize;
    fn wcscasecmp(a: *const i32, b: *const i32) -> i32;
    fn wcsncasecmp(a: *const i32, b: *const i32, n: usize) -> i32;
    fn wcstod(s: *const i32, e: *mut *mut i32) -> f64;
    fn wcstof(s: *const i32, e: *mut *mut i32) -> f32;
    fn wcstol(s: *const i32, e: *mut *mut i32, b: i32) -> i64;
    fn wcstoul(s: *const i32, e: *mut *mut i32, b: i32) -> u64;
    fn wcstoll(s: *const i32, e: *mut *mut i32, b: i32) -> i64;
    fn wcstoull(s: *const i32, e: *mut *mut i32, b: i32) -> u64;
}

macro_rules! cw { ($($name:ident => $base:ident),* $(,)?) => { $(
    // # C: int <name>(wint_t wc, locale_t loc) — C-locale wide ctype.
    #[no_mangle] pub unsafe extern "C" fn $name(wc: u32, _l: usize) -> i32 {
        // SAFETY: delegates to the base wide-ctype fn; locale ignored (C only).
        unsafe { $base(wc) }
    }
)* }; }
cw! {
    iswalnum_l => iswalnum, iswalpha_l => iswalpha, iswblank_l => iswblank,
    iswcntrl_l => iswcntrl, iswdigit_l => iswdigit, iswgraph_l => iswgraph,
    iswlower_l => iswlower, iswprint_l => iswprint, iswpunct_l => iswpunct,
    iswspace_l => iswspace, iswupper_l => iswupper, iswxdigit_l => iswxdigit,
}

// # C: int iswctype_l(wint_t, wctype_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn iswctype_l(wc: u32, desc: u64, _l: usize) -> i32 {
    // SAFETY: delegates to iswctype.
    unsafe { iswctype(wc, desc) }
}
// # C: wint_t towlower_l(wint_t, locale_t) / towupper_l
#[no_mangle] pub unsafe extern "C" fn towlower_l(wc: u32, _l: usize) -> u32 {
    // SAFETY: delegates to towlower.
    unsafe { towlower(wc) }
}
#[no_mangle] pub unsafe extern "C" fn towupper_l(wc: u32, _l: usize) -> u32 {
    // SAFETY: delegates to towupper.
    unsafe { towupper(wc) }
}
// # C: wint_t towctrans_l(wint_t, wctrans_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn towctrans_l(wc: u32, desc: isize, _l: usize) -> u32 {
    // SAFETY: delegates to towctrans.
    unsafe { towctrans(wc, desc) }
}
// # C: wctype_t wctype_l(const char*, locale_t)
#[no_mangle] pub unsafe extern "C" fn wctype_l(name: *const c_char, _l: usize) -> u64 {
    // SAFETY: name is a NUL class name; delegates to wctype.
    unsafe { wctype(name as *const u8) }
}
// # C: wctrans_t wctrans_l(const char*, locale_t)
#[no_mangle] pub unsafe extern "C" fn wctrans_l(name: *const c_char, _l: usize) -> isize {
    // SAFETY: name is a NUL mapping name; delegates to wctrans.
    unsafe { wctrans(name as *const u8) }
}

// --- wide string collation / case (C locale == code-point order) ---
#[no_mangle] pub unsafe extern "C" fn wcscoll_l(a: *const i32, b: *const i32, _l: usize) -> i32 {
    // SAFETY: C-locale collation == wcscoll.
    unsafe { wcscoll(a, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcsxfrm_l(d: *mut i32, s: *const i32, n: usize, _l: usize) -> usize {
    // SAFETY: C-locale transform == wcsxfrm.
    unsafe { wcsxfrm(d, s, n) }
}
#[no_mangle] pub unsafe extern "C" fn wcscasecmp_l(a: *const i32, b: *const i32, _l: usize) -> i32 {
    // SAFETY: C-locale case-fold == wcscasecmp.
    unsafe { wcscasecmp(a, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcsncasecmp_l(a: *const i32, b: *const i32, n: usize, _l: usize) -> i32 {
    // SAFETY: C-locale case-fold == wcsncasecmp.
    unsafe { wcsncasecmp(a, b, n) }
}

// --- wide numeric _l (+ C23 __isoc23_ and f32/f64 forms) ---
#[no_mangle] pub unsafe extern "C" fn wcstod_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f64 {
    // SAFETY: C-locale numeric parse == wcstod.
    unsafe { wcstod(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstof_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f32 {
    // SAFETY: == wcstof.
    unsafe { wcstof(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstof32_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f32 {
    // SAFETY: _Float32 == float == wcstof.
    unsafe { wcstof(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstof64_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f64 {
    // SAFETY: _Float64 == double == wcstod.
    unsafe { wcstod(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstol_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> i64 {
    // SAFETY: == wcstol.
    unsafe { wcstol(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoul_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> u64 {
    // SAFETY: == wcstoul.
    unsafe { wcstoul(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoll_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> i64 {
    // SAFETY: == wcstoll.
    unsafe { wcstoll(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoull_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> u64 {
    // SAFETY: == wcstoull.
    unsafe { wcstoull(s, e, b) }
}
// C23 entry points (modern GCC redirects wcstol_l → __isoc23_wcstol_l).
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstol_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> i64 {
    // SAFETY: C23 alias of wcstol_l.
    unsafe { wcstol_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoul_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> u64 {
    // SAFETY: C23 alias of wcstoul_l.
    unsafe { wcstoul_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoll_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> i64 {
    // SAFETY: C23 alias of wcstoll_l.
    unsafe { wcstoll_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoull_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> u64 {
    // SAFETY: C23 alias of wcstoull_l.
    unsafe { wcstoull_l(s, e, b, l) }
}
