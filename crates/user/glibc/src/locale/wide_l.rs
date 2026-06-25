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

macro_rules! cw_alias { ($($alias:ident => $base:ident),* $(,)?) => { $(
    // # C: int <alias>(wint_t wc, locale_t loc) — glibc internal wide ctype alias.
    #[no_mangle] pub unsafe extern "C" fn $alias(wc: u32, loc: usize) -> i32 {
        // SAFETY: internal alias with the same wc/locale_t contract as base.
        unsafe { $base(wc, loc) }
    }
)* }; }
cw_alias! {
    __iswalnum_l => iswalnum_l, __iswalpha_l => iswalpha_l, __iswblank_l => iswblank_l,
    __iswcntrl_l => iswcntrl_l, __iswdigit_l => iswdigit_l, __iswgraph_l => iswgraph_l,
    __iswlower_l => iswlower_l, __iswprint_l => iswprint_l, __iswpunct_l => iswpunct_l,
    __iswspace_l => iswspace_l, __iswupper_l => iswupper_l, __iswxdigit_l => iswxdigit_l,
}

// # C: int iswctype_l(wint_t, wctype_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn iswctype_l(wc: u32, desc: u64, _l: usize) -> i32 {
    // SAFETY: C-locale delegator; forwards to iswctype, ignoring the locale arg.
    unsafe { iswctype(wc, desc) }
}
// # C: int __iswctype_l(wint_t, wctype_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn __iswctype_l(wc: u32, desc: u64, l: usize) -> i32 {
    // SAFETY: internal alias with the same wc/desc/locale_t contract as iswctype_l.
    unsafe { iswctype_l(wc, desc, l) }
}
// # C: wint_t towlower_l(wint_t, locale_t) / towupper_l
#[no_mangle] pub unsafe extern "C" fn towlower_l(wc: u32, _l: usize) -> u32 {
    // SAFETY: C-locale delegator; forwards to towlower, ignoring the locale arg.
    unsafe { towlower(wc) }
}
// # C: wint_t __towlower_l(wint_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn __towlower_l(wc: u32, l: usize) -> u32 {
    // SAFETY: internal alias with the same wc/locale_t contract as towlower_l.
    unsafe { towlower_l(wc, l) }
}
#[no_mangle] pub unsafe extern "C" fn towupper_l(wc: u32, _l: usize) -> u32 {
    // SAFETY: C-locale delegator; forwards to towupper, ignoring the locale arg.
    unsafe { towupper(wc) }
}
// # C: wint_t __towupper_l(wint_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn __towupper_l(wc: u32, l: usize) -> u32 {
    // SAFETY: internal alias with the same wc/locale_t contract as towupper_l.
    unsafe { towupper_l(wc, l) }
}
// # C: wint_t towctrans_l(wint_t, wctrans_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn towctrans_l(wc: u32, desc: isize, _l: usize) -> u32 {
    // SAFETY: C-locale delegator; forwards to towctrans, ignoring the locale arg.
    unsafe { towctrans(wc, desc) }
}
// # C: wint_t __towctrans_l(wint_t, wctrans_t, locale_t)
#[no_mangle] pub unsafe extern "C" fn __towctrans_l(wc: u32, desc: isize, l: usize) -> u32 {
    // SAFETY: internal alias with the same wc/desc/locale_t contract as towctrans_l.
    unsafe { towctrans_l(wc, desc, l) }
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
    // SAFETY: C-locale delegator forwarding to wcstof (locale-invariant).
    unsafe { wcstof(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstof32_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f32 {
    // SAFETY: _Float32 == float; C-locale delegator forwarding to wcstof.
    unsafe { wcstof(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstof64_l(s: *const i32, e: *mut *mut i32, _l: usize) -> f64 {
    // SAFETY: _Float64 == double; C-locale delegator forwarding to wcstod.
    unsafe { wcstod(s, e) }
}
#[no_mangle] pub unsafe extern "C" fn wcstol_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> i64 {
    // SAFETY: C-locale delegator forwarding to wcstol (locale-invariant).
    unsafe { wcstol(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoul_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> u64 {
    // SAFETY: C-locale delegator forwarding to wcstoul (locale-invariant).
    unsafe { wcstoul(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoll_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> i64 {
    // SAFETY: C-locale delegator forwarding to wcstoll (locale-invariant).
    unsafe { wcstoll(s, e, b) }
}
#[no_mangle] pub unsafe extern "C" fn wcstoull_l(s: *const i32, e: *mut *mut i32, b: i32, _l: usize) -> u64 {
    // SAFETY: C-locale delegator forwarding to wcstoull (locale-invariant).
    unsafe { wcstoull(s, e, b) }
}
// C23 entry points (modern GCC redirects wcstol_l → __isoc23_wcstol_l).
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstol_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> i64 {
    // SAFETY: C23 entry point; forwards to wcstol_l with the same args.
    unsafe { wcstol_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoul_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> u64 {
    // SAFETY: C23 entry point; forwards to wcstoul_l with the same args.
    unsafe { wcstoul_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoll_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> i64 {
    // SAFETY: C23 entry point; forwards to wcstoll_l with the same args.
    unsafe { wcstoll_l(s, e, b, l) }
}
#[no_mangle] pub unsafe extern "C" fn __isoc23_wcstoull_l(s: *const i32, e: *mut *mut i32, b: i32, l: usize) -> u64 {
    // SAFETY: C23 entry point; forwards to wcstoull_l with the same args.
    unsafe { wcstoull_l(s, e, b, l) }
}
