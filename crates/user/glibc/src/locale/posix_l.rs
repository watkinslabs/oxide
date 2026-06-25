// locale `_l` variants + the locale object (docs/59§6 §9.1, G16). We support the
// C/POSIX locale only (incl. C.UTF-8), so every `_l` entry point ignores its
// locale_t and delegates to the base function — semantically exact for C.
// newlocale/duplocale return distinct heap handles; uselocale swaps the
// thread's active locale (cosmetic: all locales behave as C).
#![cfg(feature = "freestanding")]
use core::ffi::c_char;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::malloc::heap;

const LC_GLOBAL_LOCALE: usize = usize::MAX; // (locale_t)-1
const EINVAL: i32 = 22;

// Intra-libc base functions the `_l` wrappers delegate to.
extern "C" {
    fn isalnum(c: i32) -> i32; fn isalpha(c: i32) -> i32; fn isblank(c: i32) -> i32;
    fn iscntrl(c: i32) -> i32; fn isdigit(c: i32) -> i32; fn isgraph(c: i32) -> i32;
    fn islower(c: i32) -> i32; fn isprint(c: i32) -> i32; fn ispunct(c: i32) -> i32;
    fn isspace(c: i32) -> i32; fn isupper(c: i32) -> i32; fn isxdigit(c: i32) -> i32;
    fn tolower(c: i32) -> i32; fn toupper(c: i32) -> i32;
    fn strtod(n: *const c_char, e: *mut *mut c_char) -> f64;
    fn strtof(n: *const c_char, e: *mut *mut c_char) -> f32;
    fn strtol(n: *const c_char, e: *mut *mut c_char, b: i32) -> i64;
    fn strtoul(n: *const c_char, e: *mut *mut c_char, b: i32) -> u64;
    fn strtoll(n: *const c_char, e: *mut *mut c_char, b: i32) -> i64;
    fn strtoull(n: *const c_char, e: *mut *mut c_char, b: i32) -> u64;
    fn strcoll(a: *const c_char, b: *const c_char) -> i32;
    fn strxfrm(d: *mut c_char, s: *const c_char, n: usize) -> usize;
    fn strcasecmp(a: *const c_char, b: *const c_char) -> i32;
    fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> i32;
    fn strerror(e: i32) -> *mut u8;
    fn nl_langinfo(item: i32) -> *mut c_char;
    // ctype table accessors — *loc() derefs once to the +128-offset table base.
    fn __ctype_b_loc() -> *mut *const u16;
    fn __ctype_tolower_loc() -> *mut *const i32;
    fn __ctype_toupper_loc() -> *mut *const i32;
}

// glibc's <ctype.h> inlines is*_l(c, loc) as `loc->__ctype_b[c] & bit`, so a
// locale_t is NOT opaque — the struct must carry the ctype table pointers at
// their __locale_struct offsets: __locales[13] (0..104), __ctype_b@104,
// __ctype_tolower@112, __ctype_toupper@120, __names[13] (128..232).
const LOCALE_SIZE: usize = 232;
const OFF_CTYPE_B: usize = 104;
const OFF_TOLOWER: usize = 112;
const OFF_TOUPPER: usize = 120;

// Allocate + populate a __locale_struct pointing at our C-locale ctype tables.
unsafe fn make_locale() -> usize {
    // SAFETY: malloc a zeroed __locale_struct and write the three ctype table
    // base pointers (from the *_loc accessors) at their fixed offsets so the
    // header's inlined is*_l/tolower_l/toupper_l macros index valid memory.
    unsafe {
        let p = heap::malloc(LOCALE_SIZE);
        if p.is_null() { return 0; }
        core::ptr::write_bytes(p, 0, LOCALE_SIZE);
        *(p.add(OFF_CTYPE_B) as *mut *const u16) = *__ctype_b_loc();
        *(p.add(OFF_TOLOWER) as *mut *const i32) = *__ctype_tolower_loc();
        *(p.add(OFF_TOUPPER) as *mut *const i32) = *__ctype_toupper_loc();
        p as usize
    }
}

// --- locale object ---------------------------------------------------------
static CURRENT: AtomicUsize = AtomicUsize::new(LC_GLOBAL_LOCALE);

fn name_is_c(name: *const c_char) -> bool {
    if name.is_null() { return true; }
    // SAFETY: name is a NUL-terminated locale name; we only accept C-equivalents.
    unsafe {
        let n = crate::string::len::strlen_impl(name as *mut u8);
        let s = core::slice::from_raw_parts(name as *const u8, n);
        matches!(s, b"" | b"C" | b"POSIX" | b"C.UTF-8" | b"C.utf8")
    }
}

// # C: locale_t newlocale(int category_mask, const char *locale, locale_t base)
#[no_mangle]
pub unsafe extern "C" fn newlocale(_mask: i32, locale: *const c_char, base: usize) -> usize {
    // SAFETY: locale is null or a NUL name; base is null/LC_GLOBAL/a prior
    // handle we consume. Only C-equivalent locales exist → a fresh dummy handle.
    unsafe {
        if !name_is_c(locale) { *crate::internal::errno::__errno_location() = EINVAL; return 0; }
        if base != 0 && base != LC_GLOBAL_LOCALE { heap::free(base as *mut u8); }
        let h = make_locale();
        if h == 0 { *crate::internal::errno::__errno_location() = 12; }
        h
    }
}
// # C: locale_t duplocale(locale_t loc)
#[no_mangle]
pub unsafe extern "C" fn duplocale(_loc: usize) -> usize {
    // SAFETY: returns a fresh __locale_struct (all locales are C-equivalent).
    unsafe { make_locale() }
}
// # C: locale_t __duplocale(locale_t loc)
#[no_mangle]
pub unsafe extern "C" fn __duplocale(loc: usize) -> usize {
    // SAFETY: __duplocale has the same locale handle contract as duplocale.
    unsafe { duplocale(loc) }
}
// # C: void freelocale(locale_t loc)
#[no_mangle]
pub unsafe extern "C" fn freelocale(loc: usize) {
    // SAFETY: loc is a handle from newlocale/duplocale (not LC_GLOBAL/null).
    unsafe { if loc != 0 && loc != LC_GLOBAL_LOCALE { heap::free(loc as *mut u8); } }
}
// # C: void __freelocale(locale_t loc)
#[no_mangle]
pub unsafe extern "C" fn __freelocale(loc: usize) {
    // SAFETY: __freelocale has the same locale handle contract as freelocale.
    unsafe { freelocale(loc) }
}
// # C: locale_t uselocale(locale_t newloc)
#[no_mangle]
pub extern "C" fn uselocale(newloc: usize) -> usize {
    // 0 = query (no change). All locales behave as C, so this is cosmetic.
    if newloc == 0 { return CURRENT.load(Ordering::Relaxed); }
    CURRENT.swap(newloc, Ordering::Relaxed)
}

// --- ctype _l (delegate to the C-locale base) ------------------------------
macro_rules! ctype_l {
    ($($name:ident => $base:ident),* $(,)?) => { $(
        // # C: int <name>(int c, locale_t loc) — C-locale ctype.
        #[no_mangle]
        pub unsafe extern "C" fn $name(c: i32, _loc: usize) -> i32 {
            // SAFETY: delegates to the base ctype fn; the locale arg is ignored
            // (only the C locale exists, so classification is locale-independent).
            unsafe { $base(c) }
        }
    )* };
}
ctype_l! {
    isalnum_l => isalnum, isalpha_l => isalpha, isblank_l => isblank,
    iscntrl_l => iscntrl, isdigit_l => isdigit, isgraph_l => isgraph,
    islower_l => islower, isprint_l => isprint, ispunct_l => ispunct,
    isspace_l => isspace, isupper_l => isupper, isxdigit_l => isxdigit,
    tolower_l => tolower, toupper_l => toupper,
}

macro_rules! ctype_l_alias {
    ($($alias:ident => $base:ident),* $(,)?) => { $(
        // # C: int <alias>(int c, locale_t loc) — glibc internal ctype alias.
        #[no_mangle]
        pub unsafe extern "C" fn $alias(c: i32, loc: usize) -> i32 {
            // SAFETY: internal alias with the same c/locale_t contract as base.
            unsafe { $base(c, loc) }
        }
    )* };
}
ctype_l_alias! {
    __isalnum_l => isalnum_l, __isalpha_l => isalpha_l, __isblank_l => isblank_l,
    __iscntrl_l => iscntrl_l, __isdigit_l => isdigit_l, __isgraph_l => isgraph_l,
    __islower_l => islower_l, __isprint_l => isprint_l, __ispunct_l => ispunct_l,
    __isspace_l => isspace_l, __isupper_l => isupper_l, __isxdigit_l => isxdigit_l,
    __tolower_l => tolower_l, __toupper_l => toupper_l,
}

// # C: int __isascii_l(int c, locale_t loc)
#[no_mangle]
pub extern "C" fn __isascii_l(c: i32, _loc: usize) -> i32 {
    ((c & !0x7f) == 0) as i32
}

// # C: int __toascii_l(int c, locale_t loc)
#[no_mangle]
pub extern "C" fn __toascii_l(c: i32, _loc: usize) -> i32 {
    c & 0x7f
}

// --- numeric _l ------------------------------------------------------------
// # C: double strtod_l(const char*, char**, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtod_l(n: *const c_char, e: *mut *mut c_char, _l: usize) -> f64 {
    // SAFETY: delegates to strtod; C-locale numeric parsing is locale-invariant.
    unsafe { strtod(n, e) }
}
// # C: float strtof_l(const char*, char**, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtof_l(n: *const c_char, e: *mut *mut c_char, _l: usize) -> f32 {
    // SAFETY: delegates to strtof under the C locale.
    unsafe { strtof(n, e) }
}
// # C: _Float32 strtof32_l(const char*, char**, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtof32_l(n: *const c_char, e: *mut *mut c_char, l: usize) -> f32 {
    // SAFETY: _Float32 == float on Oxide targets; same contract as strtof_l.
    unsafe { strtof_l(n, e, l) }
}
// # C: _Float64 strtof64_l(const char*, char**, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtof64_l(n: *const c_char, e: *mut *mut c_char, l: usize) -> f64 {
    // SAFETY: _Float64 == double on Oxide targets; same contract as strtod_l.
    unsafe { strtod_l(n, e, l) }
}
// # C: long strtol_l(const char*, char**, int base, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtol_l(n: *const c_char, e: *mut *mut c_char, b: i32, _l: usize) -> i64 {
    // SAFETY: delegates to strtol under the C locale.
    unsafe { strtol(n, e, b) }
}
// # C: unsigned long strtoul_l(const char*, char**, int base, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtoul_l(n: *const c_char, e: *mut *mut c_char, b: i32, _l: usize) -> u64 {
    // SAFETY: delegates to strtoul under the C locale.
    unsafe { strtoul(n, e, b) }
}
// # C: long long strtoll_l(const char*, char**, int base, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtoll_l(n: *const c_char, e: *mut *mut c_char, b: i32, _l: usize) -> i64 {
    // SAFETY: delegates to strtoll under the C locale.
    unsafe { strtoll(n, e, b) }
}
// # C: unsigned long long strtoull_l(const char*, char**, int base, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strtoull_l(n: *const c_char, e: *mut *mut c_char, b: i32, _l: usize) -> u64 {
    // SAFETY: delegates to strtoull under the C locale.
    unsafe { strtoull(n, e, b) }
}

// C23 entry points: modern GCC redirects strtol_l→__isoc23_strtol_l etc. when
// compiling in the default/C23 mode. Behavior matches the base for our inputs.
// # C: long __isoc23_strtol_l(const char*, char**, int, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_strtol_l(n: *const c_char, e: *mut *mut c_char, b: i32, l: usize) -> i64 {
    // SAFETY: C23 alias of strtol_l (same args/contract).
    unsafe { strtol_l(n, e, b, l) }
}
// # C: unsigned long __isoc23_strtoul_l(const char*, char**, int, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_strtoul_l(n: *const c_char, e: *mut *mut c_char, b: i32, l: usize) -> u64 {
    // SAFETY: C23 alias of strtoul_l; same NUL string + endptr + base contract.
    unsafe { strtoul_l(n, e, b, l) }
}
// # C: long long __isoc23_strtoll_l(const char*, char**, int, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_strtoll_l(n: *const c_char, e: *mut *mut c_char, b: i32, l: usize) -> i64 {
    // SAFETY: C23 alias of strtoll_l; same NUL string + endptr + base contract.
    unsafe { strtoll_l(n, e, b, l) }
}
// # C: unsigned long long __isoc23_strtoull_l(const char*, char**, int, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_strtoull_l(n: *const c_char, e: *mut *mut c_char, b: i32, l: usize) -> u64 {
    // SAFETY: C23 alias of strtoull_l; same NUL string + endptr + base contract.
    unsafe { strtoull_l(n, e, b, l) }
}

// --- string collation / case _l --------------------------------------------
// # C: int strcoll_l(const char*, const char*, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strcoll_l(a: *const c_char, b: *const c_char, _l: usize) -> i32 {
    // SAFETY: C-locale collation == byte order == strcoll.
    unsafe { strcoll(a, b) }
}
// # C: size_t strxfrm_l(char*, const char*, size_t, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strxfrm_l(d: *mut c_char, s: *const c_char, n: usize, _l: usize) -> usize {
    // SAFETY: C-locale transform == copy == strxfrm.
    unsafe { strxfrm(d, s, n) }
}
// # C: int strcasecmp_l(const char*, const char*, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strcasecmp_l(a: *const c_char, b: *const c_char, _l: usize) -> i32 {
    // SAFETY: C-locale case-fold == strcasecmp.
    unsafe { strcasecmp(a, b) }
}
// # C: int __strcasecmp_l(const char*, const char*, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __strcasecmp_l(a: *const c_char, b: *const c_char, l: usize) -> i32 {
    // SAFETY: internal alias has the same string/locale contract as strcasecmp_l.
    unsafe { strcasecmp_l(a, b, l) }
}
// # C: int strncasecmp_l(const char*, const char*, size_t, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strncasecmp_l(a: *const c_char, b: *const c_char, n: usize, _l: usize) -> i32 {
    // SAFETY: C-locale case-fold == strncasecmp.
    unsafe { strncasecmp(a, b, n) }
}
// # C: int __strncasecmp_l(const char*, const char*, size_t, locale_t)
#[no_mangle]
pub unsafe extern "C" fn __strncasecmp_l(a: *const c_char, b: *const c_char, n: usize, l: usize) -> i32 {
    // SAFETY: internal alias has the same string/locale contract as strncasecmp_l.
    unsafe { strncasecmp_l(a, b, n, l) }
}

// --- misc _l ---------------------------------------------------------------
// # C: char *strerror_l(int errnum, locale_t)
#[no_mangle]
pub unsafe extern "C" fn strerror_l(errnum: i32, _l: usize) -> *mut c_char {
    // SAFETY: messages are C-locale only; delegates to strerror (returns the
    // same buffer, retyped char* — `char` is i8 on these targets).
    unsafe { strerror(errnum) as *mut c_char }
}
// # C: char *nl_langinfo_l(nl_item item, locale_t)
#[no_mangle]
pub unsafe extern "C" fn nl_langinfo_l(item: i32, _l: usize) -> *mut c_char {
    // SAFETY: C-locale langinfo == nl_langinfo.
    unsafe { nl_langinfo(item) }
}
