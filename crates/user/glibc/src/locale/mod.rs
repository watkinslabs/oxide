//! locale — setlocale/localeconv/nl_langinfo (docs/59§3, §6 G16). The C /
//! C.UTF-8 / en_US.UTF-8 locales; numeric/monetary formatting via lconv.
//! Wide-char/multibyte conversion (G16b), wctype (G16c), iconv (G16d) and TZ
//! (G16e) follow. The C-locale lconv field values are pure + hosted-tested vs
//! the host's; setlocale/localeconv/nl_langinfo C ABI are freestanding.
#![allow(clippy::upper_case_acronyms)]

pub mod iconv;
pub mod wchar;
pub mod wctype;
#[cfg(feature = "freestanding")]
pub mod gettext;
#[cfg(feature = "freestanding")]
pub mod catgets;
#[cfg(feature = "freestanding")]
pub mod strfmon;
#[cfg(feature = "freestanding")]
pub mod posix_l;

pub const LC_CTYPE: i32 = 0;
pub const LC_NUMERIC: i32 = 1;
pub const LC_TIME: i32 = 2;
pub const LC_COLLATE: i32 = 3;
pub const LC_MONETARY: i32 = 4;
pub const LC_MESSAGES: i32 = 5;
pub const LC_ALL: i32 = 6;

/// C-locale lconv scalar fields (the `char`-typed members). Pure data, so it
/// can be checked against the host's localeconv() in the C locale.
pub(crate) struct CLconv {
    pub int_frac_digits: i8,
    pub frac_digits: i8,
    pub p_sign_posn: i8,
    pub n_sign_posn: i8,
}
const CHAR_MAX: i8 = 127;
pub(crate) const C_LCONV: CLconv = CLconv {
    int_frac_digits: CHAR_MAX,
    frac_digits: CHAR_MAX,
    p_sign_posn: CHAR_MAX,
    n_sign_posn: CHAR_MAX,
};

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicU8, Ordering};

    #[repr(C)]
    pub struct lconv {
        pub decimal_point: *const u8,
        pub thousands_sep: *const u8,
        pub grouping: *const u8,
        pub int_curr_symbol: *const u8,
        pub currency_symbol: *const u8,
        pub mon_decimal_point: *const u8,
        pub mon_thousands_sep: *const u8,
        pub mon_grouping: *const u8,
        pub positive_sign: *const u8,
        pub negative_sign: *const u8,
        pub int_frac_digits: i8,
        pub frac_digits: i8,
        pub p_cs_precedes: i8,
        pub p_sep_by_space: i8,
        pub n_cs_precedes: i8,
        pub n_sep_by_space: i8,
        pub p_sign_posn: i8,
        pub n_sign_posn: i8,
        pub int_p_cs_precedes: i8,
        pub int_p_sep_by_space: i8,
        pub int_n_cs_precedes: i8,
        pub int_n_sep_by_space: i8,
        pub int_p_sign_posn: i8,
        pub int_n_sign_posn: i8,
    }

    const DOT: &[u8] = b".\0";
    const EMPTY: &[u8] = b"\0";

    struct LconvCell(UnsafeCell<lconv>);
    // SAFETY: localeconv returns a pointer to this single static; the C-locale
    // contents are constant and only read by callers.
    unsafe impl Sync for LconvCell {}
    static LC: LconvCell = LconvCell(UnsafeCell::new(lconv {
        decimal_point: DOT.as_ptr(), thousands_sep: EMPTY.as_ptr(), grouping: EMPTY.as_ptr(),
        int_curr_symbol: EMPTY.as_ptr(), currency_symbol: EMPTY.as_ptr(),
        mon_decimal_point: EMPTY.as_ptr(), mon_thousands_sep: EMPTY.as_ptr(), mon_grouping: EMPTY.as_ptr(),
        positive_sign: EMPTY.as_ptr(), negative_sign: EMPTY.as_ptr(),
        int_frac_digits: CHAR_MAX, frac_digits: CHAR_MAX, p_cs_precedes: CHAR_MAX, p_sep_by_space: CHAR_MAX,
        n_cs_precedes: CHAR_MAX, n_sep_by_space: CHAR_MAX, p_sign_posn: CHAR_MAX, n_sign_posn: CHAR_MAX,
        int_p_cs_precedes: CHAR_MAX, int_p_sep_by_space: CHAR_MAX, int_n_cs_precedes: CHAR_MAX,
        int_n_sep_by_space: CHAR_MAX, int_p_sign_posn: CHAR_MAX, int_n_sign_posn: CHAR_MAX,
    }));

    // current locale name index per category (0=C, 1=C.UTF-8, 2=en_US.UTF-8)
    static CUR: [AtomicU8; 7] = [
        AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
        AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    ];
    const NAMES: [&[u8]; 3] = [b"C\0", b"C.UTF-8\0", b"en_US.UTF-8\0"];

    fn name_index(s: &[u8]) -> Option<u8> {
        match s {
            b"C" | b"POSIX" | b"" => Some(0),
            b"C.UTF-8" => Some(1),
            b"en_US.UTF-8" | b"en_US.utf8" => Some(2),
            _ => None,
        }
    }

    // # C: char *setlocale(int category, const char *locale)
    #[no_mangle]
    pub unsafe extern "C" fn setlocale(category: i32, locale: *const u8) -> *const u8 {
        // SAFETY: locale is null (query) or a NUL-terminated locale name.
        unsafe {
            if !(0..=LC_ALL).contains(&category) { return core::ptr::null(); }
            if locale.is_null() {
                let cat = if category == LC_ALL { LC_CTYPE } else { category };
                let idx = CUR[cat as usize].load(Ordering::Acquire) as usize;
                return NAMES[idx].as_ptr();
            }
            let mut n = 0;
            while *locale.add(n) != 0 { n += 1; }
            let s = core::slice::from_raw_parts(locale, n);
            match name_index(s) {
                Some(idx) => {
                    if category == LC_ALL {
                        for c in &CUR { c.store(idx, Ordering::Release); }
                    } else {
                        CUR[category as usize].store(idx, Ordering::Release);
                    }
                    NAMES[idx as usize].as_ptr()
                }
                None => core::ptr::null(),
            }
        }
    }

    // # C: size_t __ctype_get_mb_cur_max(void) — backs the MB_CUR_MAX macro.
    // C/POSIX LC_CTYPE → 1 byte; the UTF-8 locales (C.UTF-8 / en_US.UTF-8) → 6
    // (the max UTF-8 sequence glibc reports).
    #[no_mangle]
    pub extern "C" fn __ctype_get_mb_cur_max() -> usize {
        if CUR[LC_CTYPE as usize].load(Ordering::Acquire) == 0 { 1 } else { 6 }
    }

    // # C: struct lconv *localeconv(void)
    #[no_mangle]
    pub extern "C" fn localeconv() -> *mut lconv {
        // returns the single static C-locale lconv (constant contents);
        // UnsafeCell::get is a safe pointer fetch (no deref here).
        LC.0.get()
    }

    // glibc nl_item codes (category<<16 | index) for the stable subset.
    const CODESET: i32 = 14; // _NL_CTYPE_CODESET_NAME
    const RADIXCHAR: i32 = 0x10000; // LC_NUMERIC,0
    const THOUSEP: i32 = 0x10001;
    const D_T_FMT: i32 = 0x20000 + 40;
    const D_FMT: i32 = 0x20000 + 41;
    const T_FMT: i32 = 0x20000 + 42;
    const AM_STR: i32 = 0x20000 + 38;
    const PM_STR: i32 = 0x20000 + 39;
    const DAY_1: i32 = 0x20000 + 7;
    const MON_1: i32 = 0x20000 + 26;

    // # C: char *nl_langinfo(nl_item item) — C-locale strings
    #[no_mangle]
    pub extern "C" fn nl_langinfo(item: i32) -> *const u8 {
        let days: [&[u8]; 7] = [b"Sunday\0", b"Monday\0", b"Tuesday\0", b"Wednesday\0", b"Thursday\0", b"Friday\0", b"Saturday\0"];
        let mons: [&[u8]; 12] = [b"January\0", b"February\0", b"March\0", b"April\0", b"May\0", b"June\0", b"July\0", b"August\0", b"September\0", b"October\0", b"November\0", b"December\0"];
        let s: &[u8] = match item {
            CODESET => b"UTF-8\0",
            RADIXCHAR => b".\0",
            THOUSEP => b"\0",
            D_T_FMT => b"%a %b %e %H:%M:%S %Y\0",
            D_FMT => b"%m/%d/%y\0",
            T_FMT => b"%H:%M:%S\0",
            AM_STR => b"AM\0",
            PM_STR => b"PM\0",
            i if (DAY_1..DAY_1 + 7).contains(&i) => days[(i - DAY_1) as usize],
            i if (MON_1..MON_1 + 12).contains(&i) => mons[(i - MON_1) as usize],
            _ => b"\0",
        };
        s.as_ptr()
    }

    // # C: int rpmatch(const char *response) — 1 = yes, 0 = no, -1 = no match.
    // C/POSIX locale: YESEXPR ^[+1yY], NOEXPR ^[-0nN] (the regexes glibc ships
    // for the C locale). Only the first character is inspected.
    #[no_mangle]
    pub unsafe extern "C" fn rpmatch(response: *const u8) -> i32 {
        // SAFETY: response is null or a NUL-terminated string; inspect its first
        // byte against the C-locale yes/no expressions.
        unsafe {
            if response.is_null() { return -1; }
            match *response {
                b'y' | b'Y' => 1,
                b'n' | b'N' => 0,
                _ => -1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_lconv_matches_host() {
        // SAFETY: host localeconv() in the default C locale; read its fields.
        let lc = unsafe { &*libc::localeconv() };
        assert_eq!(C_LCONV.int_frac_digits, lc.int_frac_digits);
        assert_eq!(C_LCONV.frac_digits, lc.frac_digits);
        assert_eq!(C_LCONV.p_sign_posn, lc.p_sign_posn);
        assert_eq!(C_LCONV.n_sign_posn, lc.n_sign_posn);
        // SAFETY: decimal_point is a NUL-terminated C string in the C locale.
        let dp = unsafe { core::ffi::CStr::from_ptr(lc.decimal_point) };
        assert_eq!(dp.to_str().unwrap(), ".");
    }
}
