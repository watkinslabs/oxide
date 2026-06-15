// <libintl.h> gettext (docs/59§6 G16). Message translation. With no message
// catalog loaded (the only state we support — .mo loading is a large separate
// effort), every lookup returns the original msgid, which is exactly what
// glibc does for untranslated strings. ngettext picks singular/plural by n.
// textdomain/bindtextdomain track the minimal domain/binding state. C ABI only.
#![cfg(feature = "freestanding")]
use crate::string::len::strlen_impl;
use core::cell::UnsafeCell;

// passthrough lookups — the msgid is returned unchanged.
// # C: char *gettext(const char *msgid)
#[no_mangle]
pub unsafe extern "C" fn gettext(msgid: *const u8) -> *mut u8 { msgid as *mut u8 }
// # C: char *dgettext(const char *domain, const char *msgid)
#[no_mangle]
pub unsafe extern "C" fn dgettext(_domain: *const u8, msgid: *const u8) -> *mut u8 { msgid as *mut u8 }
// # C: char *dcgettext(const char *domain, const char *msgid, int category)
#[no_mangle]
pub unsafe extern "C" fn dcgettext(_domain: *const u8, msgid: *const u8, _cat: i32) -> *mut u8 { msgid as *mut u8 }

// # C: char *ngettext(const char *s, const char *p, unsigned long n)
#[no_mangle]
pub unsafe extern "C" fn ngettext(s: *const u8, p: *const u8, n: u64) -> *mut u8 {
    (if n == 1 { s } else { p }) as *mut u8
}
// # C: char *dngettext(const char *domain, const char *s, const char *p, unsigned long n)
#[no_mangle]
pub unsafe extern "C" fn dngettext(_domain: *const u8, s: *const u8, p: *const u8, n: u64) -> *mut u8 {
    (if n == 1 { s } else { p }) as *mut u8
}
// # C: char *dcngettext(domain, s, p, n, category)
#[no_mangle]
pub unsafe extern "C" fn dcngettext(_domain: *const u8, s: *const u8, p: *const u8, n: u64, _cat: i32) -> *mut u8 {
    (if n == 1 { s } else { p }) as *mut u8
}

struct Dom(UnsafeCell<[u8; 256]>);
// SAFETY: process-global current text domain; single-threaded until TLS.
unsafe impl Sync for Dom {}
const fn dom_init() -> [u8; 256] {
    let mut a = [0u8; 256];
    let s = b"messages";
    let mut i = 0;
    while i < s.len() { a[i] = s[i]; i += 1; }
    a
}
static DOMAIN: Dom = Dom(UnsafeCell::new(dom_init()));

// # C: char *textdomain(const char *domainname)
#[no_mangle]
pub unsafe extern "C" fn textdomain(name: *const u8) -> *mut u8 {
    // SAFETY: name is null (query) or a NUL-terminated domain name ≤255 chars;
    // store it and return a pointer to the process-global current domain.
    unsafe {
        let d = &mut *DOMAIN.0.get();
        if !name.is_null() {
            let n = strlen_impl(name).min(255);
            core::ptr::copy_nonoverlapping(name, d.as_mut_ptr(), n);
            d[n] = 0;
        }
        d.as_mut_ptr()
    }
}
// # C: char *bindtextdomain(const char *domainname, const char *dirname)
#[no_mangle]
pub unsafe extern "C" fn bindtextdomain(_domain: *const u8, dir: *const u8) -> *mut u8 {
    // We do not load catalogs, so just echo the requested directory (glibc
    // returns the bound directory; with no binding it returns dirname).
    dir as *mut u8
}
// # C: char *bind_textdomain_codeset(const char *domainname, const char *codeset)
#[no_mangle]
pub unsafe extern "C" fn bind_textdomain_codeset(_domain: *const u8, codeset: *const u8) -> *mut u8 {
    codeset as *mut u8
}
