// Wide-character stdio (docs/59§6 G6) — <wchar.h>/<stdio.h> wide ops over the
// existing byte FILE + the crate's UTF-8 multibyte codec (locale::wchar). The
// stream byte content is UTF-8; a wide get decodes one scalar value, a wide put
// encodes one. fwide() tracks orientation in FILE._mode (C99 7.19.2). The
// _unlocked set are aliases (single-threaded). Wide formatted I/O lives in
// wide_fmt.rs (built on the narrow printf/scanf engines).
#![cfg(feature = "freestanding")]
use super::file::{get_orient, set_eof, set_orient, set_wunget, stdin_ptr, stdout_ptr, take_wunget, FILE};
use super::memstream::{stream_read, stream_write, wmem_write};
use crate::locale::wchar::{decode_utf8, encode_utf8};

// wint_t WEOF = (wint_t)-1; in our i32 ABI that is the 0xFFFFFFFF bit pattern.
pub(crate) const WEOF: i32 = -1;
const ORIENT_WIDE: i32 = 1;
const ORIENT_NARROW: i32 = -1;

// Read one UTF-8-encoded wide char from a stream. Honours any ungetwc pushback;
// reads byte-at-a-time, completing the multibyte sequence; WEOF at end/error.
pub(crate) unsafe fn getwc_raw(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream; we read at most 4 bytes to complete
    // one UTF-8 scalar value and never read past the decoded length.
    unsafe {
        set_orient(f, ORIENT_WIDE);
        if let Some(wc) = take_wunget(f) { return wc; }
        let mut buf = [0u8; 4];
        let mut have = 0usize;
        loop {
            let mut b = 0u8;
            if stream_read(f, &mut b as *mut u8, 1) != 1 { set_eof(f); return WEOF; }
            buf[have] = b;
            have += 1;
            match decode_utf8(&buf[..have]) {
                Ok((cp, _)) => return cp as i32,
                Err(-2) => { if have == 4 { return WEOF; } } // need more bytes
                _ => return WEOF, // EILSEQ
            }
        }
    }
}

// Encode one wide char to UTF-8 and write it to a stream; the wide char on
// success, WEOF on a write error or an invalid scalar value.
pub(crate) unsafe fn putwc_raw(wc: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a valid writable stream; encode_utf8 yields ≤4 bytes which
    // we hand to stream_write from the stack buffer.
    unsafe {
        set_orient(f, ORIENT_WIDE);
        let cp = wc as u32;
        if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) { return WEOF; }
        if let Some(ok) = wmem_write(f, wc) { return if ok { wc } else { WEOF }; }
        let (o, len) = encode_utf8(cp);
        if stream_write(f, o.as_ptr(), len) == len as isize { wc } else { WEOF }
    }
}

// # C: wint_t fgetwc(FILE *)
#[no_mangle]
pub unsafe extern "C" fn fgetwc(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream per the C contract.
    unsafe { getwc_raw(f) }
}
// # C: wint_t getwc(FILE *) — same as fgetwc.
#[no_mangle]
pub unsafe extern "C" fn getwc(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream; alias of fgetwc.
    unsafe { getwc_raw(f) }
}
// # C: wint_t getwchar(void)
#[no_mangle]
pub unsafe extern "C" fn getwchar() -> i32 {
    // SAFETY: reads one wide char from the stdin stream.
    unsafe { getwc_raw(stdin_ptr()) }
}

// # C: wint_t fputwc(wchar_t wc, FILE *)
#[no_mangle]
pub unsafe extern "C" fn fputwc(wc: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a valid writable stream per the C contract.
    unsafe { putwc_raw(wc, f) }
}
// # C: wint_t putwc(wchar_t wc, FILE *) — same as fputwc.
#[no_mangle]
pub unsafe extern "C" fn putwc(wc: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a valid writable stream; alias of fputwc.
    unsafe { putwc_raw(wc, f) }
}
// # C: wint_t putwchar(wchar_t wc)
#[no_mangle]
pub unsafe extern "C" fn putwchar(wc: i32) -> i32 {
    // SAFETY: writes one wide char to the stdout stream.
    unsafe { putwc_raw(wc, stdout_ptr()) }
}

// # C: wint_t ungetwc(wint_t wc, FILE *)
#[no_mangle]
pub unsafe extern "C" fn ungetwc(wc: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; stash one pushed-back wide char (no-op for
    // WEOF), and fix the stream's orientation to wide.
    unsafe {
        if wc == WEOF { return WEOF; }
        set_orient(f, ORIENT_WIDE);
        set_wunget(f, wc);
        wc
    }
}

// # C: wchar_t *fgetws(wchar_t *ws, int n, FILE *)
#[no_mangle]
pub unsafe extern "C" fn fgetws(ws: *mut i32, n: i32, f: *mut FILE) -> *mut i32 {
    // SAFETY: ws is writable for `n` wchar_t; reads up to n-1 wide chars or a
    // newline, then NUL-terminates. Null on immediate EOF/error.
    unsafe {
        if n <= 0 { return core::ptr::null_mut(); }
        let cap = (n - 1) as usize;
        let mut i = 0usize;
        while i < cap {
            let wc = getwc_raw(f);
            if wc == WEOF { break; }
            *ws.add(i) = wc;
            i += 1;
            if wc == '\n' as i32 { break; }
        }
        if i == 0 { return core::ptr::null_mut(); }
        *ws.add(i) = 0;
        ws
    }
}

// # C: int fputws(const wchar_t *ws, FILE *)
#[no_mangle]
pub unsafe extern "C" fn fputws(ws: *const i32, f: *mut FILE) -> i32 {
    // SAFETY: ws is a NUL-terminated wide string; write each wide char. Returns
    // a non-negative count on success, WEOF(-1) on a write error.
    unsafe {
        let mut i = 0usize;
        while *ws.add(i) != 0 {
            if putwc_raw(*ws.add(i), f) == WEOF { return WEOF; }
            i += 1;
        }
        i as i32
    }
}

// # C: int fwide(FILE *, int mode) — set orientation only if unset; return the
// resulting orientation (<0 narrow, 0 unset, >0 wide). C99 7.19.2.
#[no_mangle]
pub unsafe extern "C" fn fwide(f: *mut FILE, mode: i32) -> i32 {
    // SAFETY: f is a valid stream; consult/fix its orientation field.
    unsafe {
        if mode > 0 { set_orient(f, ORIENT_WIDE); }
        else if mode < 0 { set_orient(f, ORIENT_NARROW); }
        get_orient(f)
    }
}

// _unlocked set — single-threaded, so exact aliases of the locked ops.
macro_rules! walias {
    ($(#[$m:meta])* $u:ident ($($a:ident : $t:ty),*) -> $r:ty = $base:ident) => {
        $(#[$m])*
        #[no_mangle] pub unsafe extern "C" fn $u($($a: $t),*) -> $r {
            // SAFETY: single-threaded → identical to the locked $base; forwards.
            unsafe { $base($($a),*) }
        }
    };
}
walias!(/// # C: wint_t getwc_unlocked(FILE *)
        getwc_unlocked(f: *mut FILE) -> i32 = getwc);
walias!(/// # C: wint_t getwchar_unlocked(void)
        getwchar_unlocked() -> i32 = getwchar);
walias!(/// # C: wint_t fgetwc_unlocked(FILE *)
        fgetwc_unlocked(f: *mut FILE) -> i32 = fgetwc);
walias!(/// # C: wint_t fputwc_unlocked(wchar_t, FILE *)
        fputwc_unlocked(wc: i32, f: *mut FILE) -> i32 = fputwc);
walias!(/// # C: wint_t putwc_unlocked(wchar_t, FILE *)
        putwc_unlocked(wc: i32, f: *mut FILE) -> i32 = putwc);
walias!(/// # C: wint_t putwchar_unlocked(wchar_t)
        putwchar_unlocked(wc: i32) -> i32 = putwchar);
walias!(/// # C: wchar_t *fgetws_unlocked(wchar_t *, int, FILE *)
        fgetws_unlocked(ws: *mut i32, n: i32, f: *mut FILE) -> *mut i32 = fgetws);
walias!(/// # C: int fputws_unlocked(const wchar_t *, FILE *)
        fputws_unlocked(ws: *const i32, f: *mut FILE) -> i32 = fputws);
