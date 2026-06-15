// locale/wchar — multibyte ⇄ wide conversion (docs/59§6 G16). UTF-8 codec
// (the only supported encoding; the C-locale is treated as UTF-8 like glibc's
// C.UTF-8). wchar_t = i32. Pure encode/decode hosted-tested vs Rust core's
// UTF-8; the mb*/wc* C ABI wraps it. Cross-call partial-sequence state is a
// follow-up (callers pass whole characters/buffers).
#![allow(clippy::upper_case_acronyms)]

/// Decode one UTF-8 character from the front of `b`.
/// Ok((codepoint, len)); Err(-1) invalid (EILSEQ); Err(-2) incomplete.
///
/// # C: UTF-8 decode of one scalar value
pub(crate) fn decode_utf8(b: &[u8]) -> Result<(u32, usize), i8> {
    if b.is_empty() { return Err(-2); }
    let b0 = b[0];
    if b0 < 0x80 { return Ok((b0 as u32, 1)); }
    let (len, min, mut cp) = if b0 >= 0xF0 {
        if b0 > 0xF4 { return Err(-1); }
        (4usize, 0x10000u32, (b0 & 0x07) as u32)
    } else if b0 >= 0xE0 {
        (3, 0x800, (b0 & 0x0F) as u32)
    } else if b0 >= 0xC0 {
        (2, 0x80, (b0 & 0x1F) as u32)
    } else {
        return Err(-1); // 0x80..=0xBF: lone continuation
    };
    if b.len() < len { return Err(-2); }
    for &c in &b[1..len] {
        if c & 0xC0 != 0x80 { return Err(-1); }
        cp = (cp << 6) | (c & 0x3F) as u32;
    }
    if cp < min { return Err(-1); } // overlong
    if (0xD800..=0xDFFF).contains(&cp) { return Err(-1); } // surrogate
    if cp > 0x10FFFF { return Err(-1); }
    Ok((cp, len))
}

/// Encode codepoint `cp` to UTF-8; returns (bytes, len). cp must be a valid
/// scalar value (caller-checked).
/// # C: UTF-8 encode of one scalar value
pub(crate) fn encode_utf8(cp: u32) -> ([u8; 4], usize) {
    let mut o = [0u8; 4];
    if cp < 0x80 {
        o[0] = cp as u8;
        (o, 1)
    } else if cp < 0x800 {
        o[0] = 0xC0 | (cp >> 6) as u8;
        o[1] = 0x80 | (cp & 0x3F) as u8;
        (o, 2)
    } else if cp < 0x10000 {
        o[0] = 0xE0 | (cp >> 12) as u8;
        o[1] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        o[2] = 0x80 | (cp & 0x3F) as u8;
        (o, 3)
    } else {
        o[0] = 0xF0 | (cp >> 18) as u8;
        o[1] = 0x80 | ((cp >> 12) & 0x3F) as u8;
        o[2] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        o[3] = 0x80 | (cp & 0x3F) as u8;
        (o, 4)
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::internal::errno;
    use crate::string::len::strlen_impl;

    const EILSEQ: i32 = 84;

    #[repr(C)]
    pub struct mbstate_t {
        __count: i32,
        __value: u32,
    }
    const _: () = assert!(core::mem::size_of::<mbstate_t>() == 8);

    // # C: size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn mbrtowc(pwc: *mut i32, s: *const u8, n: usize, _ps: *mut mbstate_t) -> usize {
        // SAFETY: s null (state reset → 0) or readable for `n` bytes; pwc null
        // or writable. Returns byte count, 0 for NUL, (size_t)-1 EILSEQ,
        // (size_t)-2 incomplete.
        unsafe {
            if s.is_null() { return 0; }
            let b = core::slice::from_raw_parts(s, n);
            match decode_utf8(b) {
                Ok((cp, len)) => {
                    if !pwc.is_null() { *pwc = cp as i32; }
                    if cp == 0 { 0 } else { len }
                }
                Err(-2) => usize::MAX - 1, // (size_t)-2
                _ => { errno::set(EILSEQ); usize::MAX } // (size_t)-1
            }
        }
    }

    // # C: int mbtowc(wchar_t *pwc, const char *s, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn mbtowc(pwc: *mut i32, s: *const u8, n: usize) -> i32 {
        // SAFETY: s null (→0) or readable for n; pwc null or writable.
        unsafe {
            if s.is_null() { return 0; }
            let b = core::slice::from_raw_parts(s, n);
            match decode_utf8(b) {
                Ok((cp, len)) => {
                    if !pwc.is_null() { *pwc = cp as i32; }
                    if cp == 0 { 0 } else { len as i32 }
                }
                _ => { errno::set(EILSEQ); -1 }
            }
        }
    }

    // # C: int mblen(const char *s, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn mblen(s: *const u8, n: usize) -> i32 {
        // SAFETY: s null (→0) or readable for n bytes.
        unsafe {
            if s.is_null() { return 0; }
            let b = core::slice::from_raw_parts(s, n);
            match decode_utf8(b) { Ok((cp, len)) => if cp == 0 { 0 } else { len as i32 }, _ => { errno::set(EILSEQ); -1 } }
        }
    }

    // # C: size_t mbrlen(const char *s, size_t n, mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn mbrlen(s: *const u8, n: usize, ps: *mut mbstate_t) -> usize {
        // SAFETY: forwards to mbrtowc with a null wc out-param.
        unsafe { mbrtowc(core::ptr::null_mut(), s, n, ps) }
    }

    // # C: size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn wcrtomb(s: *mut u8, wc: i32, _ps: *mut mbstate_t) -> usize {
        // SAFETY: s null (→1, reset) or writable for up to 4 bytes.
        unsafe {
            if s.is_null() { return 1; }
            let cp = wc as u32;
            if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) { errno::set(EILSEQ); return usize::MAX; }
            let (o, len) = encode_utf8(cp);
            core::ptr::copy_nonoverlapping(o.as_ptr(), s, len);
            len
        }
    }

    // # C: int wctomb(char *s, wchar_t wc)
    #[no_mangle]
    pub unsafe extern "C" fn wctomb(s: *mut u8, wc: i32) -> i32 {
        // SAFETY: s null (→0) or writable for up to 4 bytes.
        unsafe {
            if s.is_null() { return 0; }
            let r = wcrtomb(s, wc, core::ptr::null_mut());
            if r == usize::MAX { -1 } else { r as i32 }
        }
    }

    // # C: size_t mbstowcs(wchar_t *dst, const char *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn mbstowcs(dst: *mut i32, src: *const u8, n: usize) -> usize {
        // SAFETY: src is a NUL-terminated string; dst null (count only) or
        // writable for n wchars.
        unsafe {
            let s = core::slice::from_raw_parts(src, strlen_impl(src) + 1); // include NUL
            let mut i = 0; // byte cursor
            let mut w = 0; // wchar count
            loop {
                if !dst.is_null() && w >= n { return w; }
                match decode_utf8(&s[i..]) {
                    Ok((cp, len)) => {
                        if !dst.is_null() { *dst.add(w) = cp as i32; }
                        if cp == 0 { return w; } // don't count the terminator
                        i += len;
                        w += 1;
                    }
                    _ => { errno::set(EILSEQ); return usize::MAX; }
                }
            }
        }
    }

    // # C: size_t wcstombs(char *dst, const wchar_t *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn wcstombs(dst: *mut u8, src: *const i32, n: usize) -> usize {
        // SAFETY: src is a NUL-terminated wide string; dst null (count only)
        // or writable for n bytes.
        unsafe {
            let mut written = 0usize;
            let mut k = 0usize;
            loop {
                let wc = *src.add(k);
                if wc == 0 { return written; }
                let cp = wc as u32;
                if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) { errno::set(EILSEQ); return usize::MAX; }
                let (o, len) = encode_utf8(cp);
                if !dst.is_null() {
                    if written + len > n { return written; }
                    core::ptr::copy_nonoverlapping(o.as_ptr(), dst.add(written), len);
                }
                written += len;
                k += 1;
            }
        }
    }

    // # C: size_t mbsrtowcs(wchar_t *dst, const char **src, size_t n, mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn mbsrtowcs(dst: *mut i32, src: *mut *const u8, n: usize, _ps: *mut mbstate_t) -> usize {
        // SAFETY: *src is a NUL-terminated string; dst null (count only) or
        // writable for n wchars. On a non-null dst, *src is advanced past the
        // bytes consumed (to NULL after a complete copy), per the C contract.
        unsafe {
            let mut p = *src;
            let mut w = 0usize;
            loop {
                if !dst.is_null() && w >= n { *src = p; return w; }
                let b = core::slice::from_raw_parts(p, strlen_impl(p) + 1);
                match decode_utf8(b) {
                    Ok((cp, len)) => {
                        if !dst.is_null() { *dst.add(w) = cp as i32; }
                        if cp == 0 { if !dst.is_null() { *src = core::ptr::null(); } return w; }
                        p = p.add(len);
                        w += 1;
                    }
                    _ => { if !dst.is_null() { *src = p; } errno::set(EILSEQ); return usize::MAX; }
                }
            }
        }
    }

    // # C: size_t wcsrtombs(char *dst, const wchar_t **src, size_t n, mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn wcsrtombs(dst: *mut u8, src: *mut *const i32, n: usize, _ps: *mut mbstate_t) -> usize {
        // SAFETY: *src is a NUL-terminated wide string; dst null (count only)
        // or writable for n bytes. On a non-null dst, *src is advanced past the
        // wchars consumed (to NULL after a complete copy).
        unsafe {
            let mut p = *src;
            let mut written = 0usize;
            loop {
                let wc = *p;
                if wc == 0 { if !dst.is_null() { *src = core::ptr::null(); } return written; }
                let cp = wc as u32;
                if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) { if !dst.is_null() { *src = p; } errno::set(EILSEQ); return usize::MAX; }
                let (o, len) = encode_utf8(cp);
                if !dst.is_null() {
                    if written + len > n { *src = p; return written; }
                    core::ptr::copy_nonoverlapping(o.as_ptr(), dst.add(written), len);
                }
                written += len;
                p = p.add(1);
            }
        }
    }

    // # C: wint_t btowc(int c)
    #[no_mangle]
    pub extern "C" fn btowc(c: i32) -> i32 {
        if (0..=0x7f).contains(&c) { c } else { -1 } // WEOF for non-ASCII single byte
    }
    // # C: int wctob(wint_t c)
    #[no_mangle]
    pub extern "C" fn wctob(c: i32) -> i32 {
        if (0..=0x7f).contains(&c) { c } else { -1 }
    }
    // # C: int mbsinit(const mbstate_t *ps)
    #[no_mangle]
    pub unsafe extern "C" fn mbsinit(ps: *const mbstate_t) -> i32 {
        // SAFETY: ps is null or a valid mbstate_t; initial iff count==0.
        unsafe { if ps.is_null() { 1 } else { (((*ps).__count) == 0) as i32 } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_matches_core(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some()); // skip surrogates
            let (bytes, len) = encode_utf8(cp);
            // matches Rust core's UTF-8 encoding
            let mut buf = [0u8; 4];
            let s = char::from_u32(cp).unwrap().encode_utf8(&mut buf);
            prop_assert_eq!(&bytes[..len], s.as_bytes());
            // decode round-trips
            prop_assert_eq!(decode_utf8(&bytes[..len]), Ok((cp, len)));
        }
    }

    #[test]
    fn known_vectors() {
        assert_eq!(decode_utf8(&[0xC3, 0xA9]), Ok((0xE9, 2))); // é
        assert_eq!(decode_utf8(&[0xE2, 0x82, 0xAC]), Ok((0x20AC, 3))); // €
        assert_eq!(decode_utf8(&[0xF0, 0x9D, 0x84, 0x9E]), Ok((0x1D11E, 4))); // 𝄞
        assert_eq!(decode_utf8(&[0x41]), Ok((0x41, 1)));
        assert_eq!(decode_utf8(&[0x00]), Ok((0, 1)));
        // rejections
        assert_eq!(decode_utf8(&[0xC0, 0x80]), Err(-1)); // overlong NUL
        assert_eq!(decode_utf8(&[0xED, 0xA0, 0x80]), Err(-1)); // surrogate
        assert_eq!(decode_utf8(&[0x80]), Err(-1)); // lone continuation
        assert_eq!(decode_utf8(&[0xE2, 0x82]), Err(-2)); // incomplete
        assert_eq!(decode_utf8(&[]), Err(-2));
    }
}
