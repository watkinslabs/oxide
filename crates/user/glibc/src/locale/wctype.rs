// locale/wctype — wide-char classification + case mapping (docs/59§6 G16c).
// wint_t = u32, wctype_t = u64 (a class bitmask), wctrans_t = our small handle.
// classify(cp) builds the class mask from Rust core's Unicode predicates (the
// C-locale ASCII rules — digit/xdigit/blank — are ASCII-exact); towupper/
// towlower are Unicode *simple* (single-char) case mapping. Pure inner fns are
// the oracle target; the isw*/tow* C ABI wraps them.

// Class bits (internal — wctype()/iswctype() agree on these; values are ours).
pub(crate) const ALPHA: u64 = 1 << 0;
pub(crate) const DIGIT: u64 = 1 << 1;
pub(crate) const ALNUM: u64 = 1 << 2;
pub(crate) const SPACE: u64 = 1 << 3;
pub(crate) const UPPER: u64 = 1 << 4;
pub(crate) const LOWER: u64 = 1 << 5;
pub(crate) const CNTRL: u64 = 1 << 6;
pub(crate) const PUNCT: u64 = 1 << 7;
pub(crate) const PRINT: u64 = 1 << 8;
pub(crate) const GRAPH: u64 = 1 << 9;
pub(crate) const XDIGIT: u64 = 1 << 10;
pub(crate) const BLANK: u64 = 1 << 11;

/// Class bitmask for codepoint `cp` (0 if not a Unicode scalar value).
/// # C: derives the iswctype() class set for a wint_t
pub(crate) fn classify(cp: u32) -> u64 {
    let c = match char::from_u32(cp) { Some(c) => c, None => return 0 };
    let ascii = cp < 0x80;
    let mut m = 0u64;
    if c.is_alphabetic() { m |= ALPHA; }
    if ascii && (cp as u8).is_ascii_digit() { m |= DIGIT; }
    if c.is_alphanumeric() { m |= ALNUM; }
    if c.is_whitespace() { m |= SPACE; }
    if c.is_uppercase() { m |= UPPER; }
    if c.is_lowercase() { m |= LOWER; }
    if c.is_control() { m |= CNTRL; }
    if ascii && (cp as u8).is_ascii_hexdigit() { m |= XDIGIT; }
    if cp == 0x20 || cp == 0x09 { m |= BLANK; }
    let print = !c.is_control(); // glibc isprint: assigned & not a control char
    if print { m |= PRINT; }
    if print && !c.is_whitespace() { m |= GRAPH; } // graph = printable non-space
    if (m & GRAPH) != 0 && (m & ALNUM) == 0 { m |= PUNCT; } // punct = graph non-alnum
    m
}

/// Unicode simple uppercase of `cp` (unchanged when no single-char mapping).
/// # C: wint_t towupper(wint_t)
pub(crate) fn towupper_cp(cp: u32) -> u32 { simple_case(cp, true) }

/// Unicode simple lowercase of `cp` (unchanged when no single-char mapping).
/// # C: wint_t towlower(wint_t)
pub(crate) fn towlower_cp(cp: u32) -> u32 { simple_case(cp, false) }

// Simple (single-char) case fold: glibc tow{upper,lower} map only when the
// result is one scalar; multi-char full mappings (ß→SS, ﬀ→FF) leave cp as-is.
fn simple_case(cp: u32, up: bool) -> u32 {
    let c = match char::from_u32(cp) { Some(c) => c, None => return cp };
    if up {
        let mut it = c.to_uppercase();
        let first = it.next().unwrap();
        if it.next().is_none() { first as u32 } else { cp }
    } else {
        let mut it = c.to_lowercase();
        let first = it.next().unwrap();
        if it.next().is_none() { first as u32 } else { cp }
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;

    macro_rules! isw { ($n:ident, $bit:expr) => {
        // # C: int $n(wint_t)
        #[no_mangle]
        pub extern "C" fn $n(c: u32) -> i32 { ((classify(c) & $bit) != 0) as i32 }
    }; }
    isw!(iswalpha, ALPHA);
    isw!(iswdigit, DIGIT);
    isw!(iswalnum, ALNUM);
    isw!(iswspace, SPACE);
    isw!(iswupper, UPPER);
    isw!(iswlower, LOWER);
    isw!(iswcntrl, CNTRL);
    isw!(iswpunct, PUNCT);
    isw!(iswprint, PRINT);
    isw!(iswgraph, GRAPH);
    isw!(iswxdigit, XDIGIT);
    isw!(iswblank, BLANK);

    // # C: wint_t towupper(wint_t)
    #[no_mangle]
    pub extern "C" fn towupper(c: u32) -> u32 { towupper_cp(c) }
    // # C: wint_t towlower(wint_t)
    #[no_mangle]
    pub extern "C" fn towlower(c: u32) -> u32 { towlower_cp(c) }

    // # C: wctype_t wctype(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn wctype(name: *const u8) -> u64 {
        // SAFETY: name is a NUL-terminated class name; read it as a byte slice
        // up to the terminator and map to the class bit (0 for unknown).
        unsafe {
            if name.is_null() { return 0; }
            let mut n = 0;
            while *name.add(n) != 0 { n += 1; }
            class_bit(core::slice::from_raw_parts(name, n))
        }
    }

    // # C: int iswctype(wint_t wc, wctype_t desc)
    #[no_mangle]
    pub extern "C" fn iswctype(wc: u32, desc: u64) -> i32 {
        ((classify(wc) & desc) != 0) as i32
    }

    // # C: wctrans_t wctrans(const char *name) — 1=toupper, 2=tolower, 0=unknown
    #[no_mangle]
    pub unsafe extern "C" fn wctrans(name: *const u8) -> isize {
        // SAFETY: name is a NUL-terminated transform name; read it as a slice
        // and map "toupper"/"tolower" to our 1/2 handle (0 for unknown).
        unsafe {
            if name.is_null() { return 0; }
            let mut n = 0;
            while *name.add(n) != 0 { n += 1; }
            match core::slice::from_raw_parts(name, n) {
                b"toupper" => 1,
                b"tolower" => 2,
                _ => 0,
            }
        }
    }

    // # C: wint_t towctrans(wint_t wc, wctrans_t desc)
    #[no_mangle]
    pub extern "C" fn towctrans(wc: u32, desc: isize) -> u32 {
        match desc { 1 => towupper_cp(wc), 2 => towlower_cp(wc), _ => wc }
    }

    fn class_bit(name: &[u8]) -> u64 {
        match name {
            b"alpha" => ALPHA, b"digit" => DIGIT, b"alnum" => ALNUM,
            b"space" => SPACE, b"upper" => UPPER, b"lower" => LOWER,
            b"cntrl" => CNTRL, b"punct" => PUNCT, b"print" => PRINT,
            b"graph" => GRAPH, b"xdigit" => XDIGIT, b"blank" => BLANK,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn classify_matches_core(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some());
            let c = char::from_u32(cp).unwrap();
            let m = classify(cp);
            // bind core predicates to locals first
            let (alpha, alnum, space) = (c.is_alphabetic(), c.is_alphanumeric(), c.is_whitespace());
            let (upper, lower, cntrl) = (c.is_uppercase(), c.is_lowercase(), c.is_control());
            prop_assert_eq!((m & ALPHA) != 0, alpha);
            prop_assert_eq!((m & ALNUM) != 0, alnum);
            prop_assert_eq!((m & SPACE) != 0, space);
            prop_assert_eq!((m & UPPER) != 0, upper);
            prop_assert_eq!((m & LOWER) != 0, lower);
            prop_assert_eq!((m & CNTRL) != 0, cntrl);
            prop_assert_eq!((m & DIGIT) != 0, c.is_ascii_digit());
            // structural invariants
            if (m & GRAPH) != 0 { prop_assert!((m & PRINT) != 0); } // graph ⊆ print
            if (m & PUNCT) != 0 { prop_assert!((m & ALNUM) == 0 && (m & GRAPH) != 0); }
        }

        #[test]
        fn case_matches_simple_core(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some());
            let c = char::from_u32(cp).unwrap();
            // simple-mapping oracle: use core's mapping iff it yields one char
            let want_up = if c.to_uppercase().count() == 1 { c.to_uppercase().next().unwrap() as u32 } else { cp };
            let want_lo = if c.to_lowercase().count() == 1 { c.to_lowercase().next().unwrap() as u32 } else { cp };
            prop_assert_eq!(towupper_cp(cp), want_up);
            prop_assert_eq!(towlower_cp(cp), want_lo);
        }
    }

    #[test]
    fn ascii_vectors() {
        assert_eq!(classify(b'A' as u32) & (ALPHA | UPPER | ALNUM | PRINT | GRAPH | XDIGIT), ALPHA | UPPER | ALNUM | PRINT | GRAPH | XDIGIT);
        assert_eq!(classify(b'z' as u32) & UPPER, 0);
        assert_ne!(classify(b'z' as u32) & (ALPHA | LOWER), 0);
        assert_ne!(classify(b'7' as u32) & (DIGIT | XDIGIT | ALNUM | PRINT | GRAPH), 0);
        assert_eq!(classify(b'7' as u32) & ALPHA, 0);
        assert_ne!(classify(b'_' as u32) & PUNCT, 0);
        assert_eq!(classify(b'_' as u32) & ALNUM, 0);
        assert_ne!(classify(b' ' as u32) & (SPACE | BLANK | PRINT), 0);
        assert_eq!(classify(b' ' as u32) & GRAPH, 0); // space is print, not graph
        assert_ne!(classify(b'\t' as u32) & (SPACE | BLANK | CNTRL), 0);
        assert_eq!(classify(b'\t' as u32) & PRINT, 0); // tab is a control char
        assert_ne!(classify(0x0a) & CNTRL, 0);
        assert_eq!(classify(b'f' as u32) & XDIGIT, XDIGIT);
        assert_eq!(classify(b'g' as u32) & XDIGIT, 0);
        // case
        assert_eq!(towupper_cp(b'a' as u32), b'A' as u32);
        assert_eq!(towlower_cp(b'A' as u32), b'a' as u32);
        assert_eq!(towupper_cp(b'5' as u32), b'5' as u32);
        assert_eq!(towupper_cp(0xDF), 0xDF); // ß has no single-char uppercase
        assert_eq!(towupper_cp(0xE9), 0xC9); // é → É
    }
}
