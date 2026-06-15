// strfmon / strfmon_l — <monetary.h> monetary formatting (docs/59§6 G16).
// C-locale only currency formatting: empty currency symbol, no grouping,
// '.' decimal, '-' negative sign (or '(' '...' ')' with the `(` flag). The
// digit production matches glibc's %f (round-half-to-even on the exact binary
// value, via core::fmt's "{:.*}"). Conversion syntax (SUSv4 strfmon):
//   %[flags][field width][#left-prec][.right-prec][conversion]
// flags: '=f' fill char, '^' no grouping, '+'/'(' sign style, '!' no symbol,
//        '-' left-justify. Conversions: 'n' national, 'i' international, '%'.
#![cfg(feature = "freestanding")]

use core::ffi::{c_void, VaList};

// One parsed conversion's options.
struct Conv {
    fill: u8,        // '=f' fill char (default space)
    no_group: bool,  // '^'
    left_just: bool, // '-'
    use_plus: bool,  // '+' (force +/-)
    use_paren: bool, // '(' (parenthesize negatives)
    no_symbol: bool, // '!'
    width: usize,    // field width
    left_prec: Option<usize>,  // '#n'
    right_prec: Option<usize>, // '.n'
}

// Render magnitude (>=0) to `frac` fixed decimals into `dst`; returns length.
// Uses core::fmt, which rounds identically to glibc's %f for these values.
fn render_fixed(dst: &mut [u8], mag: f64, frac: usize) -> usize {
    use core::fmt::Write as _;
    struct W<'a> { b: &'a mut [u8], n: usize }
    impl core::fmt::Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &c in s.as_bytes() { if self.n < self.b.len() { self.b[self.n] = c; self.n += 1; } }
            Ok(())
        }
    }
    let mut w = W { b: dst, n: 0 };
    let _ = write!(w, "{:.*}", frac, mag);
    w.n
}

// Format one value into `out` per the parsed conversion. neg = value < 0.
fn format_value(out: &mut alloc::vec::Vec<u8>, c: &Conv, mag: f64, neg: bool) {
    let frac = c.right_prec.unwrap_or(2); // C-locale frac_digits fallback = 2
    let mut digits = [0u8; 64];
    let dn = render_fixed(&mut digits, mag, frac);
    // split integer / fractional at the '.'
    let dot = digits[..dn].iter().position(|&b| b == b'.').unwrap_or(dn);
    let int_part = &digits[..dot];
    let frac_part = &digits[dot..dn]; // includes the '.'

    // sign handling (C locale: '-' prefix, or parens with the `(` flag).
    let plus_sign: &[u8] = if c.use_plus { b"+" } else { b"" };
    let (pre_sign, post_sign): (&[u8], &[u8]) = if neg {
        if c.use_paren { (b"(", b")") } else { (b"-", b"") }
    } else { (plus_sign, b"") };

    // build the value field (without field-width padding).
    let mut v = alloc::vec::Vec::<u8>::new();
    if let Some(lp) = c.left_prec {
        // left-precision: one reserved sign slot, then fill the integer part
        // up to `lp` digits with the fill char, then digits + frac.
        // parens replace the sign slot; '-'/'+'/space otherwise.
        let slot: &[u8] = if neg && c.use_paren { b"(" }
            else if neg { b"-" } else if c.use_plus { b"+" } else { b" " };
        v.extend_from_slice(slot);
        let pad = lp.saturating_sub(int_part.len());
        for _ in 0..pad { v.push(c.fill); }
        v.extend_from_slice(int_part);
        v.extend_from_slice(frac_part);
        if neg && c.use_paren { v.push(b')'); }
    } else {
        v.extend_from_slice(pre_sign);
        v.extend_from_slice(int_part);
        v.extend_from_slice(frac_part);
        v.extend_from_slice(post_sign);
    }

    // field-width padding (space-fill; left- or right-justify).
    let pad = c.width.saturating_sub(v.len());
    if c.left_just { out.extend_from_slice(&v); for _ in 0..pad { out.push(b' '); } }
    else { for _ in 0..pad { out.push(b' '); } out.extend_from_slice(&v); }
}

// Core engine: walk `fmt`, copy literals, format each `%...` conversion.
// Returns total bytes that would be written (excluding the NUL), or usize::MAX
// to signal a parse error (-> caller returns -1 per strfmon(3)).
unsafe fn run(fmt: *const u8, ap: &mut VaList) -> alloc::vec::Vec<u8> {
    // SAFETY: fmt is a NUL-terminated format string; ap supplies one double
    // per non-'%%' conversion, matching the C strfmon contract.
    unsafe {
        let mut out = alloc::vec::Vec::<u8>::new();
        let mut i = 0usize;
        loop {
            let ch = *fmt.add(i);
            if ch == 0 { break; }
            if ch != b'%' { out.push(ch); i += 1; continue; }
            i += 1;
            if *fmt.add(i) == b'%' { out.push(b'%'); i += 1; continue; }
            let mut c = Conv { fill: b' ', no_group: false, left_just: false,
                use_plus: false, use_paren: false, no_symbol: false,
                width: 0, left_prec: None, right_prec: None };
            // flags (any order, repeatable)
            loop {
                match *fmt.add(i) {
                    b'=' => { i += 1; c.fill = *fmt.add(i); i += 1; }
                    b'^' => { c.no_group = true; i += 1; }
                    b'+' => { c.use_plus = true; i += 1; }
                    b'(' => { c.use_paren = true; i += 1; }
                    b'!' => { c.no_symbol = true; i += 1; }
                    b'-' => { c.left_just = true; i += 1; }
                    _ => break,
                }
            }
            // field width
            while (*fmt.add(i)).is_ascii_digit() { c.width = c.width * 10 + (*fmt.add(i) - b'0') as usize; i += 1; }
            // #left-precision
            if *fmt.add(i) == b'#' {
                i += 1; let mut lp = 0usize;
                while (*fmt.add(i)).is_ascii_digit() { lp = lp * 10 + (*fmt.add(i) - b'0') as usize; i += 1; }
                c.left_prec = Some(lp);
            }
            // .right-precision
            if *fmt.add(i) == b'.' {
                i += 1; let mut rp = 0usize;
                while (*fmt.add(i)).is_ascii_digit() { rp = rp * 10 + (*fmt.add(i) - b'0') as usize; i += 1; }
                c.right_prec = Some(rp);
            }
            // conversion char
            let conv = *fmt.add(i); i += 1;
            let _ = c.no_group; let _ = c.no_symbol; // C locale: no grouping/symbol
            match conv {
                b'n' | b'i' => {
                    let val: f64 = ap.next_arg();
                    let neg = val.is_sign_negative() && val != 0.0;
                    format_value(&mut out, &c, if neg { -val } else { val }, neg);
                }
                _ => { return alloc::vec![0xFFu8]; } // sentinel: parse error
            }
        }
        out
    }
}

// Copy `src` into the `max`-byte buffer `s` with a NUL terminator. Returns
// the count (excluding NUL) on success, or -1 if it does not fit.
unsafe fn emit(s: *mut u8, max: usize, src: &[u8]) -> isize {
    // SAFETY: s points to a writable buffer of `max` bytes per strfmon(3).
    unsafe {
        if src == [0xFFu8] { return -1; } // parse-error sentinel from run()
        if src.len() + 1 > max { return -1; } // E2BIG: result + NUL exceeds buf
        for (k, &b) in src.iter().enumerate() { *s.add(k) = b; }
        *s.add(src.len()) = 0;
        src.len() as isize
    }
}

// # C: ssize_t strfmon(char *s, size_t max, const char *format, ...)
#[no_mangle]
pub unsafe extern "C" fn strfmon(s: *mut u8, max: usize, format: *const u8, mut ap: ...) -> isize {
    // SAFETY: s/max describe a writable buffer; format is NUL-terminated; the
    // varargs are doubles, one per conversion, per the C strfmon contract.
    unsafe { let out = run(format, &mut ap); emit(s, max, &out) }
}

// # C: ssize_t strfmon_l(char *s, size_t max, locale_t loc, const char *fmt,...)
// In the C locale (the only monetary locale we carry) `loc` is ignored.
#[no_mangle]
pub unsafe extern "C" fn strfmon_l(s: *mut u8, max: usize, _loc: *mut c_void, format: *const u8, mut ap: ...) -> isize {
    // SAFETY: same contract as strfmon; loc selects the C locale formatting.
    unsafe { let out = run(format, &mut ap); emit(s, max, &out) }
}
