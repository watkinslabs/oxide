// strptime (docs/59§6 G10) — inverse of strftime. Parses a NUL-terminated
// buffer per a NUL-terminated format into a struct tm (C/POSIX locale), and
// wcsftime (wide strftime, transcoded to the narrow strftime engine). Pure
// parser hosted-tested vs host strptime; the C ABI is freestanding-gated.
use super::tm::tm;

const DAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const ABDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MON: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const ABMON: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

fn lc(b: u8) -> u8 { if b.is_ascii_uppercase() { b + 32 } else { b } }
fn ci_eq(a: &[u8], b: &[u8]) -> bool { a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| lc(x) == lc(y)) }

struct P<'a> { s: &'a [u8], i: usize }
impl<'a> P<'a> {
    fn skip_ws(&mut self) { while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() { self.i += 1; } }
    // Read up to `max` decimal digits; None if no digit present.
    fn num(&mut self, max: usize) -> Option<i64> {
        self.skip_ws();
        let mut neg = false;
        if self.i < self.s.len() && (self.s[self.i] == b'+' || self.s[self.i] == b'-') { neg = self.s[self.i] == b'-'; self.i += 1; }
        let start = self.i;
        let mut v: i64 = 0;
        while self.i < self.s.len() && self.i - start < max && self.s[self.i].is_ascii_digit() {
            v = v * 10 + (self.s[self.i] - b'0') as i64; self.i += 1;
        }
        if self.i == start { None } else { Some(if neg { -v } else { v }) }
    }
    // Match the longest name from `names` case-insensitively, return its index.
    fn name(&mut self, names: &[&[u8]]) -> Option<usize> {
        self.skip_ws();
        let mut best: Option<(usize, usize)> = None; // (idx, len)
        for (k, &n) in names.iter().enumerate() {
            if self.i + n.len() <= self.s.len() && ci_eq(&self.s[self.i..self.i + n.len()], n)
                && best.map(|(_, l)| n.len() > l).unwrap_or(true) { best = Some((k, n.len())); }
        }
        best.map(|(k, l)| { self.i += l; k })
    }
    fn lit(&mut self, c: u8) -> bool {
        if c.is_ascii_whitespace() { self.skip_ws(); return true; }
        if self.i < self.s.len() && self.s[self.i] == c { self.i += 1; true } else { false }
    }
}

/// Parse `buf` per `fmt` into `t`. Returns Some(bytes consumed) or None on
/// mismatch. # C: strptime core
pub(crate) fn parse(buf: &[u8], fmt: &[u8], t: &mut tm) -> Option<usize> {
    let mut p = P { s: buf, i: 0 };
    let mut f = 0;
    let mut century: Option<i64> = None;
    let mut yy: Option<i64> = None;
    while f < fmt.len() {
        let c = fmt[f];
        if c.is_ascii_whitespace() { p.skip_ws(); f += 1; continue; }
        if c != b'%' { if !p.lit(c) { return None; } f += 1; continue; }
        f += 1;
        if f >= fmt.len() { break; }
        let conv = fmt[f]; f += 1;
        match conv {
            b'Y' => { let v = p.num(4)?; t.tm_year = (v - 1900) as i32; }
            b'y' => { yy = Some(p.num(2)?); }
            b'C' => { century = Some(p.num(2)?); }
            b'm' => { t.tm_mon = (p.num(2)? - 1) as i32; }
            b'd' | b'e' => { t.tm_mday = p.num(2)? as i32; }
            b'H' => { t.tm_hour = p.num(2)? as i32; }
            b'I' => { t.tm_hour = p.num(2)? as i32; }
            b'M' => { t.tm_min = p.num(2)? as i32; }
            b'S' => { t.tm_sec = p.num(2)? as i32; }
            b'j' => { t.tm_yday = (p.num(3)? - 1) as i32; }
            b'p' | b'P' => {
                let idx = p.name(&[b"AM", b"PM"])?; // 0=AM 1=PM
                if idx == 1 { if t.tm_hour < 12 { t.tm_hour += 12; } }
                else if t.tm_hour == 12 { t.tm_hour = 0; }
            }
            b'a' | b'A' => { t.tm_wday = p.name(&DAY).or_else(|| p.name(&ABDAY))? as i32; }
            b'b' | b'B' | b'h' => { t.tm_mon = p.name(&MON).or_else(|| p.name(&ABMON))? as i32; }
            b'w' => { t.tm_wday = p.num(1)? as i32; }
            b'u' => { let v = p.num(1)?; t.tm_wday = (v % 7) as i32; }
            b'n' | b't' => { p.skip_ws(); }
            b'F' => { parse_into(&mut p, b"%Y-%m-%d", t, &mut century, &mut yy)?; }
            b'T' | b'X' => { parse_into(&mut p, b"%H:%M:%S", t, &mut century, &mut yy)?; }
            b'R' => { parse_into(&mut p, b"%H:%M", t, &mut century, &mut yy)?; }
            b'D' | b'x' => { parse_into(&mut p, b"%m/%d/%y", t, &mut century, &mut yy)?; }
            b'%' => { if !p.lit(b'%') { return None; } }
            _ => return None,
        }
    }
    apply_year(t, century, yy);
    Some(p.i)
}

// AM/PM and nested-format helpers operate on the same parser/cursor.
fn parse_into(p: &mut P, fmt: &[u8], t: &mut tm, century: &mut Option<i64>, yy: &mut Option<i64>) -> Option<()> {
    let mut f = 0;
    while f < fmt.len() {
        let c = fmt[f];
        if c != b'%' { if !p.lit(c) { return None; } f += 1; continue; }
        f += 1; let conv = fmt[f]; f += 1;
        match conv {
            b'Y' => { let v = p.num(4)?; t.tm_year = (v - 1900) as i32; }
            b'y' => { *yy = Some(p.num(2)?); }
            b'm' => { t.tm_mon = (p.num(2)? - 1) as i32; }
            b'd' | b'e' => { t.tm_mday = p.num(2)? as i32; }
            b'H' => { t.tm_hour = p.num(2)? as i32; }
            b'M' => { t.tm_min = p.num(2)? as i32; }
            b'S' => { t.tm_sec = p.num(2)? as i32; }
            _ => return None,
        }
        let _ = century;
    }
    Some(())
}

fn apply_year(t: &mut tm, century: Option<i64>, yy: Option<i64>) {
    match (century, yy) {
        (Some(c), Some(y)) => t.tm_year = (c * 100 + y - 1900) as i32,
        (Some(c), None) => t.tm_year = (c * 100 - 1900) as i32,
        (None, Some(y)) => { let full = if y <= 68 { 2000 + y } else { 1900 + y }; t.tm_year = (full - 1900) as i32; }
        (None, None) => {}
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::string::len::strlen_impl;

    // # C: char *strptime(const char *s, const char *format, struct tm *tm)
    #[no_mangle]
    pub unsafe extern "C" fn strptime(s: *const u8, format: *const u8, t: *mut tm) -> *mut u8 {
        // SAFETY: s and format are NUL-terminated; t is a valid struct tm. Returns
        // a pointer to the first unparsed input byte, or NULL on mismatch.
        unsafe {
            let buf = core::slice::from_raw_parts(s, strlen_impl(s));
            let fmt = core::slice::from_raw_parts(format, strlen_impl(format));
            match parse(buf, fmt, &mut *t) { Some(n) => s.add(n) as *mut u8, None => core::ptr::null_mut() }
        }
    }

    // # C: char *strptime_l(const char *s, const char *format, struct tm *tm, locale_t loc)
    #[no_mangle]
    pub unsafe extern "C" fn strptime_l(s: *const u8, format: *const u8, t: *mut tm, _loc: usize) -> *mut u8 {
        // SAFETY: delegates to strptime; only C-equivalent locales exist, so
        // locale_t does not affect parsing.
        unsafe { strptime(s, format, t) }
    }

    // # C: size_t wcsftime(wchar_t *s, size_t maxsize, const wchar_t *format, const struct tm *tm)
    #[no_mangle]
    pub unsafe extern "C" fn wcsftime(s: *mut i32, maxsize: usize, format: *const i32, t: *const tm) -> usize {
        // SAFETY: s writable for `maxsize` wchars; format a 0-terminated wide
        // string (C-locale conversions are all ASCII, so we transcode the format
        // to narrow bytes, run the narrow strftime engine, then widen the result).
        unsafe {
            if maxsize == 0 { return 0; }
            // narrow the format (ASCII; non-ASCII wchars copied as their low byte,
            // which the C-locale format never contains beyond the literals).
            let mut nfmt = [0u8; 512];
            let mut k = 0usize;
            while k + 1 < nfmt.len() { let w = *format.add(k); if w == 0 { break; } nfmt[k] = w as u8; k += 1; }
            let mut nout = [0u8; 1024];
            let cap = if maxsize - 1 < nout.len() { maxsize - 1 } else { nout.len() };
            match crate::time::strftime::format(&mut nout[..cap], &nfmt[..k], &*t) {
                Some(n) => {
                    for j in 0..n { *s.add(j) = nout[j] as i32; }
                    *s.add(n) = 0;
                    n
                }
                None => 0,
            }
        }
    }

    // # C: size_t wcsftime_l(wchar_t *s, size_t max, const wchar_t *fmt, const struct tm *tm, locale_t loc)
    #[no_mangle]
    pub unsafe extern "C" fn wcsftime_l(s: *mut i32, maxsize: usize, format: *const i32, t: *const tm, _loc: usize) -> usize {
        // SAFETY: delegates to wcsftime; only C-equivalent locales exist, so
        // locale_t does not alter wide time formatting.
        unsafe { wcsftime(s, maxsize, format, t) }
    }
    // # C: size_t __wcsftime_l(wchar_t *s, size_t max, const wchar_t *fmt, const struct tm *tm, locale_t loc)
    #[no_mangle]
    pub unsafe extern "C" fn __wcsftime_l(s: *mut i32, maxsize: usize, format: *const i32, t: *const tm, loc: usize) -> usize {
        // SAFETY: internal alias has the same output buffer and tm pointer contract as wcsftime_l.
        unsafe { wcsftime_l(s, maxsize, format, t, loc) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn blank() -> tm { tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() } }
    #[test]
    fn parse_datetime() {
        let mut t = blank();
        let n = parse(b"2026-06-15 13:45", b"%Y-%m-%d %H:%M", &mut t).unwrap();
        assert_eq!(n, 16);
        assert_eq!(t.tm_year, 126);
        assert_eq!(t.tm_mon, 5);
        assert_eq!(t.tm_mday, 15);
        assert_eq!(t.tm_hour, 13);
        assert_eq!(t.tm_min, 45);
    }
    #[test]
    fn parse_names_and_y() {
        let mut t = blank();
        parse(b"Jun 70", b"%b %y", &mut t).unwrap();
        assert_eq!(t.tm_mon, 5);
        assert_eq!(t.tm_year, 70); // 1970
    }
}
