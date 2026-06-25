// strftime (docs/59§6 G10), C/POSIX locale. Formats a struct tm into a
// bounded buffer; returns bytes written (excl NUL) or 0 if it would
// overflow. Common conversions; %c/%x/%X expand to the C-locale forms.
// Differentially tested vs host strftime. strptime is a follow-up.
use super::tm::tm;

const DAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const ABDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MON: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const ABMON: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

struct W<'a> { buf: &'a mut [u8], pos: usize, ovf: bool }
impl W<'_> {
    fn put(&mut self, b: u8) { if self.pos < self.buf.len() { self.buf[self.pos] = b; self.pos += 1; } else { self.ovf = true; } }
    fn puts(&mut self, s: &[u8]) { for &b in s { self.put(b); } }
    // signed decimal, optional zero/space pad to `width`
    fn num(&mut self, v: i64, width: usize, zero: bool) {
        let mut tmp = [0u8; 24];
        let neg = v < 0;
        let mut n = v.unsigned_abs();
        let mut k = 0;
        if n == 0 { tmp[0] = b'0'; k = 1; } else { while n > 0 { tmp[k] = b'0' + (n % 10) as u8; n /= 10; k += 1; } }
        let digits = k + neg as usize;
        let pad = width.saturating_sub(digits);
        if neg { self.put(b'-'); }
        for _ in 0..pad { self.put(if zero { b'0' } else { b' ' }); }
        while k > 0 { k -= 1; self.put(tmp[k]); }
    }
}

fn year(t: &tm) -> i64 { t.tm_year as i64 + 1900 }

// ISO 8601 week-based (year, week): week 1 contains the year's first Thursday,
// weeks start Monday. Used by %V/%G/%g.
fn iso_week(t: &tm) -> (i64, i64) {
    let wd = { let w = t.tm_wday.rem_euclid(7) as i64; if w == 0 { 7 } else { w } }; // 1=Mon..7=Sun
    let yday1 = t.tm_yday as i64 + 1; // 1-based day of year
    let y = year(t);
    let p = |y: i64| (y + y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400)).rem_euclid(7);
    let weeks = |y: i64| if p(y) == 4 || p(y - 1) == 3 { 53 } else { 52 };
    let week = (yday1 - wd + 10).div_euclid(7);
    if week < 1 { (y - 1, weeks(y - 1)) }
    else if week > weeks(y) { (y + 1, 1) }
    else { (y, week) }
}

/// # C: write tm per fmt into buf; None on overflow
pub(crate) fn format(buf: &mut [u8], fmt: &[u8], t: &tm) -> Option<usize> {
    let mut w = W { buf, pos: 0, ovf: false };
    emit(&mut w, fmt, t);
    if w.ovf { None } else { Some(w.pos) }
}

fn emit(w: &mut W, fmt: &[u8], t: &tm) {
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' { w.put(c); i += 1; continue; }
        i += 1;
        if i >= fmt.len() { w.put(b'%'); break; }
        let conv = fmt[i];
        i += 1;
        let wd = (t.tm_wday.rem_euclid(7)) as usize;
        let mo = (t.tm_mon.rem_euclid(12)) as usize;
        match conv {
            b'Y' => w.num(year(t), 0, false),
            b'y' => w.num(year(t).rem_euclid(100), 2, true),
            b'C' => w.num(year(t).div_euclid(100), 2, true),
            b'm' => w.num(t.tm_mon as i64 + 1, 2, true),
            b'd' => w.num(t.tm_mday as i64, 2, true),
            b'e' => w.num(t.tm_mday as i64, 2, false),
            b'H' => w.num(t.tm_hour as i64, 2, true),
            b'I' => { let h = t.tm_hour % 12; w.num(if h == 0 { 12 } else { h } as i64, 2, true); }
            b'M' => w.num(t.tm_min as i64, 2, true),
            b'S' => w.num(t.tm_sec as i64, 2, true),
            b'j' => w.num(t.tm_yday as i64 + 1, 3, true),
            b'p' => w.puts(if t.tm_hour < 12 { b"AM" } else { b"PM" }),
            b'P' => w.puts(if t.tm_hour < 12 { b"am" } else { b"pm" }),
            b'a' => w.puts(ABDAY[wd]),
            b'A' => w.puts(DAY[wd]),
            b'b' | b'h' => w.puts(ABMON[mo]),
            b'B' => w.puts(MON[mo]),
            b'u' => w.num(if wd == 0 { 7 } else { wd } as i64, 0, false),
            b'w' => w.num(wd as i64, 0, false),
            b'U' => w.num((t.tm_yday as i64 + 7 - wd as i64).div_euclid(7), 2, true),
            b'W' => w.num((t.tm_yday as i64 + 7 - (wd as i64 + 6).rem_euclid(7)).div_euclid(7), 2, true),
            b'V' => w.num(iso_week(t).1, 2, true),
            b'G' => w.num(iso_week(t).0, 0, false),
            b'g' => w.num(iso_week(t).0.rem_euclid(100), 2, true),
            b'F' => emit(w, b"%Y-%m-%d", t),
            b'T' | b'X' => emit(w, b"%H:%M:%S", t),
            b'R' => emit(w, b"%H:%M", t),
            b'r' => emit(w, b"%I:%M:%S %p", t),
            b'D' | b'x' => emit(w, b"%m/%d/%y", t),
            b'c' => emit(w, b"%a %b %e %H:%M:%S %Y", t),
            b'z' => {
                let off = t.tm_gmtoff;
                w.put(if off < 0 { b'-' } else { b'+' });
                let a = off.abs();
                w.num(a / 3600, 2, true);
                w.num((a % 3600) / 60, 2, true);
            }
            b'Z' => {
                if !t.tm_zone.is_null() {
                    // SAFETY: tm_zone, when non-null, is a NUL-terminated
                    // zone abbreviation string set by gmtime/localtime.
                    unsafe { let mut k = 0; while *t.tm_zone.add(k) != 0 { w.put(*t.tm_zone.add(k)); k += 1; } }
                }
            }
            b'n' => w.put(b'\n'),
            b't' => w.put(b'\t'),
            b'%' => w.put(b'%'),
            other => { w.put(b'%'); w.put(other); }
        }
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use crate::string::len::strlen_impl;
    // # C: size_t strftime(char *s, size_t max, const char *fmt, const struct tm *tm)
    #[no_mangle]
    pub unsafe extern "C" fn strftime(s: *mut u8, max: usize, fmt: *const u8, t: *const tm) -> usize {
        // SAFETY: s is valid for `max` bytes; fmt NUL-terminated; t a valid
        // struct tm. We reserve 1 byte for the terminating NUL.
        unsafe {
            if max == 0 { return 0; }
            let fmt_s = core::slice::from_raw_parts(fmt, strlen_impl(fmt));
            let out = core::slice::from_raw_parts_mut(s, max - 1);
            match format(out, fmt_s, &*t) {
                Some(n) => { *s.add(n) = 0; n }
                None => 0,
            }
        }
    }

    // # C: size_t strftime_l(char *s, size_t max, const char *fmt, const struct tm *tm, locale_t loc)
    #[no_mangle]
    pub unsafe extern "C" fn strftime_l(s: *mut u8, max: usize, fmt: *const u8, t: *const tm, _loc: usize) -> usize {
        // SAFETY: delegates to strftime; Oxide supports only C-equivalent
        // locales, so locale_t does not change formatting.
        unsafe { strftime(s, max, fmt, t) }
    }
    // # C: size_t __strftime_l(char *s, size_t max, const char *fmt, const struct tm *tm, locale_t loc)
    #[no_mangle]
    pub unsafe extern "C" fn __strftime_l(s: *mut u8, max: usize, fmt: *const u8, t: *const tm, loc: usize) -> usize {
        // SAFETY: internal alias has the same output buffer and tm pointer contract as strftime_l.
        unsafe { strftime_l(s, max, fmt, t, loc) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tm::gmtime_into;
    use alloc::format as fmt_macro;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn strftime_matches_host(epoch in -2_000_000_000i64..2_000_000_000) {
            // build host tm, copy into ours (incl gmtoff/zone) so %z/%Z match
            // SAFETY: host gmtime_r into a local libc::tm.
            let h: libc::tm = unsafe { let mut h = core::mem::zeroed(); libc::gmtime_r(&epoch, &mut h); h };
            let mut o = tm { tm_sec:0,tm_min:0,tm_hour:0,tm_mday:0,tm_mon:0,tm_year:0,tm_wday:0,tm_yday:0,tm_isdst:0,tm_gmtoff:0,tm_zone:core::ptr::null() };
            gmtime_into(epoch, &mut o);
            o.tm_gmtoff = h.tm_gmtoff;
            o.tm_zone = h.tm_zone as *const u8;
            for f in ["%Y-%m-%d %H:%M:%S", "%a %b %e %T %Y", "%j %u %w %p %I", "%F %T %z", "%D %R %%", "%C%y", "%A, %B %d"] {
                let cf = fmt_macro!("{f}\0");
                let mut ours = [0u8; 256];
                let n = format(&mut ours[..255], f.as_bytes(), &o).unwrap();
                let mut theirs = [0u8; 256];
                // SAFETY: theirs is 256 bytes; cf NUL-terminated; h valid tm.
                let m = unsafe { libc::strftime(theirs.as_mut_ptr() as *mut _, 256, cf.as_ptr() as *const _, &h) };
                prop_assert_eq!(&ours[..n], &theirs[..m], "fmt={} epoch={}", f, epoch);
            }
        }
    }
}
