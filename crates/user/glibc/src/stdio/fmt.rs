// printf format engine (docs/59§6 G6). Drives output through a `Sink`
// (counts everything, writes what fits → snprintf truncation) and reads
// arguments through `Args` (VaList in the shipped libc; a typed slice in
// the hosted oracle). Integer/string/char/pointer conversions are exact
// and differentially tested vs host snprintf; float (f/e/g) is rendered
// via core::fmt — functional but not yet bit-exact (exact dtoa is a
// follow-up G6 refinement). %n is intentionally unsupported (security).
use core::fmt::Write as _;

pub(crate) trait Sink {
    fn push(&mut self, b: u8);
    fn count(&self) -> usize; // total bytes that *would* be written
    fn push_all(&mut self, s: &[u8]) { for &b in s { self.push(b); } }
}

pub(crate) trait Args {
    // # C: read next int-promoted / widened vararg per conversion.
    unsafe fn next_i32(&mut self) -> i32;
    unsafe fn next_i64(&mut self) -> i64;
    unsafe fn next_u32(&mut self) -> u32;
    unsafe fn next_u64(&mut self) -> u64;
    unsafe fn next_ptr(&mut self) -> *const u8;
    unsafe fn next_f64(&mut self) -> f64;
}

#[derive(Clone, Copy)]
enum Len { Int, Long, LongLong, Short, Char, Size, IntMax, PtrDiff }

struct Spec { left: bool, plus: bool, space: bool, alt: bool, zero: bool, width: usize, prec: Option<usize>, len: Len, conv: u8 }

// read a decimal run; returns (value, advanced)
unsafe fn read_num(p: *const u8) -> (usize, usize) {
    // SAFETY: p points into the NUL-terminated format string; digits stop
    // at the first non-digit, always inside the string.
    unsafe {
        let mut v = 0usize; let mut i = 0usize;
        while (*p.add(i)).is_ascii_digit() { v = v * 10 + (*p.add(i) - b'0') as usize; i += 1; }
        (v, i)
    }
}

// parse one conversion starting just after '%'; returns (spec, bytes consumed)
unsafe fn parse(p: *const u8, args: &mut dyn Args) -> (Spec, usize) {
    // SAFETY: p is within the NUL-terminated format string; every branch
    // advances only over format characters that exist before the NUL.
    unsafe {
        let mut i = 0usize;
        let (mut left, mut plus, mut space, mut alt, mut zero) = (false, false, false, false, false);
        loop {
            match *p.add(i) {
                b'-' => left = true, b'+' => plus = true, b' ' => space = true,
                b'#' => alt = true, b'0' => zero = true, _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if *p.add(i) == b'*' { width = args.next_i32().max(0) as usize; i += 1; }
        else { let (w, a) = read_num(p.add(i)); width = if a > 0 { w } else { width }; i += a; }
        let mut prec = None;
        if *p.add(i) == b'.' {
            i += 1;
            if *p.add(i) == b'*' { prec = Some(args.next_i32().max(0) as usize); i += 1; }
            else { let (pv, a) = read_num(p.add(i)); prec = Some(pv); i += a; }
        }
        let len = match *p.add(i) {
            b'h' => { i += 1; if *p.add(i) == b'h' { i += 1; Len::Char } else { Len::Short } }
            b'l' => { i += 1; if *p.add(i) == b'l' { i += 1; Len::LongLong } else { Len::Long } }
            b'z' => { i += 1; Len::Size }
            b'j' => { i += 1; Len::IntMax }
            b't' => { i += 1; Len::PtrDiff }
            b'L' => { i += 1; Len::LongLong }
            _ => Len::Int,
        };
        let conv = *p.add(i); i += 1;
        (Spec { left, plus, space, alt, zero, width, prec, len, conv }, i)
    }
}

// emit `body` (already the digits/text) with sign/prefix + width padding.
fn emit(out: &mut dyn Sink, sp: &Spec, sign: &[u8], prefix: &[u8], body: &[u8]) {
    let content = sign.len() + prefix.len() + body.len();
    let pad = sp.width.saturating_sub(content);
    let zero_pad = sp.zero && !sp.left && sp.prec.is_none();
    if !sp.left && !zero_pad { for _ in 0..pad { out.push(b' '); } }
    out.push_all(sign);
    out.push_all(prefix);
    if zero_pad { for _ in 0..pad { out.push(b'0'); } }
    out.push_all(body);
    if sp.left { for _ in 0..pad { out.push(b' '); } }
}

fn fmt_uint(out: &mut dyn Sink, sp: &Spec, mut v: u64, neg: bool, base: u64, upper: bool, signed_conv: bool) {
    let mut tmp = [0u8; 24];
    let mut n = 0usize;
    let value_zero = v == 0;
    if v == 0 {
        // C: precision 0 + value 0 produces NO digits (except # octal → "0")
        if sp.prec != Some(0) { tmp[0] = b'0'; n = 1; }
    }
    while v > 0 {
        let d = (v % base) as u8;
        tmp[n] = if d < 10 { b'0' + d } else { (if upper { b'A' } else { b'a' }) + d - 10 };
        n += 1; v /= base;
    }
    let minp = sp.prec.unwrap_or(0);
    let mut zeros = minp.saturating_sub(n);
    let mut body = [0u8; 80];
    let mut bn = 0usize;
    // # octal: ensure a leading 0
    if sp.alt && base == 8 && !(n + zeros > 0 && (zeros > 0 || tmp[n - 1] == b'0')) { body[bn] = b'0'; bn += 1; }
    for _ in 0..zeros { body[bn] = b'0'; bn += 1; }
    let mut k = n;
    while k > 0 { k -= 1; body[bn] = tmp[k]; bn += 1; }
    let _ = &mut zeros;
    // sign only for signed conversions (d/i); ignored for u/o/x/X
    let sign: &[u8] = if neg { b"-" } else if signed_conv && sp.plus { b"+" } else if signed_conv && sp.space { b" " } else { b"" };
    let prefix: &[u8] = if sp.alt && base == 16 && !value_zero { if upper { b"0X" } else { b"0x" } } else { b"" };
    emit(out, sp, sign, prefix, &body[..bn]);
}

unsafe fn signed(args: &mut dyn Args, len: Len) -> i64 {
    // SAFETY: reads the int-promoted vararg, narrowing per length modifier.
    unsafe {
        match len {
            Len::Char => args.next_i32() as i8 as i64,
            Len::Short => args.next_i32() as i16 as i64,
            Len::Int => args.next_i32() as i64,
            _ => args.next_i64(),
        }
    }
}
unsafe fn unsigned(args: &mut dyn Args, len: Len) -> u64 {
    // SAFETY: reads the unsigned vararg, narrowing per length modifier.
    unsafe {
        match len {
            Len::Char => args.next_u32() as u8 as u64,
            Len::Short => args.next_u32() as u16 as u64,
            Len::Int => args.next_u32() as u64,
            _ => args.next_u64(),
        }
    }
}

struct Adapter<'a>(&'a mut dyn Sink);
impl core::fmt::Write for Adapter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.push_all(s.as_bytes()); Ok(()) }
}

// ---- positional arguments (%N$, glibc) -------------------------------------
// A buffered vararg: positional formats reference args out of order, so they
// must be pre-scanned for type, read once in index order, then formatted by
// index (you cannot index a C va_list arbitrarily).
#[derive(Clone, Copy)]
enum Val { I(i64), U(u64), F(f64), P(*const u8), None }

// Read an optional leading "<digits>$" (a 1-based arg position).
unsafe fn parse_pos(p: *const u8) -> (Option<usize>, usize) {
    // SAFETY: p is within the NUL-terminated format string.
    unsafe {
        let (n, a) = read_num(p);
        if a > 0 && *p.add(a) == b'$' { (Some(n), a + 1) } else { (None, 0) }
    }
}

// Does the format use positional specifiers anywhere?
unsafe fn is_positional(fmt: *const u8) -> bool {
    // SAFETY: walks the NUL-terminated format looking for `%<digits>$`.
    unsafe {
        let mut i = 0usize;
        loop {
            let c = *fmt.add(i);
            if c == 0 { return false; }
            if c == b'%' {
                i += 1;
                if *fmt.add(i) == b'%' { i += 1; continue; }
                let (pos, _) = parse_pos(fmt.add(i));
                if pos.is_some() { return true; }
            } else { i += 1; }
        }
    }
}

// Read one positional vararg of the type implied by (conv, len).
unsafe fn read_val(args: &mut dyn Args, conv: u8, len: Len) -> Val {
    // SAFETY: args supplies the matching vararg per the caller's promise.
    unsafe {
        match conv {
            b'd' | b'i' => Val::I(signed(args, len)),
            b'u' | b'o' | b'x' | b'X' => Val::U(unsigned(args, len)),
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => Val::F(args.next_f64()),
            b'c' => Val::I(args.next_i32() as i64),
            b's' | b'p' | b'n' => Val::P(args.next_ptr()),
            _ => Val::None,
        }
    }
}

// Emit one conversion using an already-read value (shared by the positional
// path). Mirrors the sequential conversion handlers in vformat.
#[allow(clippy::manual_c_str_literals)] // byte literal is arch-portable (c_char signedness)
unsafe fn emit_val(out: &mut dyn Sink, sp: &Spec, val: Val) {
    // SAFETY: for %s/%p, val is a valid C string / pointer per the format.
    unsafe {
        let iv = |v: Val| -> i64 { if let Val::I(x) = v { x } else { 0 } };
        let uv = |v: Val| -> u64 { if let Val::U(x) = v { x } else { 0 } };
        match sp.conv {
            b'd' | b'i' => { let v = iv(val); fmt_uint(out, sp, v.unsigned_abs(), v < 0, 10, false, true); }
            b'u' => fmt_uint(out, sp, uv(val), false, 10, false, false),
            b'o' => fmt_uint(out, sp, uv(val), false, 8, false, false),
            b'x' => fmt_uint(out, sp, uv(val), false, 16, false, false),
            b'X' => fmt_uint(out, sp, uv(val), false, 16, true, false),
            b'c' => emit(out, sp, b"", b"", &[iv(val) as u8]),
            b's' => {
                let p = if let Val::P(p) = val { p } else { b"(null)\0".as_ptr() };
                let max = sp.prec.unwrap_or(usize::MAX);
                let mut n = 0usize;
                while n < max && *p.add(n) != 0 { n += 1; }
                emit(out, sp, b"", b"", core::slice::from_raw_parts(p, n));
            }
            b'p' => {
                let p = if let Val::P(p) = val { p as usize } else { 0 };
                if p == 0 { emit(out, sp, b"", b"", b"(nil)"); }
                else { let mut s2 = Spec { alt: true, ..core_copy(sp) }; s2.conv = b'x'; fmt_uint(out, &s2, p as u64, false, 16, false, false); }
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => { if let Val::F(v) = val { fmt_float(out, sp, v); } }
            _ => { out.push(b'%'); out.push(sp.conv); }
        }
    }
}

// Two-pass positional formatter: (1) type-scan each conversion's arg index,
// (2) read positions 1..=max in order, (3) format from the value table.
unsafe fn vformat_positional(out: &mut dyn Sink, fmt: *const u8, args: &mut dyn Args) -> usize {
    // SAFETY: fmt NUL-terminated; args holds positions 1..=max in order.
    unsafe {
        let mut tys: [(u8, Len); 64] = [(0, Len::Int); 64]; // conv,len per position (0 = unused)
        let mut maxpos = 0usize;
        // Pass 1: scan types (incl positional width/prec `*N$`, which are int).
        let mut i = 0usize;
        loop {
            let c = *fmt.add(i);
            if c == 0 { break; }
            if c != b'%' { i += 1; continue; }
            i += 1;
            if *fmt.add(i) == b'%' { i += 1; continue; }
            let (pos, a) = parse_pos(fmt.add(i)); i += a;
            // flags
            while matches!(*fmt.add(i), b'-' | b'+' | b' ' | b'#' | b'0') { i += 1; }
            // width (optionally *M$)
            if *fmt.add(i) == b'*' { i += 1; let (wp, wa) = parse_pos(fmt.add(i)); if let Some(w) = wp { if w < 64 { tys[w] = (b'd', Len::Int); maxpos = maxpos.max(w); } i += wa; } }
            else { let (_, na) = read_num(fmt.add(i)); i += na; }
            // precision (optionally .*K$)
            if *fmt.add(i) == b'.' { i += 1; if *fmt.add(i) == b'*' { i += 1; let (pp, pa) = parse_pos(fmt.add(i)); if let Some(pk) = pp { if pk < 64 { tys[pk] = (b'd', Len::Int); maxpos = maxpos.max(pk); } i += pa; } } else { let (_, na) = read_num(fmt.add(i)); i += na; } }
            let len = scan_len(fmt, &mut i);
            let conv = *fmt.add(i); i += 1;
            if let Some(p) = pos { if p < 64 { tys[p] = (conv, len); maxpos = maxpos.max(p); } }
        }
        // Pass 2: read args 1..=maxpos in order.
        let mut vals: [Val; 64] = [Val::None; 64];
        for p in 1..=maxpos { let (conv, len) = tys[p]; if conv != 0 { vals[p] = read_val(args, conv, len); } }
        // Pass 3: format from the table.
        let mut i = 0usize;
        loop {
            let c = *fmt.add(i);
            if c == 0 { break; }
            if c != b'%' { out.push(c); i += 1; continue; }
            i += 1;
            if *fmt.add(i) == b'%' { out.push(b'%'); i += 1; continue; }
            let (pos, a) = parse_pos(fmt.add(i)); i += a;
            let (mut left, mut plus, mut space, mut alt, mut zero) = (false, false, false, false, false);
            loop { match *fmt.add(i) { b'-' => left = true, b'+' => plus = true, b' ' => space = true, b'#' => alt = true, b'0' => zero = true, _ => break } i += 1; }
            let mut width = 0usize;
            if *fmt.add(i) == b'*' { i += 1; let (wp, wa) = parse_pos(fmt.add(i)); i += wa; if let Some(w) = wp { width = if let Val::I(x) = vals[w] { x.max(0) as usize } else { 0 }; } }
            else { let (w, na) = read_num(fmt.add(i)); width = w; i += na; }
            let mut prec = None;
            if *fmt.add(i) == b'.' { i += 1; if *fmt.add(i) == b'*' { i += 1; let (pp, pa) = parse_pos(fmt.add(i)); i += pa; if let Some(pk) = pp { prec = Some(if let Val::I(x) = vals[pk] { x.max(0) as usize } else { 0 }); } } else { let (pv, na) = read_num(fmt.add(i)); prec = Some(pv); i += na; } }
            let len = scan_len(fmt, &mut i);
            let conv = *fmt.add(i); i += 1;
            let sp = Spec { left, plus, space, alt, zero, width, prec, len, conv };
            let val = match pos { Some(p) if p < 64 => vals[p], _ => Val::None };
            emit_val(out, &sp, val);
        }
        out.count()
    }
}

// Parse a length modifier at *i, advancing i past it.
fn scan_len(fmt: *const u8, i: &mut usize) -> Len {
    // SAFETY: fmt is NUL-terminated; only advances over present modifier bytes.
    unsafe {
        match *fmt.add(*i) {
            b'h' => { *i += 1; if *fmt.add(*i) == b'h' { *i += 1; Len::Char } else { Len::Short } }
            b'l' => { *i += 1; if *fmt.add(*i) == b'l' { *i += 1; Len::LongLong } else { Len::Long } }
            b'z' => { *i += 1; Len::Size }
            b'j' => { *i += 1; Len::IntMax }
            b't' => { *i += 1; Len::PtrDiff }
            b'L' => { *i += 1; Len::LongLong }
            _ => Len::Int,
        }
    }
}

// The engine. Returns the number of bytes that would be written.
pub(crate) unsafe fn vformat(out: &mut dyn Sink, fmt: *const u8, args: &mut dyn Args) -> usize {
    // SAFETY: fmt is a NUL-terminated format string; args supplies one
    // vararg per conversion as the caller promised. Counting is the Sink's.
    unsafe {
        if is_positional(fmt) { return vformat_positional(out, fmt, args); }
        let mut i = 0usize;
        loop {
            let c = *fmt.add(i);
            if c == 0 { break; }
            if c != b'%' { out.push(c); i += 1; continue; }
            i += 1;
            if *fmt.add(i) == b'%' { out.push(b'%'); i += 1; continue; }
            let (sp, adv) = parse(fmt.add(i), args);
            i += adv;
            match sp.conv {
                b'd' | b'i' => { let v = signed(args, sp.len); fmt_uint(out, &sp, v.unsigned_abs(), v < 0, 10, false, true); }
                b'u' => { let v = unsigned(args, sp.len); fmt_uint(out, &sp, v, false, 10, false, false); }
                b'o' => { let v = unsigned(args, sp.len); fmt_uint(out, &sp, v, false, 8, false, false); }
                b'x' => { let v = unsigned(args, sp.len); fmt_uint(out, &sp, v, false, 16, false, false); }
                b'X' => { let v = unsigned(args, sp.len); fmt_uint(out, &sp, v, false, 16, true, false); }
                b'c' => { let ch = args.next_i32() as u8; emit(out, &sp, b"", b"", &[ch]); }
                b's' => {
                    let p = args.next_ptr();
                    let max = sp.prec.unwrap_or(usize::MAX);
                    let mut n = 0usize;
                    while n < max && *p.add(n) != 0 { n += 1; }
                    emit(out, &sp, b"", b"", core::slice::from_raw_parts(p, n));
                }
                b'p' => {
                    let p = args.next_ptr() as usize;
                    if p == 0 { emit(out, &sp, b"", b"", b"(nil)"); }
                    else { let mut s2 = Spec { alt: true, ..core_copy(&sp) }; s2.conv = b'x'; fmt_uint(out, &s2, p as u64, false, 16, false, false); }
                }
                b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                    let v = args.next_f64();
                    fmt_float(out, &sp, v);
                }
                0 => break,
                other => { out.push(b'%'); out.push(other); }
            }
        }
        out.count()
    }
}

// Fixed stack buffer used to render a float magnitude before padding.
struct Buf { b: [u8; 512], n: usize }
impl Sink for Buf {
    fn push(&mut self, x: u8) { if self.n < self.b.len() { self.b[self.n] = x; self.n += 1; } }
    fn count(&self) -> usize { self.n }
}

// Decimal exponent X of a magnitude (X such that mag = d.ddd × 10^X); 0 for 0.
fn decimal_exp(mag: f64) -> i32 {
    if mag == 0.0 || !mag.is_finite() { return 0; }
    let mut b = Buf { b: [0; 512], n: 0 };
    { let mut a = Adapter(&mut b); let _ = write!(a, "{:e}", mag); } // "d.dddeN"
    let mut i = 0;
    while i < b.n && b.b[i] != b'e' { i += 1; }
    i += 1;
    let neg = i < b.n && b.b[i] == b'-';
    if neg { i += 1; }
    let mut x: i32 = 0;
    while i < b.n { x = x * 10 + (b.b[i] - b'0') as i32; i += 1; }
    if neg { -x } else { x }
}

// Strip trailing zeros (and a bare trailing '.') from body[..end] — %g without
// '#'. No-op if there is no decimal point.
fn strip_zeros(body: &mut [u8], mut end: usize) -> usize {
    if !body[..end].contains(&b'.') { return end; }
    while end > 0 && body[end - 1] == b'0' { end -= 1; }
    if end > 0 && body[end - 1] == b'.' { end -= 1; }
    end
}

// Render a float per C printf semantics: sign (or +/space flag), C-style
// exponent (e±dd, ≥2 digits) for e/E, then field-width + zero/space padding.
// f/e/g share sign+pad; only the magnitude rendering differs.
fn fmt_float(out: &mut dyn Sink, sp: &Spec, v: f64) {
    let neg = v.is_sign_negative() && !v.is_nan();
    let mag = if neg { -v } else { v };
    let upper = sp.conv == b'E' || sp.conv == b'G';
    // Decide the effective rendering: e-style vs f-style and its precision.
    // %g (C): P sig digits (default 6, min 1); use f-style iff -4 ≤ X < P where
    // X is the decimal exponent, else e-style; then strip trailing zeros.
    let is_g = sp.conv == b'g' || sp.conv == b'G';
    let (estyle, rprec) = match sp.conv {
        b'e' | b'E' => (true, sp.prec.unwrap_or(6)),
        b'g' | b'G' => {
            let p = sp.prec.unwrap_or(6).max(1);
            let x = decimal_exp(mag);
            if x >= -4 && x < p as i32 { (false, (p as i32 - 1 - x).max(0) as usize) }
            else { (true, p - 1) }
        }
        _ => (false, sp.prec.unwrap_or(6)),
    };
    let mut buf = Buf { b: [0; 512], n: 0 };
    {
        let mut a = Adapter(&mut buf);
        if estyle { let _ = write!(a, "{:.*e}", rprec, mag); }
        else { let _ = write!(a, "{:.*}", rprec, mag); }
    }
    // Rust renders the exponent as "...eN" (no sign/pad); rewrite to C "e±NN".
    // For %g, strip trailing zeros from the fraction (and a bare '.') unless '#'.
    let mut body = [0u8; 512];
    let mut bn = 0usize;
    let mut frac_end = 0usize; // index in body where the fraction (mantissa) ends
    let mut i = 0usize;
    while i < buf.n {
        let c = buf.b[i];
        if (c == b'e' || c == b'E') && estyle {
            frac_end = bn;
            if is_g && !sp.alt { bn = strip_zeros(&mut body, bn); frac_end = bn; }
            body[bn] = if upper { b'E' } else { b'e' }; bn += 1;
            i += 1;
            let esign = if i < buf.n && buf.b[i] == b'-' { i += 1; b'-' } else { b'+' };
            body[bn] = esign; bn += 1;
            let estart = i;
            while i < buf.n { body[bn] = buf.b[i]; bn += 1; i += 1; }
            if i - estart == 1 { body[bn] = body[bn - 1]; body[bn - 1] = b'0'; bn += 1; }
        } else {
            body[bn] = if upper { c.to_ascii_uppercase() } else { c }; bn += 1;
            i += 1;
        }
    }
    if is_g && !sp.alt && frac_end == 0 { bn = strip_zeros(&mut body, bn); } // f-style %g
    let sign: &[u8] = if neg { b"-" } else if sp.plus { b"+" } else if sp.space { b" " } else { b"" };
    // width padding: zero-fill (after sign) unless left-justified; floats
    // zero-pad even when a precision is set (unlike integers).
    let content = sign.len() + bn;
    let pad = sp.width.saturating_sub(content);
    if sp.left {
        out.push_all(sign); out.push_all(&body[..bn]);
        for _ in 0..pad { out.push(b' '); }
    } else if sp.zero {
        out.push_all(sign);
        for _ in 0..pad { out.push(b'0'); }
        out.push_all(&body[..bn]);
    } else {
        for _ in 0..pad { out.push(b' '); }
        out.push_all(sign); out.push_all(&body[..bn]);
    }
}

// Spec is not Copy (no derive to keep it small); shallow clone for %p.
fn core_copy(s: &Spec) -> Spec {
    Spec { left: s.left, plus: s.plus, space: s.space, alt: s.alt, zero: s.zero, width: s.width, prec: s.prec, len: s.len, conv: s.conv }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec, string::String, format};

    struct VecSink { v: Vec<u8>, total: usize }
    impl Sink for VecSink { fn push(&mut self, b: u8) { self.v.push(b); self.total += 1; } fn count(&self) -> usize { self.total } }

    enum A { I32(i32), U32(u32) }
    struct TestArgs { items: Vec<A>, i: usize }
    impl Args for TestArgs {
        unsafe fn next_i32(&mut self) -> i32 { let r = match self.items[self.i] { A::I32(x) => x, _ => panic!() }; self.i += 1; r }
        unsafe fn next_u32(&mut self) -> u32 { let r = match self.items[self.i] { A::U32(x) => x, _ => panic!() }; self.i += 1; r }
        unsafe fn next_i64(&mut self) -> i64 { 0 }
        unsafe fn next_u64(&mut self) -> u64 { 0 }
        unsafe fn next_ptr(&mut self) -> *const u8 { core::ptr::null() }
        unsafe fn next_f64(&mut self) -> f64 { 0.0 }
    }

    fn host(fmt: &str, signed: bool, v: i64) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let cf = format!("{fmt}\0");
        // SAFETY: cf is NUL-terminated; buf is 256 bytes; one int vararg matches `fmt`.
        let n = unsafe {
            if signed { libc::snprintf(buf.as_mut_ptr() as *mut _, 256, cf.as_ptr() as *const _, v as i32) }
            else { libc::snprintf(buf.as_mut_ptr() as *mut _, 256, cf.as_ptr() as *const _, v as u32) }
        };
        buf[..n as usize].to_vec()
    }

    fn ours(fmt: &str, arg: A) -> Vec<u8> {
        let cf = format!("{fmt}\0");
        let mut sink = VecSink { v: Vec::new(), total: 0 };
        let mut args = TestArgs { items: vec![arg], i: 0 };
        // SAFETY: cf is NUL-terminated; args supplies exactly one matching vararg.
        unsafe { vformat(&mut sink, cf.as_ptr(), &mut args); }
        sink.v
    }

    use proptest::prelude::*;
    fn flagset() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop_oneof![Just('-'), Just('+'), Just(' '), Just('#'), Just('0')], 0..3)
            .prop_map(|cs| cs.into_iter().collect())
    }
    proptest! {
        #[test]
        fn signed_dec_matches(flags in flagset(), width in 0usize..14, prec in prop::option::of(0usize..8), v in any::<i32>()) {
            let p = prec.map(|x| format!(".{x}")).unwrap_or_default();
            let fmt = format!("%{flags}{width}{p}d");
            prop_assert_eq!(ours(&fmt, A::I32(v)), host(&fmt, true, v as i64), "fmt={}", fmt);
        }
        #[test]
        fn unsigned_hex_matches(flags in flagset(), width in 0usize..14, prec in prop::option::of(0usize..8), v in any::<u32>(), upper in any::<bool>()) {
            let p = prec.map(|x| format!(".{x}")).unwrap_or_default();
            let conv = if upper { 'X' } else { 'x' };
            let fmt = format!("%{flags}{width}{p}{conv}");
            prop_assert_eq!(ours(&fmt, A::U32(v)), host(&fmt, false, v as i64), "fmt={}", fmt);
        }
        #[test]
        fn octal_matches(flags in flagset(), width in 0usize..14, v in any::<u32>()) {
            let fmt = format!("%{flags}{width}o");
            prop_assert_eq!(ours(&fmt, A::U32(v)), host(&fmt, false, v as i64), "fmt={}", fmt);
        }
    }
}
