use super::*;
struct Buf { b: [u8; 512], n: usize }
impl Sink for Buf {
    fn push(&mut self, x: u8) { if self.n < self.b.len() { self.b[self.n] = x; self.n += 1; } }
    fn count(&self) -> usize { self.n }
}

// Decimal exponent X of a magnitude (X such that mag = d.ddd × 10^X); 0 for 0.
pub(super) fn decimal_exp(mag: f64) -> i32 {
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
pub(super) fn strip_zeros(body: &mut [u8], mut end: usize) -> usize {
    if !body[..end].contains(&b'.') { return end; }
    while end > 0 && body[end - 1] == b'0' { end -= 1; }
    if end > 0 && body[end - 1] == b'.' { end -= 1; }
    end
}

// sign+prefix+width emit shared by fmt_float/fmt_hexfloat. `prefix` (e.g. the
// "0x" of %a) stays attached after the sign and before any zero padding, like
// an integer prefix. zero_ok=false (inf/nan) forces space padding regardless
// of the '0' flag, per C.
pub(super) fn emit_float_body(out: &mut dyn Sink, sp: &Spec, neg: bool, prefix: &[u8], body: &[u8], zero_ok: bool) {
    let sign: &[u8] = if neg { b"-" } else if sp.plus { b"+" } else if sp.space { b" " } else { b"" };
    let pad = sp.width.saturating_sub(sign.len() + prefix.len() + body.len());
    if sp.left { out.push_all(sign); out.push_all(prefix); out.push_all(body); for _ in 0..pad { out.push(b' '); } }
    else if sp.zero && zero_ok { out.push_all(sign); out.push_all(prefix); for _ in 0..pad { out.push(b'0'); } out.push_all(body); }
    else { for _ in 0..pad { out.push(b' '); } out.push_all(sign); out.push_all(prefix); out.push_all(body); }
}

// %a/%A: C99 hexadecimal float "0x1.fracp±d" (lowercase) / "0X1.FRACP±D".
// Default precision renders the exact mantissa (13 nibbles, trailing zeros
// stripped); explicit precision rounds to nearest-even at the nibble boundary,
// carrying into the leading digit (which may become 2).
pub(super) fn fmt_hexfloat(out: &mut dyn Sink, sp: &Spec, v: f64) {
    let upper = sp.conv == b'A';
    let neg = v.is_sign_negative();
    if v.is_nan() { emit_float_body(out, sp, false, b"", if upper { b"NAN" } else { b"nan" }, false); return; }
    if v.is_infinite() { emit_float_body(out, sp, neg, b"", if upper { b"INF" } else { b"inf" }, false); return; }
    let bits = v.abs().to_bits();
    let exp_field = ((bits >> 52) & 0x7ff) as i32;
    let mant = bits & 0xf_ffff_ffff_ffff; // 52-bit fraction
    let (mut lead, ubexp, mut frac) = if exp_field == 0 {
        if mant == 0 { (0u8, 0i32, 0u64) } else { (0u8, -1022, mant) }
    } else { (1u8, exp_field - 1023, mant) };
    // round to an explicit precision (in nibbles) if given
    if let Some(p) = sp.prec {
        if p < 13 {
            let drop = 52 - 4 * p; // bits discarded
            let kept = frac >> drop;
            let rem = frac & ((1u64 << drop) - 1);
            let half = 1u64 << (drop - 1);
            let up = rem > half || (rem == half && (kept & 1) == 1);
            let mut k = kept + if up { 1 } else { 0 };
            if k >> (4 * p) != 0 { lead += 1; k = 0; } // carry into leading digit
            frac = k << drop;
        }
    }
    let digit = |nib: u64| -> u8 { if nib < 10 { b'0' + nib as u8 } else { (if upper { b'A' } else { b'a' }) + (nib - 10) as u8 } };
    let mut b = [0u8; 32];
    let mut n = 0;
    b[n] = b'0' + lead; n += 1;
    // fraction nibbles (MSB first)
    let ndig = match sp.prec {
        Some(p) => p.min(13),
        None => { let mut last = 0; for k in 0..13 { if (frac >> (48 - 4 * k)) & 0xf != 0 { last = k + 1; } } last }
    };
    if ndig > 0 {
        b[n] = b'.'; n += 1;
        for k in 0..ndig { b[n] = digit((frac >> (48 - 4 * k)) & 0xf); n += 1; }
    }
    b[n] = if upper { b'P' } else { b'p' }; n += 1;
    b[n] = if ubexp < 0 { b'-' } else { b'+' }; n += 1;
    let ae = ubexp.unsigned_abs();
    if ae >= 1000 { b[n] = b'0' + (ae / 1000 % 10) as u8; n += 1; }
    if ae >= 100 { b[n] = b'0' + (ae / 100 % 10) as u8; n += 1; }
    if ae >= 10 { b[n] = b'0' + (ae / 10 % 10) as u8; n += 1; }
    b[n] = b'0' + (ae % 10) as u8; n += 1;
    emit_float_body(out, sp, neg, if upper { b"0X" } else { b"0x" }, &b[..n], true);
}

// Render a float per C printf semantics: sign (or +/space flag), C-style
// exponent (e±dd, ≥2 digits) for e/E, then field-width + zero/space padding.
// f/e/g share sign+pad; only the magnitude rendering differs.
pub(super) fn fmt_float(out: &mut dyn Sink, sp: &Spec, v: f64) {
    let neg = v.is_sign_negative() && !v.is_nan();
    let mag = if neg { -v } else { v };
    let upper = matches!(sp.conv, b'E' | b'G' | b'F');
    // inf/nan: glibc spells them "inf"/"nan" (upper conversions "INF"/"NAN");
    // core::fmt would render "NaN". A NaN with its sign bit set prints "-nan".
    if v.is_nan() { emit_float_body(out, sp, v.is_sign_negative(), b"", if upper { b"NAN" } else { b"nan" }, false); return; }
    if v.is_infinite() { emit_float_body(out, sp, neg, b"", if upper { b"INF" } else { b"inf" }, false); return; }
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
    // '#' (alt) flag forces a radix point even when the rendering has none
    // (e.g. "%#.0f" of 1 → "1."); insert it after the mantissa's integer part.
    if sp.alt {
        let mant_end = if frac_end > 0 { frac_end } else { bn }; // e-style mantissa ends at 'e'
        if !body[..mant_end].contains(&b'.') {
            if frac_end > 0 { body.copy_within(frac_end..bn, frac_end + 1); body[frac_end] = b'.'; }
            else { body[bn] = b'.'; }
            bn += 1;
        }
    }
    // floats zero-pad even when a precision is set (unlike integers).
    emit_float_body(out, sp, neg, b"", &body[..bn], true);
}

// Spec is not Copy (no derive to keep it small); shallow clone for %p.
fn core_copy(s: &Spec) -> Spec {
    Spec { left: s.left, plus: s.plus, space: s.space, alt: s.alt, zero: s.zero, width: s.width, prec: s.prec, len: s.len, conv: s.conv }
}
