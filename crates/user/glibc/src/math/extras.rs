// math/extras — the remaining glibc libm extras (docs/59§6 G15):
//   exp10/pow10 (10^x), scalb (deprecated ldexp-like), significand, sincosf,
//   nextup/nextdown, the out-of-line classification symbols glibc still exports
//   (__finite/finite, the bool isinf/isnan/signbit wrappers), llogb, the C23
//   payload + total-order predicates (getpayload/setpayload[sig]/totalorder
//   [mag]/canonicalize), and nan/nanf string-payload parsing.
// double + float variants only — the `*l` long-double forms are UNSUPPORTED.
// Pure no-std; the bit-exact (classify/payload/order/round) parts match glibc
// bit-for-bit, exp10 matches the host transcendental at %.13g.
#![allow(clippy::excessive_precision, clippy::approx_constant)] // hi/lo ln10 split
use super::basic::{fabs, floor, isinf, isnan, scalbn};
use super::exp::exp;

// log2(10) and ln(10) split into hi (top ~33 bits, exactly representable) + lo
// so the argument reduction 10^x = 2^n · 10^r keeps full f64 precision.
const LOG2_10: f64 = 3.321928094887362347870319429489390175864831;
const LN10_HI: f64 = 2.302585092994045901; // hi part (exact in f64)
const LN10_LO: f64 = -2.1707562233822494859e-16; // ln(10) - LN10_HI

// 10^0 .. 10^22 are exactly representable in f64; glibc returns them exactly.
const POW10_TBL: [f64; 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
    1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
];

/// # C: double exp10(double) — 10^x (alias pow10)
pub(crate) fn exp10(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x > 308.5 { return f64::INFINITY; }
    if x < -340.0 { return 0.0; }
    // exact integer exponents: glibc returns the correctly-rounded power. Build
    // it from the exact ≤22 table in 22-decade chunks (each chunk exact, one
    // rounding per multiply) so 10^100, 10^300 round like the host.
    if x == floor(x) {
        let n = x as i32;
        let mut m = n.unsigned_abs();
        let mut acc = 1.0f64;
        while m > 22 { acc *= POW10_TBL[22]; m -= 22; }
        acc *= POW10_TBL[m as usize];
        return if n >= 0 { acc } else { 1.0 / acc };
    }
    // general: 10^x = 2^n · 10^r where n = round(x·log2 10), r = x - n/log2(10).
    // r small → 10^r = exp(r·ln10) with ln10 in two parts; scale by 2^n.
    let n = floor(x * LOG2_10 + 0.5);
    let r = x - n / LOG2_10;
    let rln10 = r * LN10_HI + r * LN10_LO;
    scalbn(exp(rln10), n as i32)
}
/// # C: float exp10f(float)
pub(crate) fn exp10f(x: f32) -> f32 { exp10(x as f64) as f32 }

/// # C: double scalb(double, double) — deprecated: x·2^n with a double exponent
pub(crate) fn scalb(x: f64, n: f64) -> f64 {
    if isnan(x) || isnan(n) { return x + n; }
    if isinf(n) {
        // scalb(x, +inf)=±inf·sign(x); scalb(x, -inf)=±0; scalb(0,inf)/scalb(inf,-inf) invalid
        if n > 0.0 { if x == 0.0 { return f64::NAN; } return x * f64::INFINITY; }
        if isinf(x) { return f64::NAN; }
        return x * 0.0;
    }
    scalbn(x, n as i32)
}

/// # C: double significand(double) — mantissa scaled into [1,2)
pub(crate) fn significand(x: f64) -> f64 {
    if x == 0.0 || isnan(x) || isinf(x) { return x; }
    // strip the exponent: significand = x / 2^ilogb(x), result in [1,2).
    let e = super::basic::ilogb(x);
    scalbn(x, -e)
}

// ---- next up / next down (C23): the adjacent representable toward ±inf ----
/// # C: double nextup(double) — next representable toward +inf
pub(crate) fn nextup(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x == f64::INFINITY { return x; }
    let b = x.to_bits();
    if x == 0.0 { return f64::from_bits(1); } // +0/-0 → smallest +subnormal
    let nb = if b >> 63 == 0 { b + 1 } else { b - 1 }; // +: up; -: toward 0
    f64::from_bits(nb)
}
/// # C: double nextdown(double) — next representable toward -inf
pub(crate) fn nextdown(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x == f64::NEG_INFINITY { return x; }
    let b = x.to_bits();
    if x == 0.0 { return f64::from_bits(1 | (1u64 << 63)); } // → smallest -subnormal
    let nb = if b >> 63 == 0 { b - 1 } else { b + 1 };
    f64::from_bits(nb)
}
fn nextupf(x: f32) -> f32 {
    if x.is_nan() || x == f32::INFINITY { return x; }
    let b = x.to_bits();
    if x == 0.0 { return f32::from_bits(1); }
    f32::from_bits(if b >> 31 == 0 { b + 1 } else { b - 1 })
}
fn nextdownf(x: f32) -> f32 {
    if x.is_nan() || x == f32::NEG_INFINITY { return x; }
    let b = x.to_bits();
    if x == 0.0 { return f32::from_bits(1 | (1u32 << 31)); }
    f32::from_bits(if b >> 31 == 0 { b - 1 } else { b + 1 })
}

/// # C: int llogb(double) — like ilogb but returns long; FP_LLOGB0/NAN edges
pub(crate) fn llogb(x: f64) -> i64 {
    if x == 0.0 { return i64::MIN; }
    if isnan(x) || isinf(x) { return i64::MAX; }
    super::basic::ilogb(x) as i64
}

// ---- C23 NaN payload + total-order predicates ----
// f64 quiet bit = bit 51; payload = mantissa bits 0..=50 (the quiet bit is not
// part of the payload). getpayload returns the payload as a double integer.
/// # C: double getpayload(const double *) — NaN payload as an integral double
pub(crate) fn getpayload(x: f64) -> f64 {
    if !isnan(x) { return -1.0; }
    (x.to_bits() & 0x0007_ffff_ffff_ffff) as f64
}
/// # C: int setpayload(double *res, double pl) — build a quiet NaN payload
pub(crate) fn setpayload(pl: f64, signaling: bool) -> (f64, i32) {
    // pl must be a non-negative integral value < 2^51 (the payload width).
    if pl < 0.0 || pl != super::basic::trunc(pl) || pl >= 2251799813685248.0 {
        return (0.0, 1); // failure: *res set to +0.0, return 1
    }
    let payload = pl as u64 & 0x0007_ffff_ffff_ffff;
    let nan = if signaling {
        // signaling: exponent all-ones, quiet bit clear, payload nonzero.
        if payload == 0 { return (0.0, 1); } // 0-payload sNaN is not representable
        0x7ff0_0000_0000_0000 | payload
    } else {
        0x7ff8_0000_0000_0000 | payload // quiet bit set
    };
    (f64::from_bits(nan), 0)
}

// Map a double to a sign-magnitude-ordered i64 key for the total order.
fn order_key(x: f64) -> i64 {
    // sign-magnitude → two's-complement monotone key: negatives flip all bits
    // below the sign, positives keep theirs. Gives -inf < -1 < -0 < +0 < +inf,
    // the IEEE totalOrder over the bit pattern (NaNs sort to the extremes).
    let b = x.to_bits() as i64;
    b ^ (((b >> 63) as u64 >> 1) as i64)
}
/// # C: int totalorder(const double *, const double *) — IEEE totalOrder
pub(crate) fn totalorder(x: f64, y: f64) -> i32 { (order_key(x) <= order_key(y)) as i32 }
/// # C: int totalordermag(const double *, const double *)
pub(crate) fn totalordermag(x: f64, y: f64) -> i32 { totalorder(fabs(x), fabs(y)) }

/// # C: double canonicalize(double *, const double *) — IEEE canonical form
pub(crate) fn canonicalize(x: f64) -> f64 { x } // all f64 bit patterns are already canonical

// ---- nan("tag") string-payload parse ----
// glibc parses the tag as the strtoull payload (decimal/hex/octal) of a quiet
// NaN, returning 0x7ff8... | (payload & mask) on a valid leading integer, else
// the default quiet NaN. Pure-byte parse — no allocation.
unsafe fn parse_payload(tag: *const u8) -> u64 {
    if tag.is_null() { return 0; }
    let mut p = tag;
    let (mut val, mut base): (u64, u64) = (0, 10);
    // SAFETY: tag is a caller-supplied C string; we read forward only until the
    // terminating NUL byte, matching strtoull's leading-integer scan contract.
    unsafe {
        let mut c = *p;
        if c == b'0' {
            let n = *p.add(1);
            if n == b'x' || n == b'X' { base = 16; p = p.add(2); c = *p; }
            else { base = 8; p = p.add(1); c = *p; }
        }
        loop {
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u64,
                b'a'..=b'f' => (c - b'a' + 10) as u64,
                b'A'..=b'F' => (c - b'A' + 10) as u64,
                _ => break,
            };
            if d >= base { break; }
            val = val.wrapping_mul(base).wrapping_add(d);
            p = p.add(1);
            c = *p;
        }
    }
    val & 0x0007_ffff_ffff_ffff
}

#[cfg(feature = "freestanding")]
mod exports {
    use crate::math::basic as b;
    use crate::math::trig::sincos;

    // # C: double exp10(double); double pow10(double) — aliases
    #[no_mangle] pub extern "C" fn exp10(x: f64) -> f64 { super::exp10(x) }
    #[no_mangle] pub extern "C" fn pow10(x: f64) -> f64 { super::exp10(x) }
    #[no_mangle] pub extern "C" fn exp10f(x: f32) -> f32 { super::exp10f(x) }
    #[no_mangle] pub extern "C" fn pow10f(x: f32) -> f32 { super::exp10f(x) }
    // # C: double scalb(double, double); float scalbf(float, float) — deprecated
    #[no_mangle] pub extern "C" fn scalb(x: f64, n: f64) -> f64 { super::scalb(x, n) }
    #[no_mangle] pub extern "C" fn scalbf(x: f32, n: f32) -> f32 { super::scalb(x as f64, n as f64) as f32 }
    // # C: double significand(double); float significandf(float)
    #[no_mangle] pub extern "C" fn significand(x: f64) -> f64 { super::significand(x) }
    #[no_mangle] pub extern "C" fn significandf(x: f32) -> f32 { super::significand(x as f64) as f32 }
    // # C: void sincosf(float, float *, float *)
    #[no_mangle] pub unsafe extern "C" fn sincosf(x: f32, s: *mut f32, c: *mut f32) {
        let (sv, cv) = sincos(x as f64);
        // SAFETY: s and c are writable float out-params per sincosf(3); null-checked.
        unsafe {
            if !s.is_null() { *s = sv as f32; }
            if !c.is_null() { *c = cv as f32; }
        }
    }
    // # C: double nextup(double)/nextdown(double); float nextupf/nextdownf
    #[no_mangle] pub extern "C" fn nextup(x: f64) -> f64 { super::nextup(x) }
    #[no_mangle] pub extern "C" fn nextdown(x: f64) -> f64 { super::nextdown(x) }
    #[no_mangle] pub extern "C" fn nextupf(x: f32) -> f32 { super::nextupf(x) }
    #[no_mangle] pub extern "C" fn nextdownf(x: f32) -> f32 { super::nextdownf(x) }
    // # C: int llogb(double); int llogbf(float)
    #[no_mangle] pub extern "C" fn llogb(x: f64) -> i64 { super::llogb(x) }
    #[no_mangle] pub extern "C" fn llogbf(x: f32) -> i64 { super::llogb(x as f64) }

    // ---- out-of-line classification symbols glibc exports (headers use macros) ----
    // # C: int isinf(double) — glibc returns ±1 by sign; float form
    #[no_mangle] pub extern "C" fn isinf(x: f64) -> i32 { if b::isinf(x) { if b::signbit(x) { -1 } else { 1 } } else { 0 } }
    #[no_mangle] pub extern "C" fn isinff(x: f32) -> i32 { isinf(x as f64) }
    // # C: int isnan(double); int isnanf(float)
    #[no_mangle] pub extern "C" fn isnan(x: f64) -> i32 { b::isnan(x) as i32 }
    #[no_mangle] pub extern "C" fn isnanf(x: f32) -> i32 { b::isnan(x as f64) as i32 }
    // # C: int signbit(double)
    #[no_mangle] pub extern "C" fn signbit(x: f64) -> i32 { b::signbit(x) as i32 }
    // # C: int finite(double)/finitef(float) — legacy finite predicates
    #[no_mangle] pub extern "C" fn finite(x: f64) -> i32 { b::isfinite(x) as i32 }
    #[no_mangle] pub extern "C" fn finitef(x: f32) -> i32 { b::isfinite(x as f64) as i32 }
    // # C: int __fpclassify(double) — FP_NAN0/INF1/ZERO2/SUBNORMAL3/NORMAL4
    #[no_mangle] pub extern "C" fn __fpclassify(x: f64) -> i32 {
        let bits = x.to_bits(); let exp = (bits >> 52) & 0x7ff; let man = bits & 0xf_ffff_ffff_ffff;
        if exp == 0x7ff { if man == 0 { 1 } else { 0 } }          // INF : NAN
        else if exp == 0 { if man == 0 { 2 } else { 3 } }         // ZERO : SUBNORMAL
        else { 4 }                                                 // NORMAL
    }
    // # C: int __fpclassifyf(float)
    #[no_mangle] pub extern "C" fn __fpclassifyf(x: f32) -> i32 {
        let bits = x.to_bits(); let exp = (bits >> 23) & 0xff; let man = bits & 0x7f_ffff;
        if exp == 0xff { if man == 0 { 1 } else { 0 } }
        else if exp == 0 { if man == 0 { 2 } else { 3 } }
        else { 4 }
    }

    // ---- C23 payload + total-order (glibc takes pointers) ----
    // # C: double getpayload(const double *); float getpayloadf(const float *)
    #[no_mangle] pub unsafe extern "C" fn getpayload(x: *const f64) -> f64 {
        // SAFETY: x is a readable pointer to the double whose NaN payload is read.
        super::getpayload(unsafe { *x })
    }
    #[no_mangle] pub unsafe extern "C" fn getpayloadf(x: *const f32) -> f32 {
        // SAFETY: x is a readable pointer to the float whose NaN payload is read.
        let v = unsafe { *x };
        if !v.is_nan() { return -1.0; }
        (v.to_bits() & 0x003f_ffff) as f32
    }
    // # C: int setpayload(double *res, double pl)
    #[no_mangle] pub unsafe extern "C" fn setpayload(res: *mut f64, pl: f64) -> i32 {
        let (v, rc) = super::setpayload(pl, false);
        // SAFETY: res is a writable double out-param per setpayload(3).
        unsafe { *res = v; }
        rc
    }
    // # C: int setpayloadf(float *res, float pl)
    #[no_mangle] pub unsafe extern "C" fn setpayloadf(res: *mut f32, pl: f32) -> i32 {
        let (v, rc) = setpayload_f32(pl, false);
        // SAFETY: res is a writable float out-param per setpayloadf(3).
        unsafe { *res = v; }
        rc
    }
    // # C: int setpayloadsig(double *res, double pl)
    #[no_mangle] pub unsafe extern "C" fn setpayloadsig(res: *mut f64, pl: f64) -> i32 {
        let (v, rc) = super::setpayload(pl, true);
        // SAFETY: res is a writable double out-param per setpayloadsig(3).
        unsafe { *res = v; }
        rc
    }
    // # C: int setpayloadsigf(float *res, float pl)
    #[no_mangle] pub unsafe extern "C" fn setpayloadsigf(res: *mut f32, pl: f32) -> i32 {
        let (v, rc) = setpayload_f32(pl, true);
        // SAFETY: res is a writable float out-param per setpayloadsigf(3).
        unsafe { *res = v; }
        rc
    }
    // f32 payload mask = bits 0..=21; quiet bit = bit 22.
    fn setpayload_f32(pl: f32, signaling: bool) -> (f32, i32) {
        // truncate via the f64 core (no_std f32 has no .trunc()); must be a
        // non-negative integral value below 2^22.
        if pl < 0.0 || pl as f64 != crate::math::basic::trunc(pl as f64) || pl >= 4194304.0 { return (0.0, 1); }
        let payload = pl as u32 & 0x003f_ffff;
        let bits = if signaling {
            if payload == 0 { return (0.0, 1); }
            0x7f80_0000 | payload
        } else { 0x7fc0_0000 | payload };
        (f32::from_bits(bits), 0)
    }
    // # C: int totalorder(const double *, const double *); ...mag; float forms
    #[no_mangle] pub unsafe extern "C" fn totalorder(x: *const f64, y: *const f64) -> i32 {
        // SAFETY: x and y are readable pointers to the two doubles being ordered.
        super::totalorder(unsafe { *x }, unsafe { *y })
    }
    #[no_mangle] pub unsafe extern "C" fn totalordermag(x: *const f64, y: *const f64) -> i32 {
        // SAFETY: x and y are readable pointers to the two doubles being ordered.
        super::totalordermag(unsafe { *x }, unsafe { *y })
    }
    fn order_key_f32(x: f32) -> i32 { let b = x.to_bits() as i32; b ^ (((b >> 31) as u32 >> 1) as i32) }
    #[no_mangle] pub unsafe extern "C" fn totalorderf(x: *const f32, y: *const f32) -> i32 {
        // SAFETY: x and y are readable pointers to the two floats being ordered.
        let (a, b) = unsafe { (*x, *y) };
        (order_key_f32(a) <= order_key_f32(b)) as i32
    }
    #[no_mangle] pub unsafe extern "C" fn totalordermagf(x: *const f32, y: *const f32) -> i32 {
        // SAFETY: x and y are readable pointers to the two floats being ordered.
        let (a, b) = unsafe { (*x, *y) };
        (order_key_f32(a.abs()) <= order_key_f32(b.abs())) as i32
    }
    // # C: int canonicalize(double *, const double *); float form
    #[no_mangle] pub unsafe extern "C" fn canonicalize(cx: *mut f64, x: *const f64) -> i32 {
        // SAFETY: x is readable, cx is a writable double out-param per canonicalize(3).
        unsafe { *cx = super::canonicalize(*x); }
        0
    }
    #[no_mangle] pub unsafe extern "C" fn canonicalizef(cx: *mut f32, x: *const f32) -> i32 {
        // SAFETY: x is readable, cx is a writable float out-param per canonicalizef(3).
        unsafe { *cx = *x; }
        0
    }
    // # C: double nan(const char *tagp); float nanf(const char *tagp)
    #[no_mangle] pub unsafe extern "C" fn nan(tag: *const u8) -> f64 {
        // SAFETY: tag is a caller C string read forward to NUL by parse_payload.
        let pl = unsafe { super::parse_payload(tag) };
        f64::from_bits(0x7ff8_0000_0000_0000 | pl)
    }
    #[no_mangle] pub unsafe extern "C" fn nanf(tag: *const u8) -> f32 {
        // SAFETY: tag is a caller C string read forward to NUL by parse_payload.
        let pl = (unsafe { super::parse_payload(tag) } as u32) & 0x003f_ffff;
        f32::from_bits(0x7fc0_0000 | pl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }
    extern "C" { fn exp10(x: f64) -> f64; }

    #[test]
    fn exp10_matches_host() {
        // ≤16 ULP: 10^r·2^n inherits exp()'s ≤2 ULP plus the reduction; the
        // conformance test diffs at %.13g where this rounds identically.
        for &x in &[0.0, 1.0, 2.0, 3.0, -1.0, 0.5, -2.5, 7.3, -7.3, 100.0, -100.0, 1.5, 300.0] {
            // SAFETY: host libm exp10() extern call, scalar f64 in/out.
            let h = unsafe { exp10(x) };
            assert!(ulp(super::exp10(x), h) <= 16, "exp10({x}) ours={} host={h}", super::exp10(x));
        }
    }
    #[test]
    fn nextup_down() {
        assert_eq!(nextup(0.0).to_bits(), 1);
        assert_eq!(nextdown(0.0).to_bits(), 1u64 << 63 | 1);
        assert!(nextup(1.0) > 1.0 && nextdown(1.0) < 1.0);
        assert_eq!(nextdown(nextup(1.0)), 1.0);
        assert!(nextup(f64::INFINITY).is_infinite());
    }
    #[test]
    fn payload_order() {
        let (v, rc) = setpayload(4660.0, false); // 0x1234
        assert_eq!(rc, 0);
        assert!(v.is_nan());
        assert_eq!(getpayload(v), 4660.0);
        // total order: -inf < -1 < -0 < +0 < 1 < +inf
        assert_eq!(totalorder(f64::NEG_INFINITY, 1.0), 1);
        assert_eq!(totalorder(1.0, f64::NEG_INFINITY), 0);
        assert_eq!(totalorder(-0.0, 0.0), 1); // -0 orders below +0
        assert_eq!(totalorder(0.0, -0.0), 0);
        assert_eq!(totalordermag(-5.0, 3.0), 0); // |−5| > |3|
    }
    #[test]
    fn significand_scalb() {
        assert_eq!(significand(8.0), 1.0);
        assert_eq!(significand(12.0), 1.5);
        assert_eq!(scalb(1.5, 4.0), 24.0);
        assert_eq!(llogb(8.0), 3);
        assert_eq!(llogb(0.0), i64::MIN);
    }
}
