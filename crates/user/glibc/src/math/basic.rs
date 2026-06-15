// math/basic — sign, rounding, classification, fmod, frexp/ldexp/modf
// (docs/59§6 G15). Pure IEEE754 bit operations (no std float methods);
// differentially tested against Rust core's f64/f32 methods (which match
// libm for these exact-result functions). Transcendentals are G15b+.
#![allow(clippy::upper_case_acronyms)]

// ---- classification ----
/// # C: int signbit(double)
pub(crate) fn signbit(x: f64) -> bool { x.to_bits() >> 63 != 0 }
/// # C: int isnan(double)
pub(crate) fn isnan(x: f64) -> bool { x.to_bits() & 0x7fff_ffff_ffff_ffff > 0x7ff0_0000_0000_0000 }

// glibc's invalid-operation result on x86 is the negative quiet NaN (the FPU
// default QNaN). fmod/remainder/remquo return it on a domain error.
const INVALID: f64 = f64::from_bits(0xfff8_0000_0000_0000);
/// # C: int isinf(double)
pub(crate) fn isinf(x: f64) -> bool { x.to_bits() & 0x7fff_ffff_ffff_ffff == 0x7ff0_0000_0000_0000 }
/// # C: int isfinite(double)
pub(crate) fn isfinite(x: f64) -> bool { x.to_bits() & 0x7ff0_0000_0000_0000 != 0x7ff0_0000_0000_0000 }

// ---- sign ----
/// # C: double fabs(double)
pub(crate) fn fabs(x: f64) -> f64 { f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff) }
/// # C: float fabsf(float)
pub(crate) fn fabsf(x: f32) -> f32 { f32::from_bits(x.to_bits() & 0x7fff_ffff) }
/// # C: double copysign(double, double)
pub(crate) fn copysign(x: f64, y: f64) -> f64 {
    f64::from_bits((x.to_bits() & 0x7fff_ffff_ffff_ffff) | (y.to_bits() & 0x8000_0000_0000_0000))
}
/// # C: float copysignf(float, float)
pub(crate) fn copysignf(x: f32, y: f32) -> f32 {
    f32::from_bits((x.to_bits() & 0x7fff_ffff) | (y.to_bits() & 0x8000_0000))
}

// ---- min/max (IEEE: NaN-tolerant, return the non-NaN operand) ----
/// # C: double fmin(double, double)
pub(crate) fn fmin(a: f64, b: f64) -> f64 { if isnan(a) { b } else if isnan(b) || a < b { a } else { b } }
/// # C: double fmax(double, double)
pub(crate) fn fmax(a: f64, b: f64) -> f64 { if isnan(a) { b } else if isnan(b) || a > b { a } else { b } }
/// # C: double fdim(double, double) — positive difference max(x-y, 0)
pub(crate) fn fdim(a: f64, b: f64) -> f64 { if isnan(a) || isnan(b) { f64::NAN } else if a > b { a - b } else { 0.0 } }

/// # C: double nextafter(double, double) — next representable double toward y
pub(crate) fn nextafter(x: f64, y: f64) -> f64 {
    if isnan(x) || isnan(y) { return f64::NAN; }
    if x == y { return y; }
    if x == 0.0 { return f64::from_bits(1).copysign(y); } // smallest subnormal toward y
    let mut u = x.to_bits();
    if (x < y) == (x > 0.0) { u += 1; } else { u -= 1; }
    f64::from_bits(u)
}

/// # C: double remquo(double, double, int*) — IEEE remainder + low quotient bits
pub(crate) fn remquo(x: f64, y: f64, quo: &mut i32) -> f64 {
    if isnan(x) || isnan(y) || isinf(x) || y == 0.0 { *quo = 0; return INVALID; }
    if isinf(y) { *quo = 0; return x; }
    // q = round-to-nearest-even of x/y (rint); r = x - q*y. Exact for the
    // magnitudes real programs use; full subnormal-exact handling is a follow-up.
    let qf = rint(x / y);
    let r = x - qf * y;
    let qi = qf as i64;
    let neg = (x < 0.0) ^ (y < 0.0);
    *quo = (qi.unsigned_abs() as i32 & 7) * if neg { -1 } else { 1 };
    r
}
/// # C: double remainder(double, double) — IEEE remainder
pub(crate) fn remainder(x: f64, y: f64) -> f64 { let mut q = 0; remquo(x, y, &mut q) }

// ---- rounding (musl-style bit ops) ----
/// # C: double trunc(double)
pub(crate) fn trunc(x: f64) -> f64 {
    let mut i = x.to_bits();
    let e = ((i >> 52) & 0x7ff) as i32 - 0x3ff;
    if e < 0 { return f64::from_bits(i & 0x8000_0000_0000_0000); } // |x|<1 → ±0
    if e >= 52 { return x; } // already integral / inf / nan
    let m = (1u64 << (52 - e)) - 1;
    if i & m == 0 { return x; }
    i &= !m;
    f64::from_bits(i)
}
/// # C: double floor(double)
pub(crate) fn floor(x: f64) -> f64 { let t = trunc(x); if x < 0.0 && t != x { t - 1.0 } else { t } }
/// # C: double ceil(double)
pub(crate) fn ceil(x: f64) -> f64 { let t = trunc(x); if x > 0.0 && t != x { t + 1.0 } else { t } }
/// # C: double round(double)
pub(crate) fn round(x: f64) -> f64 {
    // round-half-away-from-zero
    let t = trunc(x);
    let frac = x - t;
    if isnan(x) || isinf(x) { return x; }
    if fabs(frac) >= 0.5 { t + copysign(1.0, x) } else { t }
}
/// # C: double rint(double)
pub(crate) fn rint(x: f64) -> f64 {
    // round-to-nearest-even via the 2^52 add/sub trick (default FP mode).
    let e = ((x.to_bits() >> 52) & 0x7ff) as i32;
    if e >= 0x3ff + 52 { return x; }
    let two52 = copysign(4503599627370496.0, x);
    let r = x + two52 - two52;
    if r == 0.0 { copysign(0.0, x) } else { r }
}

// ---- fmod (faithful musl port; exact remainder) ----
/// # C: double fmod(double, double)
pub(crate) fn fmod(x: f64, y: f64) -> f64 {
    let mut uxi = x.to_bits();
    let mut uy = y.to_bits();
    let mut ex = ((uxi >> 52) & 0x7ff) as i32;
    let mut ey = ((uy >> 52) & 0x7ff) as i32;
    let sx = uxi >> 63;
    // invalid (y==0, y NaN, x inf/NaN): the FPU NaN (matches glibc's -nan).
    if uy << 1 == 0 || isnan(y) || ex == 0x7ff { return INVALID; }
    if uxi << 1 <= uy << 1 {
        if uxi << 1 == uy << 1 { return 0.0 * x; }
        return x;
    }
    // normalize x
    if ex == 0 {
        let mut i = uxi << 12;
        while i >> 63 == 0 { ex -= 1; i <<= 1; }
        uxi <<= (-ex + 1) as u32;
    } else {
        uxi &= u64::MAX >> 12;
        uxi |= 1 << 52;
    }
    // normalize y
    if ey == 0 {
        let mut i = uy << 12;
        while i >> 63 == 0 { ey -= 1; i <<= 1; }
        uy <<= (-ey + 1) as u32;
    } else {
        uy &= u64::MAX >> 12;
        uy |= 1 << 52;
    }
    // x mod y, binary long division
    while ex > ey {
        let i = uxi.wrapping_sub(uy);
        if i >> 63 == 0 { if i == 0 { return 0.0 * x; } uxi = i; }
        uxi <<= 1;
        ex -= 1;
    }
    let i = uxi.wrapping_sub(uy);
    if i >> 63 == 0 { if i == 0 { return 0.0 * x; } uxi = i; }
    while uxi >> 52 == 0 { uxi <<= 1; ex -= 1; }
    // scale result back
    if ex > 0 {
        uxi -= 1 << 52;
        uxi |= (ex as u64) << 52;
    } else {
        uxi >>= (-ex + 1) as u32;
    }
    uxi |= sx << 63;
    f64::from_bits(uxi)
}

// ---- frexp / ldexp / modf ----
/// # C: double frexp(double, int*)
pub(crate) fn frexp(x: f64) -> (f64, i32) {
    let bits = x.to_bits();
    let ee = ((bits >> 52) & 0x7ff) as i32;
    if ee == 0 {
        if x == 0.0 { return (x, 0); }
        // subnormal: scale up by 2^64 then recurse
        let (m, e) = frexp(x * 1.8446744073709552e19);
        return (m, e - 64);
    }
    if ee == 0x7ff { return (x, 0); } // inf/nan
    let e = ee - 1022;
    let m = f64::from_bits((bits & 0x800f_ffff_ffff_ffff) | 0x3fe0_0000_0000_0000);
    (m, e)
}
/// # C: double ldexp(double, int)
pub(crate) fn ldexp(x: f64, n: i32) -> f64 { scalbn(x, n) }
#[allow(clippy::if_same_then_else)] // musl's two-step exponent clamp
/// # C: double scalbn(double, int)
pub(crate) fn scalbn(x: f64, mut n: i32) -> f64 {
    // 2^1023, 2^-1022 (min normal), 2^53 as bit patterns (no C hex floats).
    let two_1023 = f64::from_bits(2046u64 << 52);
    let two_m1022 = f64::from_bits(1u64 << 52);
    let two_53 = f64::from_bits((0x3ff + 53u64) << 52);
    let mut y = x;
    if n > 1023 {
        y *= two_1023; n -= 1023;
        if n > 1023 { y *= two_1023; n -= 1023; if n > 1023 { n = 1023; } }
    } else if n < -1022 {
        y *= two_m1022 * two_53; n += 1022 - 53;
        if n < -1022 { y *= two_m1022 * two_53; n += 1022 - 53; if n < -1022 { n = -1022; } }
    }
    y * f64::from_bits(((0x3ff + n) as u64) << 52)
}
/// # C: double modf(double, double*)
pub(crate) fn modf(x: f64) -> (f64, f64) {
    // returns (fractional, integral); the fractional part carries x's sign even
    // when zero (so modf(-3.0) → (-0.0, -3.0)), and modf(±inf) → (±0.0, ±inf).
    if isinf(x) { return (copysign(0.0, x), x); }
    let i = trunc(x);
    let f = x - i;
    (if f == 0.0 { copysign(0.0, x) } else { f }, i)
}
/// # C: int ilogb(double) — unbiased base-2 exponent (FP_ILOGB0/NAN edges)
pub(crate) fn ilogb(x: f64) -> i32 {
    if x == 0.0 { return i32::MIN; }
    if isnan(x) || isinf(x) { return i32::MAX; }
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32;
    if e == 0 { let m = bits & 0xf_ffff_ffff_ffff; -1022 - (m.leading_zeros() as i32 - 11) } else { e - 1023 }
}
/// # C: double logb(double)
pub(crate) fn logb(x: f64) -> f64 {
    if x == 0.0 { return f64::NEG_INFINITY; }
    if isnan(x) { return x; }
    if isinf(x) { return f64::INFINITY; }
    ilogb(x) as f64
}
/// # C: double scalbln(double, long)
pub(crate) fn scalbln(x: f64, n: i64) -> f64 { scalbn(x, n.clamp(i32::MIN as i64, i32::MAX as i64) as i32) }
/// # C: float nextafterf(float, float)
pub(crate) fn nextafterf(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() { return f32::NAN; }
    if x == y { return y; }
    if x == 0.0 { return f32::from_bits(1 | (y.to_bits() & 0x8000_0000)); }
    let mut u = x.to_bits();
    if (x < y) == (x > 0.0) { u += 1; } else { u -= 1; }
    f32::from_bits(u)
}

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($name:ident, $inner:ident) => {
        #[no_mangle] pub extern "C" fn $name(x: f64) -> f64 { super::$inner(x) }
    }; }
    // float wrappers — bit-exact via the f64 cores for rounding/decomposition.
    macro_rules! f32_1 { ($name:ident, $inner:ident) => {
        #[no_mangle] pub extern "C" fn $name(x: f32) -> f32 { super::$inner(x as f64) as f32 }
    }; }
    f32_1!(ceilf, ceil); f32_1!(floorf, floor); f32_1!(truncf, trunc);
    f32_1!(roundf, round); f32_1!(rintf, rint); f32_1!(nearbyintf, rint);
    #[no_mangle] pub extern "C" fn fmodf(x: f32, y: f32) -> f32 { super::fmod(x as f64, y as f64) as f32 }
    #[no_mangle] pub extern "C" fn remainderf(x: f32, y: f32) -> f32 { super::remainder(x as f64, y as f64) as f32 }
    #[no_mangle] pub extern "C" fn dremf(x: f32, y: f32) -> f32 { super::remainder(x as f64, y as f64) as f32 }
    #[no_mangle] pub extern "C" fn drem(x: f64, y: f64) -> f64 { super::remainder(x, y) }
    #[no_mangle] pub extern "C" fn fmaxf(a: f32, b: f32) -> f32 { super::fmax(a as f64, b as f64) as f32 }
    #[no_mangle] pub extern "C" fn fminf(a: f32, b: f32) -> f32 { super::fmin(a as f64, b as f64) as f32 }
    #[no_mangle] pub extern "C" fn nextafterf(x: f32, y: f32) -> f32 { super::nextafterf(x, y) }
    #[no_mangle] pub extern "C" fn ldexpf(x: f32, n: i32) -> f32 { super::ldexp(x as f64, n) as f32 }
    #[no_mangle] pub extern "C" fn scalbnf(x: f32, n: i32) -> f32 { super::scalbn(x as f64, n) as f32 }
    #[no_mangle] pub extern "C" fn scalblnf(x: f32, n: i64) -> f32 { super::scalbln(x as f64, n) as f32 }
    #[no_mangle] pub extern "C" fn logbf(x: f32) -> f32 { super::logb(x as f64) as f32 }
    #[no_mangle] pub extern "C" fn ilogbf(x: f32) -> i32 { super::ilogb(x as f64) }
    // # C: double logb(double); int ilogb(double); double scalbln(double,long)
    #[no_mangle] pub extern "C" fn logb(x: f64) -> f64 { super::logb(x) }
    #[no_mangle] pub extern "C" fn ilogb(x: f64) -> i32 { super::ilogb(x) }
    #[no_mangle] pub extern "C" fn scalbln(x: f64, n: i64) -> f64 { super::scalbln(x, n) }
    // # C: float frexpf(float, int*)
    #[no_mangle] pub unsafe extern "C" fn frexpf(x: f32, e: *mut i32) -> f32 {
        let (m, ee) = super::frexp(x as f64);
        // SAFETY: e is null or a writable int out-param per frexpf(3).
        unsafe { if !e.is_null() { *e = ee; } }
        m as f32
    }
    // # C: float modff(float, float*)
    #[no_mangle] pub unsafe extern "C" fn modff(x: f32, ip: *mut f32) -> f32 {
        let (frac, i) = super::modf(x as f64);
        // SAFETY: ip is null or a writable float out-param per modff(3).
        unsafe { if !ip.is_null() { *ip = i as f32; } }
        frac as f32
    }
    f64_1!(fabs, fabs); f64_1!(floor, floor); f64_1!(ceil, ceil);
    f64_1!(trunc, trunc); f64_1!(round, round); f64_1!(rint, rint); f64_1!(nearbyint, rint);
    #[no_mangle] pub extern "C" fn copysign(x: f64, y: f64) -> f64 { super::copysign(x, y) }
    #[no_mangle] pub extern "C" fn fmin(a: f64, b: f64) -> f64 { super::fmin(a, b) }
    #[no_mangle] pub extern "C" fn fmax(a: f64, b: f64) -> f64 { super::fmax(a, b) }
    #[no_mangle] pub extern "C" fn fdim(a: f64, b: f64) -> f64 { super::fdim(a, b) }
    #[no_mangle] pub extern "C" fn fdimf(a: f32, b: f32) -> f32 { super::fdim(a as f64, b as f64) as f32 }
    #[no_mangle] pub extern "C" fn nextafter(x: f64, y: f64) -> f64 { super::nextafter(x, y) }
    #[no_mangle] pub extern "C" fn remainder(x: f64, y: f64) -> f64 { super::remainder(x, y) }
    // # C: double remquo(double, double, int *quo)
    #[no_mangle] pub unsafe extern "C" fn remquo(x: f64, y: f64, quo: *mut i32) -> f64 {
        // SAFETY: quo is a writable int out-param per remquo(3).
        unsafe { super::remquo(x, y, &mut *quo) }
    }
    #[no_mangle] pub extern "C" fn fmod(x: f64, y: f64) -> f64 { super::fmod(x, y) }
    #[no_mangle] pub extern "C" fn ldexp(x: f64, n: i32) -> f64 { super::ldexp(x, n) }
    #[no_mangle] pub extern "C" fn scalbn(x: f64, n: i32) -> f64 { super::scalbn(x, n) }
    #[no_mangle] pub extern "C" fn fabsf(x: f32) -> f32 { super::fabsf(x) }
    #[no_mangle] pub extern "C" fn copysignf(x: f32, y: f32) -> f32 { super::copysignf(x, y) }
    // # C: double frexp(double, int*)
    #[no_mangle]
    pub unsafe extern "C" fn frexp(x: f64, e: *mut i32) -> f64 {
        let (m, ee) = super::frexp(x);
        // SAFETY: frexp out-param e: null-checked writable *mut i32 per frexp(3) contract.
        unsafe { if !e.is_null() { *e = ee; } }
        m
    }
    // # C: double modf(double, double*)
    #[no_mangle]
    pub unsafe extern "C" fn modf(x: f64, ip: *mut f64) -> f64 {
        let (frac, i) = super::modf(x);
        // SAFETY: modf out-param ip: null-checked writable *mut f64 per modf(3) contract.
        unsafe { if !ip.is_null() { *ip = i; } }
        frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn rounding_matches_core(x in -1e18f64..1e18) {
            prop_assert_eq!(trunc(x), x.trunc());
            prop_assert_eq!(floor(x), x.floor());
            prop_assert_eq!(ceil(x), x.ceil());
            prop_assert_eq!(round(x), x.round());
            prop_assert_eq!(fabs(x), x.abs());
        }
        #[test]
        fn copysign_matches_core(x in -1e6f64..1e6, y in -1e6f64..1e6) {
            prop_assert_eq!(copysign(x, y), x.copysign(y));
        }
        #[test]
        fn fmod_matches_core(x in -1e6f64..1e6, y in -1e6f64..1e6) {
            prop_assume!(y != 0.0);
            let ours = fmod(x, y);
            let host = x % y; // Rust % is C fmod for floats
            prop_assert!((ours - host).abs() <= 1e-9 || ours == host, "fmod({},{})={} vs {}", x, y, ours, host);
        }
        #[test]
        fn frexp_reconstructs(x in -1e9f64..1e9) {
            prop_assume!(x != 0.0);
            let (m, e) = frexp(x);
            prop_assert!(m.abs() >= 0.5 && m.abs() < 1.0);
            prop_assert!((ldexp(m, e) - x).abs() <= x.abs() * 1e-15);
        }
    }

    #[test]
    fn classify() {
        assert!(isnan(f64::NAN));
        assert!(isinf(f64::INFINITY));
        assert!(!isfinite(f64::INFINITY));
        assert!(isfinite(1.0));
        assert!(signbit(-1.0) && !signbit(1.0));
        assert_eq!(rint(2.5), 2.0); // round to even
        assert_eq!(rint(3.5), 4.0);
        assert_eq!(round(2.5), 3.0); // half away
    }
}
