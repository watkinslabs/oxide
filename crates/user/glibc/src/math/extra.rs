// math/extra — cbrt, hypot, asinh/acosh/atanh (docs/59§6 G15, completes libm).
// cbrt is the FreeBSD bit-hack-seed + Newton port; hypot scales the larger
// operand to dodge overflow; the inverse hyperbolics are built on log/log1p/
// sqrt. Pure no-std; differentially tested vs host libm.
#![allow(clippy::excessive_precision, clippy::approx_constant)]
use super::basic::{copysign, fabs, isinf, isnan};
use super::log::{log, log1p};
use super::sqrt::sqrt;

const B1: u32 = 715094163;
const B2: u32 = 696219795;
const P0: f64 = 1.87595182427177009643;
const P1: f64 = -1.88497979543377169875;
const P2: f64 = 1.621429720105354466140;
const P3: f64 = -0.758397934778766047437;
const P4: f64 = 0.145996192886612446982;
const LN2: f64 = core::f64::consts::LN_2;

/// # C: double cbrt(double)
pub(crate) fn cbrt(x: f64) -> f64 {
    let mut ui = x.to_bits();
    let mut hx = (ui >> 32) as u32 & 0x7fff_ffff;
    if hx >= 0x7ff00000 { return x + x; } // nan/inf
    if hx < 0x00100000 {
        ui = (x * f64::from_bits((0x3ff + 54u64) << 52)).to_bits(); // x·2^54
        hx = (ui >> 32) as u32 & 0x7fff_ffff;
        if hx == 0 { return x; } // cbrt(±0) = ±0
        hx = hx / 3 + B2;
    } else {
        hx = hx / 3 + B1;
    }
    ui &= 1u64 << 63; // keep sign
    ui |= (hx as u64) << 32;
    let mut t = f64::from_bits(ui);
    let r = (t * t) * (t / x);
    t *= (P0 + r * (P1 + r * P2)) + ((r * r) * r) * (P3 + r * P4);
    // chop t to 22 significant bits, then one Newton step to 53
    ui = t.to_bits();
    ui = (ui + 0x80000000) & 0xffff_ffff_c000_0000u64;
    t = f64::from_bits(ui);
    let s = t * t;
    let r2 = x / s;
    let w = t + t;
    let r3 = (r2 - t) / (w + r2);
    t + t * r3
}

/// # C: double hypot(double, double) — sqrt(x²+y²) without spurious over/underflow
pub(crate) fn hypot(x: f64, y: f64) -> f64 {
    if isinf(x) || isinf(y) { return f64::INFINITY; } // C99: even if the other is NaN
    if isnan(x) || isnan(y) { return f64::NAN; }
    let x = fabs(x);
    let y = fabs(y);
    let (a, b) = if x >= y { (x, y) } else { (y, x) };
    if a == 0.0 { return 0.0; }
    let r = b / a;
    a * sqrt(1.0 + r * r)
}

/// # C: double asinh(double) — log(x + sqrt(x²+1))
pub(crate) fn asinh(x: f64) -> f64 {
    if isnan(x) || isinf(x) { return x; }
    let a = fabs(x);
    let r = if a < 2.0 {
        log1p(a + a * a / (1.0 + sqrt(1.0 + a * a)))
    } else if a < 1e8 {
        log(2.0 * a + 1.0 / (sqrt(a * a + 1.0) + a))
    } else {
        log(a) + LN2
    };
    copysign(r, x)
}

/// # C: double acosh(double) — log(x + sqrt(x²-1)), x ≥ 1
pub(crate) fn acosh(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x < 1.0 { return f64::NAN; }
    if x < 2.0 {
        let t = x - 1.0;
        log1p(t + sqrt(2.0 * t + t * t))
    } else if x < 1e8 {
        log(2.0 * x - 1.0 / (x + sqrt(x * x - 1.0)))
    } else {
        log(x) + LN2
    }
}

/// # C: double atanh(double) — 0.5·log((1+x)/(1-x)), |x| ≤ 1
pub(crate) fn atanh(x: f64) -> f64 {
    if isnan(x) { return x; }
    let a = fabs(x);
    if a > 1.0 { return f64::NAN; }
    if a == 1.0 { return copysign(f64::INFINITY, x); }
    let r = if a < 0.5 {
        0.5 * log1p(2.0 * a + 2.0 * a * a / (1.0 - a))
    } else {
        0.5 * log1p(2.0 * a / (1.0 - a))
    };
    copysign(r, x)
}

/// # C: float cbrtf(float)
pub(crate) fn cbrtf(x: f32) -> f32 { cbrt(x as f64) as f32 }
/// # C: float hypotf(float, float)
pub(crate) fn hypotf(x: f32, y: f32) -> f32 { hypot(x as f64, y as f64) as f32 }
/// # C: float asinhf(float)
pub(crate) fn asinhf(x: f32) -> f32 { asinh(x as f64) as f32 }
/// # C: float acoshf(float)
pub(crate) fn acoshf(x: f32) -> f32 { acosh(x as f64) as f32 }
/// # C: float atanhf(float)
pub(crate) fn atanhf(x: f32) -> f32 { atanh(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f64) -> f64 { super::$n(x) } }; }
    macro_rules! f32_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f32) -> f32 { super::$n(x) } }; }
    f64_1!(cbrt); f64_1!(asinh); f64_1!(acosh); f64_1!(atanh);
    f32_1!(cbrtf); f32_1!(asinhf); f32_1!(acoshf); f32_1!(atanhf);
    #[no_mangle] pub extern "C" fn hypot(x: f64, y: f64) -> f64 { super::hypot(x, y) }
    #[no_mangle] pub extern "C" fn hypotf(x: f32, y: f32) -> f32 { super::hypotf(x, y) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" {
        fn cbrt(x: f64) -> f64;
        fn hypot(x: f64, y: f64) -> f64;
        fn asinh(x: f64) -> f64;
        fn acosh(x: f64) -> f64;
        fn atanh(x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn cbrt_hypot_match_host(x in -1e30f64..1e30, y in -1e30f64..1e30) {
            // SAFETY: cbrt/hypot are host libm extern "C" fns, scalar f64 args in/out, no memory access.
            let (hc, hh) = unsafe { (cbrt(x), hypot(x, y)) };
            prop_assert!(ulp(super::cbrt(x), hc) <= 2, "cbrt({})", x);
            prop_assert!(ulp(super::hypot(x, y), hh) <= 2, "hypot({},{})", x, y);
        }
        #[test]
        fn inverse_hyper_match_host(x in -1e6f64..1e6) {
            // SAFETY: asinh/atanh are host libm extern "C" fns, scalar f64 args in/out, no memory access.
            let (ha, hat) = unsafe { (asinh(x), atanh(x)) };
            prop_assert!(ulp(super::asinh(x), ha) <= 3, "asinh({})", x);
            // atanh only defined on (-1,1)
            if x.abs() < 1.0 { prop_assert!(ulp(super::atanh(x), hat) <= 3, "atanh({})", x); }
        }
        #[test]
        fn acosh_match_host(x in 1.0f64..1e6) {
            // SAFETY: acosh is a host libm extern "C" fn, scalar f64 arg in/out, no memory access.
            let h = unsafe { acosh(x) };
            prop_assert!(ulp(super::acosh(x), h) <= 3, "acosh({})", x);
        }
    }

    #[test]
    fn edges() {
        assert_eq!(super::cbrt(0.0), 0.0);
        assert_eq!(super::cbrt(-8.0), -2.0);
        assert!(ulp(super::cbrt(27.0), 3.0) <= 1);
        assert_eq!(super::hypot(3.0, 4.0), 5.0);
        assert_eq!(super::hypot(0.0, 0.0), 0.0);
        assert!(super::hypot(f64::INFINITY, f64::NAN).is_infinite());
        assert_eq!(super::asinh(0.0), 0.0);
        assert_eq!(super::acosh(1.0), 0.0);
        assert!(super::acosh(0.5).is_nan());
        assert_eq!(super::atanh(0.0), 0.0);
        assert!(super::atanh(1.0).is_infinite());
        assert!(super::atanh(2.0).is_nan());
    }
}
