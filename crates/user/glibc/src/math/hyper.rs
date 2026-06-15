// math/hyper — expm1, exp2, sinh, cosh, tanh (docs/59§6 G15). expm1 uses the
// fdlibm primary-range polynomial near 0 (where exp(x)-1 cancels) and exp(x)-1
// elsewhere; the hyperbolics are built on exp/expm1 with overflow-safe forms.
// Pure no-std; differentially tested vs host libm.
#![allow(clippy::excessive_precision, clippy::approx_constant)]
use super::basic::{copysign, fabs, isnan, round, scalbn};
use super::exp::exp;

const Q1: f64 = -3.33333333333331316428e-02;
const Q2: f64 = 1.58730158725481460165e-03;
const Q3: f64 = -7.93650757867487942473e-05;
const Q4: f64 = 4.00821782732936239552e-06;
const Q5: f64 = -2.01099218183624371326e-07;

/// # C: double expm1(double) — e^x - 1, accurate near 0
pub(crate) fn expm1(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x == f64::INFINITY { return f64::INFINITY; }
    if x == f64::NEG_INFINITY { return -1.0; }
    if fabs(x) < 0.5 {
        if fabs(x) < 5.551115123125783e-17 { return x; } // |x| < 2^-54
        // fdlibm primary-range (k==0) core
        let hfx = 0.5 * x;
        let hxs = x * hfx;
        let r1 = 1.0 + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
        let t = 3.0 - r1 * hfx;
        let e = hxs * ((r1 - t) / (6.0 - x * t));
        x - (x * e - hxs)
    } else {
        exp(x) - 1.0
    }
}

/// # C: double exp2(double) — 2^x
pub(crate) fn exp2(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x > 1024.0 { return f64::INFINITY; }
    if x < -1075.0 { return 0.0; }
    let k = round(x);
    let r = x - k; // r ∈ [-0.5, 0.5]
    scalbn(exp(r * core::f64::consts::LN_2), k as i32)
}

/// # C: double sinh(double)
pub(crate) fn sinh(x: f64) -> f64 {
    if isnan(x) { return x; }
    0.5 * (expm1(x) - expm1(-x))
}

/// # C: double cosh(double)
pub(crate) fn cosh(x: f64) -> f64 {
    if isnan(x) { return x; }
    0.5 * (exp(x) + exp(-x))
}

/// # C: double tanh(double)
pub(crate) fn tanh(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x == 0.0 { return x; } // preserves ±0
    let u = expm1(-2.0 * fabs(x));
    copysign(-u / (2.0 + u), x)
}

pub(crate) fn expm1f(x: f32) -> f32 { expm1(x as f64) as f32 }
pub(crate) fn exp2f(x: f32) -> f32 { exp2(x as f64) as f32 }
pub(crate) fn sinhf(x: f32) -> f32 { sinh(x as f64) as f32 }
pub(crate) fn coshf(x: f32) -> f32 { cosh(x as f64) as f32 }
pub(crate) fn tanhf(x: f32) -> f32 { tanh(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f64) -> f64 { super::$n(x) } }; }
    macro_rules! f32_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f32) -> f32 { super::$n(x) } }; }
    f64_1!(expm1); f64_1!(exp2); f64_1!(sinh); f64_1!(cosh); f64_1!(tanh);
    f32_1!(expm1f); f32_1!(exp2f); f32_1!(sinhf); f32_1!(coshf); f32_1!(tanhf);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" {
        fn expm1(x: f64) -> f64;
        fn exp2(x: f64) -> f64;
        fn sinh(x: f64) -> f64;
        fn cosh(x: f64) -> f64;
        fn tanh(x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn expm1_exp2_match_host(x in -50.0f64..50.0) {
            // SAFETY: host libm, scalar in/out.
            let (he, h2) = unsafe { (expm1(x), exp2(x)) };
            prop_assert!(ulp(super::expm1(x), he) <= 3, "expm1({})", x);
            prop_assert!(ulp(super::exp2(x), h2) <= 3, "exp2({})", x);
        }
        #[test]
        fn hyper_match_host(x in -200.0f64..200.0) {
            let (hs, hc, ht) = unsafe { (sinh(x), cosh(x), tanh(x)) };
            prop_assert!(ulp(super::sinh(x), hs) <= 3, "sinh({})", x);
            prop_assert!(ulp(super::cosh(x), hc) <= 3, "cosh({})", x);
            prop_assert!(ulp(super::tanh(x), ht) <= 3, "tanh({})", x);
        }
    }

    #[test]
    fn edges() {
        assert_eq!(super::sinh(0.0), 0.0);
        assert_eq!(super::cosh(0.0), 1.0);
        assert_eq!(super::tanh(0.0), 0.0);
        assert_eq!(super::tanh(f64::INFINITY), 1.0);
        assert_eq!(super::tanh(f64::NEG_INFINITY), -1.0);
        assert_eq!(super::exp2(10.0), 1024.0);
        assert_eq!(super::expm1(0.0), 0.0);
        assert!(super::cosh(f64::INFINITY).is_infinite());
        assert!(ulp(super::expm1(1.0), core::f64::consts::E - 1.0) <= 2);
    }
}
