// math/log — log/log2/log10/log1p (docs/59§6 G15). fdlibm log core with a
// frexp-based [√2/2, √2) reduction (~≤1 ULP); log2/log10 scale by 1/ln2,
// 1/ln10; log1p uses the (1+x)-rounding correction trick. Pure no-std,
// differentially tested vs host libm.
#![allow(clippy::excessive_precision)] // fdlibm's exact decimal constants
use super::basic::{frexp, isinf, isnan, signbit};

const LG1: f64 = 6.666666666666735130e-01;
const LG2: f64 = 3.999999999940941908e-01;
const LG3: f64 = 2.857142874366239149e-01;
const LG4: f64 = 2.222219843214978396e-01;
const LG5: f64 = 1.818357216161805012e-01;
const LG6: f64 = 1.531383769920937332e-01;
const LG7: f64 = 1.479819860511658591e-01;
const LN2_HI: f64 = 6.93147180369123816490e-01;
const LN2_LO: f64 = 1.90821492927058770002e-10;

/// # C: double log(double) — natural log
pub(crate) fn log(x: f64) -> f64 {
    if isnan(x) || (isinf(x) && !signbit(x)) { return x; } // nan, +inf
    if x < 0.0 { return f64::NAN; }
    if x == 0.0 { return f64::NEG_INFINITY; }
    // x = m * 2^e, then shift m into [√2/2, √2) so f = m-1 ∈ [-0.293, 0.414].
    let (mut m, mut e) = frexp(x); // m ∈ [0.5, 1)
    if m < core::f64::consts::FRAC_1_SQRT_2 { m *= 2.0; e -= 1; }
    let f = m - 1.0;
    let s = f / (2.0 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    let r = t2 + t1;
    let hfsq = 0.5 * f * f;
    let dk = e as f64;
    dk * LN2_HI - ((hfsq - (s * (hfsq + r) + dk * LN2_LO)) - f)
}

/// # C: double log2(double)
pub(crate) fn log2(x: f64) -> f64 {
    if x == 0.0 { return f64::NEG_INFINITY; }
    log(x) * core::f64::consts::LOG2_E
}
/// # C: double log10(double)
pub(crate) fn log10(x: f64) -> f64 {
    if x == 0.0 { return f64::NEG_INFINITY; }
    log(x) * core::f64::consts::LOG10_E
}

/// # C: double log1p(double) — log(1+x), accurate near 0
pub(crate) fn log1p(x: f64) -> f64 {
    if x == 0.0 { return x; } // ±0
    if x == -1.0 { return f64::NEG_INFINITY; }
    let u = 1.0 + x;
    if u == 1.0 {
        x // 1+x rounded to 1 → log1p(x) ≈ x
    } else if u <= 0.0 {
        f64::NAN
    } else {
        // correct for the rounding error in (1+x): log(u) * x / (u-1).
        log(u) * (x / (u - 1.0))
    }
}

/// # C: float logf(float)
pub(crate) fn logf(x: f32) -> f32 { log(x as f64) as f32 }
/// # C: float log2f(float)
pub(crate) fn log2f(x: f32) -> f32 { log2(x as f64) as f32 }
/// # C: float log10f(float)
pub(crate) fn log10f(x: f32) -> f32 { log10(x as f64) as f32 }
/// # C: float log1pf(float)
pub(crate) fn log1pf(x: f32) -> f32 { log1p(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f64) -> f64 { super::$n(x) } }; }
    macro_rules! f32_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f32) -> f32 { super::$n(x) } }; }
    f64_1!(log); f64_1!(log2); f64_1!(log10); f64_1!(log1p);
    f32_1!(logf); f32_1!(log2f); f32_1!(log10f); f32_1!(log1pf);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" {
        fn log(x: f64) -> f64;
        fn log2(x: f64) -> f64;
        fn log10(x: f64) -> f64;
        fn log1p(x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn log_matches_host(x in 1e-300f64..1e300) {
            // SAFETY: host libm log/log2/log10 extern calls, scalar f64 in/out.
            let (h, h2, h10) = unsafe { (log(x), log2(x), log10(x)) };
            prop_assert!(ulp(super::log(x), h) <= 2);
            prop_assert!(ulp(super::log2(x), h2) <= 4);
            prop_assert!(ulp(super::log10(x), h10) <= 4);
        }
        #[test]
        fn log1p_matches_host(x in -0.9f64..1e6) {
            // SAFETY: host libm log1p() extern call, scalar f64 in/out.
            let h = unsafe { log1p(x) };
            prop_assert!(ulp(super::log1p(x), h) <= 2, "log1p({})", x);
        }
    }

    #[test]
    fn log_edges() {
        assert_eq!(super::log(1.0), 0.0);
        assert_eq!(super::log(0.0), f64::NEG_INFINITY);
        assert!(super::log(-1.0).is_nan());
        assert!(super::log(f64::INFINITY).is_infinite());
        assert!(ulp(super::log(core::f64::consts::E), 1.0) <= 1);
        assert!(ulp(super::log2(8.0), 3.0) <= 1);
        assert!(ulp(super::log10(1000.0), 3.0) <= 2);
    }
}
