// math/exp — exp/expf (docs/59§6 G15). fdlibm argument-reduction + degree-5
// rational core (~≤1 ULP). Differentially tested vs host libm. Pure no-std.
// exp2/expm1, log family and pow follow.
#![allow(clippy::excessive_precision)] // fdlibm's exact decimal constants
use super::basic::{fabs, isnan, scalbn, signbit};

const HALF: [f64; 2] = [0.5, -0.5];
const LN2HI: [f64; 2] = [6.93147180369123816490e-01, -6.93147180369123816490e-01];
const LN2LO: [f64; 2] = [1.90821492927058770002e-10, -1.90821492927058770002e-10];
const INVLN2: f64 = core::f64::consts::LOG2_E; // 1/ln2
const P1: f64 = 1.66666666666666019037e-01;
const P2: f64 = -2.77777777770155933842e-03;
const P3: f64 = 6.61375632143793436117e-05;
const P4: f64 = -1.65339022054652515390e-06;
const P5: f64 = 4.13813679705723846039e-08;

/// # C: double exp(double)
pub(crate) fn exp(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x > 709.782712893383973096 { return f64::INFINITY; }
    if x < -745.13321910194110842 { return 0.0; }
    let xsb = if signbit(x) { 1usize } else { 0 };
    let xabs = fabs(x);
    let (hi, lo, k): (f64, f64, i32);
    if xabs > 0.346573590279972654709 {
        // |x| > 0.5*ln2
        if xabs < 1.0397207708399179641 {
            // |x| < 1.5*ln2
            hi = x - LN2HI[xsb];
            lo = LN2LO[xsb];
            k = 1 - (xsb as i32) * 2;
        } else {
            let kk = (INVLN2 * x + HALF[xsb]) as i32;
            let t = kk as f64;
            hi = x - t * LN2HI[0];
            lo = t * LN2LO[0];
            k = kk;
        }
    } else if xabs < 3.725290298461914e-09 {
        // |x| < 2^-28: exp(x) ≈ 1 + x
        return 1.0 + x;
    } else {
        hi = x;
        lo = 0.0;
        k = 0;
    }
    let xr = hi - lo;
    let t = xr * xr;
    let c = xr - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    if k == 0 {
        1.0 - (xr * c / (c - 2.0) - xr)
    } else {
        let y = 1.0 - (lo - xr * c / (2.0 - c) - hi);
        scalbn(y, k)
    }
}

/// # C: float expf(float)
pub(crate) fn expf(x: f32) -> f32 { exp(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    #[no_mangle]
    pub extern "C" fn exp(x: f64) -> f64 { super::exp(x) }
    #[no_mangle]
    pub extern "C" fn expf(x: f32) -> f32 { super::expf(x) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" { fn exp(x: f64) -> f64; }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b { return 0; }
        if a.is_nan() && b.is_nan() { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn exp_matches_host(x in -700.0f64..700.0) {
            let ours = super::exp(x);
            // SAFETY: host libm exp() extern call, scalar f64 in/out.
            let host = unsafe { exp(x) };
            prop_assert!(ulp(ours, host) <= 2, "exp({})={} vs {} ({} ulp)", x, ours, host, ulp(ours, host));
        }
    }

    #[test]
    fn exp_edges() {
        assert_eq!(super::exp(0.0), 1.0);
        assert!(super::exp(f64::NAN).is_nan());
        assert!(super::exp(1000.0).is_infinite());
        assert_eq!(super::exp(-1000.0), 0.0);
        // e^1 within 2 ulp of the true constant
        assert!(ulp(super::exp(1.0), core::f64::consts::E) <= 2);
    }
}
