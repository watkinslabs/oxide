// math/sqrt — sqrt/sqrtf (docs/59§6 G15). Software Newton–Raphson from a
// frexp-normalized seed; ~≤1 ULP (bit-exact correctly-rounded sqrt is a
// follow-up). Differentially tested against the host libm. Pure no-std.
use super::basic::{frexp, isinf, isnan, scalbn};

/// # C: double sqrt(double)
pub(crate) fn sqrt(x: f64) -> f64 {
    if isnan(x) { return x; }
    if x < 0.0 { return f64::NAN; } // negatives + -inf (−0.0 < 0.0 is false)
    if x == 0.0 || isinf(x) { return x; } // ±0, +inf
    let (mut m, mut e) = frexp(x); // x = m * 2^e, m ∈ [0.5, 1)
    if e & 1 != 0 { m *= 2.0; e -= 1; } // even exponent, m ∈ [0.5, 2)
    let mut y = (m + 1.0) * 0.5; // seed ∈ [0.75, 1.5]
    let mut i = 0;
    while i < 5 { y = 0.5 * (y + m / y); i += 1; } // quadratic convergence
    scalbn(y, e / 2)
}

/// # C: float sqrtf(float)
pub(crate) fn sqrtf(x: f32) -> f32 { sqrt(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    #[no_mangle]
    pub extern "C" fn sqrt(x: f64) -> f64 { super::sqrt(x) }
    #[no_mangle]
    pub extern "C" fn sqrtf(x: f32) -> f32 { super::sqrtf(x) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" { fn sqrt(x: f64) -> f64; }
    fn ulp_diff(a: f64, b: f64) -> u64 {
        if a == b { return 0; }
        let (ia, ib) = (a.to_bits() as i64, b.to_bits() as i64);
        (ia - ib).unsigned_abs()
    }

    proptest! {
        #[test]
        fn sqrt_matches_host(x in 0.0f64..1e300) {
            let ours = super::sqrt(x);
            // SAFETY: host libm sqrt, scalar in/out.
            let host = unsafe { sqrt(x) };
            prop_assert!(ulp_diff(ours, host) <= 1, "sqrt({})={} vs {} ({} ulp)", x, ours, host, ulp_diff(ours, host));
        }
    }

    #[test]
    fn sqrt_edges() {
        assert_eq!(super::sqrt(0.0), 0.0);
        assert_eq!(super::sqrt(1.0), 1.0);
        assert_eq!(super::sqrt(4.0), 2.0);
        assert!(ulp_diff(super::sqrt(2.0), 1.4142135623730951f64) <= 1);
        assert!(super::sqrt(-1.0).is_nan());
        assert!(super::sqrt(f64::INFINITY).is_infinite());
    }
}
