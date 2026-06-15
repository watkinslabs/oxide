// math/atrig — asin/acos/atan/atan2 (docs/59§6 G15). fdlibm rational/segment
// polynomial ports; asin/acos use math::sqrt for the |x|>0.5 reduction.
// Pure no-std; differentially tested vs host libm (≤2 ULP) + atan2 quadrant
// edge table.
#![allow(clippy::excessive_precision, clippy::approx_constant)]
use super::basic::{copysign, fabs, isinf, isnan, signbit};
use super::sqrt::sqrt;

const PIO2_HI: f64 = 1.57079632679489655800e+00;
const PIO2_LO: f64 = 6.12323399573676603587e-17;
const PIO4_HI: f64 = 7.85398163397448278999e-01;
const PI: f64 = 3.14159265358979311600e+00;
const PI_LO: f64 = 1.2246467991473531772e-16;

const PS0: f64 = 1.66666666666666657415e-01;
const PS1: f64 = -3.25565818622400915405e-01;
const PS2: f64 = 2.01212532134862925881e-01;
const PS3: f64 = -4.00555345006794114027e-02;
const PS4: f64 = 7.91534994289814532176e-04;
const PS5: f64 = 3.47933107596021167570e-05;
const QS1: f64 = -2.40339491173441421878e+00;
const QS2: f64 = 2.02094576023350569471e+00;
const QS3: f64 = -6.88283971605453293030e-01;
const QS4: f64 = 7.70381505559019352791e-02;

#[inline]
fn set_lo(x: f64, l: u32) -> f64 { f64::from_bits((x.to_bits() & 0xffff_ffff_0000_0000) | l as u64) }
#[inline]
fn pq(t: f64) -> f64 {
    let p = t * (PS0 + t * (PS1 + t * (PS2 + t * (PS3 + t * (PS4 + t * PS5)))));
    let q = 1.0 + t * (QS1 + t * (QS2 + t * (QS3 + t * QS4)));
    p / q
}

/// # C: double asin(double)
pub(crate) fn asin(x: f64) -> f64 {
    let ax = fabs(x);
    if ax >= 1.0 {
        if ax == 1.0 { return x * PIO2_HI + x * PIO2_LO; } // ±π/2
        return f64::NAN;
    }
    if ax < 0.5 {
        if ax < 1.4901161193847656e-08 { return x; }
        let z = x * x;
        return x + x * pq(z);
    }
    let w = 1.0 - ax;
    let t = w * 0.5;
    let s = sqrt(t);
    let r = pq(t);
    let res = if ax > 0.975 {
        PIO2_HI - (2.0 * (s + s * r) - PIO2_LO)
    } else {
        let wf = set_lo(s, 0);
        let c = (t - wf * wf) / (s + wf);
        let p = 2.0 * s * r - (PIO2_LO - 2.0 * c);
        let q = PIO4_HI - 2.0 * wf;
        PIO4_HI - (p - q)
    };
    if x > 0.0 { res } else { -res }
}

/// # C: double acos(double)
pub(crate) fn acos(x: f64) -> f64 {
    let ax = fabs(x);
    if ax >= 1.0 {
        if ax == 1.0 { return if x > 0.0 { 0.0 } else { PI + 2.0 * PIO2_LO }; }
        return f64::NAN;
    }
    if ax < 0.5 {
        if ax < 6.938893903907228e-18 { return PIO2_HI + PIO2_LO; }
        let z = x * x;
        return PIO2_HI - (x - (PIO2_LO - x * pq(z)));
    }
    if x < 0.0 {
        let z = (1.0 + x) * 0.5;
        let s = sqrt(z);
        let r = pq(z);
        let w = r * s - PIO2_LO;
        PI - 2.0 * (s + w)
    } else {
        let z = (1.0 - x) * 0.5;
        let s = sqrt(z);
        let df = set_lo(s, 0);
        let c = (z - df * df) / (s + df);
        let r = pq(z);
        let w = r * s + c;
        2.0 * (df + w)
    }
}

const ATAN_HI: [f64; 4] = [4.63647609000806093515e-01, 7.85398163397448278999e-01, 9.82793723247329054082e-01, 1.57079632679489655800e+00];
const ATAN_LO: [f64; 4] = [2.26987774529616870924e-17, 3.06161699786838301793e-17, 1.39033110312309984516e-17, 6.12323399573676603587e-17];
const AT: [f64; 11] = [
    3.33333333333329318027e-01, -1.99999999998764832476e-01, 1.42857142725034663711e-01,
    -1.11111104054623557880e-01, 9.09088713343650656196e-02, -7.69187620504482999495e-02,
    6.66107313738753120669e-02, -5.83357013379057348645e-02, 4.97687799461593236017e-02,
    -3.65315727442169155270e-02, 1.62858201153657823623e-02,
];

/// # C: double atan(double)
pub(crate) fn atan(x: f64) -> f64 {
    if isnan(x) { return x; }
    let xneg = signbit(x);
    let mut ax = fabs(x);
    if ax >= 7.385903388770014e+19 { // |x| >= 2^66 → ±π/2
        let r = ATAN_HI[3] + ATAN_LO[3];
        return if xneg { -r } else { r };
    }
    let id: i32;
    if ax < 0.4375 {
        if ax < 1.862645149230957e-09 { return x; }
        id = -1;
    } else if ax < 0.6875 {
        id = 0;
        ax = (2.0 * ax - 1.0) / (2.0 + ax);
    } else if ax < 1.1875 {
        id = 1;
        ax = (ax - 1.0) / (ax + 1.0);
    } else if ax < 2.4375 {
        id = 2;
        ax = (ax - 1.5) / (1.0 + 1.5 * ax);
    } else {
        id = 3;
        ax = -1.0 / ax;
    }
    let z = ax * ax;
    let w = z * z;
    let s1 = z * (AT[0] + w * (AT[2] + w * (AT[4] + w * (AT[6] + w * (AT[8] + w * AT[10])))));
    let s2 = w * (AT[1] + w * (AT[3] + w * (AT[5] + w * (AT[7] + w * AT[9]))));
    if id < 0 {
        let r = ax - ax * (s1 + s2); // ax is the original |x| here (no reduction)
        return if xneg { -r } else { r };
    }
    let i = id as usize;
    let r = ATAN_HI[i] - ((ax * (s1 + s2) - ATAN_LO[i]) - ax);
    if xneg { -r } else { r }
}

/// # C: double atan2(double y, double x)
pub(crate) fn atan2(y: f64, x: f64) -> f64 {
    if isnan(x) || isnan(y) { return x + y; }
    if isinf(x) && isinf(y) {
        let base = if signbit(x) { 3.0 * PIO4_HI } else { PIO4_HI };
        return copysign(base, y);
    }
    if isinf(x) { return if signbit(x) { copysign(PI, y) } else { copysign(0.0, y) }; }
    if isinf(y) { return copysign(PIO2_HI, y); }
    if y == 0.0 {
        return if signbit(x) { copysign(PI, y) } else { y };
    }
    if x == 0.0 { return copysign(PIO2_HI, y); }
    let z = atan(fabs(y / x));
    if !signbit(x) {
        if !signbit(y) { z } else { -z }
    } else if !signbit(y) {
        PI - (z - PI_LO)
    } else {
        (z - PI_LO) - PI
    }
}

/// # C: float asinf(float x)
pub(crate) fn asinf(x: f32) -> f32 { asin(x as f64) as f32 }
/// # C: float acosf(float x)
pub(crate) fn acosf(x: f32) -> f32 { acos(x as f64) as f32 }
/// # C: float atanf(float x)
pub(crate) fn atanf(x: f32) -> f32 { atan(x as f64) as f32 }
/// # C: float atan2f(float y, float x)
pub(crate) fn atan2f(y: f32, x: f32) -> f32 { atan2(y as f64, x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f64) -> f64 { super::$n(x) } }; }
    macro_rules! f32_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f32) -> f32 { super::$n(x) } }; }
    f64_1!(asin); f64_1!(acos); f64_1!(atan);
    f32_1!(asinf); f32_1!(acosf); f32_1!(atanf);
    #[no_mangle] pub extern "C" fn atan2(y: f64, x: f64) -> f64 { super::atan2(y, x) }
    #[no_mangle] pub extern "C" fn atan2f(y: f32, x: f32) -> f32 { super::atan2f(y, x) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" {
        fn asin(x: f64) -> f64;
        fn acos(x: f64) -> f64;
        fn atan(x: f64) -> f64;
        fn atan2(y: f64, x: f64) -> f64;
    }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn asin_acos_match_host(x in -1.0f64..1.0) {
            // SAFETY: host libm asin/acos extern calls, scalar f64 in and out, no pointers.
            let (ha, hc) = unsafe { (asin(x), acos(x)) };
            prop_assert!(ulp(super::asin(x), ha) <= 2, "asin({})", x);
            prop_assert!(ulp(super::acos(x), hc) <= 2, "acos({})", x);
        }
        #[test]
        fn atan_matches_host(x in -1e3f64..1e3) {
            // SAFETY: host libm atan extern call, scalar f64 in and out, no pointers.
            let h = unsafe { atan(x) };
            prop_assert!(ulp(super::atan(x), h) <= 2, "atan({})", x);
        }
        #[test]
        fn atan2_matches_host(y in -1e3f64..1e3, x in -1e3f64..1e3) {
            // SAFETY: host libm atan2 extern call, scalar f64 args and result, no pointers.
            let h = unsafe { atan2(y, x) };
            prop_assert!(ulp(super::atan2(y, x), h) <= 2, "atan2({},{})", y, x);
        }
    }

    #[test]
    fn edges() {
        let p2 = core::f64::consts::FRAC_PI_2;
        assert!(ulp(super::asin(1.0), p2) <= 1);
        assert!(ulp(super::asin(-1.0), -p2) <= 1);
        assert_eq!(super::acos(1.0), 0.0);
        assert!(ulp(super::acos(0.0), p2) <= 1);
        assert!(super::asin(2.0).is_nan());
        assert_eq!(super::atan2(0.0, 1.0), 0.0);
        assert!(ulp(super::atan2(1.0, 0.0), p2) <= 1);
        assert!(ulp(super::atan2(-1.0, 0.0), -p2) <= 1);
        assert!(ulp(super::atan2(0.0, -1.0), core::f64::consts::PI) <= 1);
        assert!(ulp(super::atan2(1.0, 1.0), core::f64::consts::FRAC_PI_4) <= 1);
        assert!(ulp(super::atan2(f64::INFINITY, f64::INFINITY), core::f64::consts::FRAC_PI_4) <= 1);
        assert_eq!(super::atan2(1.0, f64::INFINITY), 0.0);
    }
}
