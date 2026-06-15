// math/round — C99/C23 round-to-integer family (docs/59§6 G15). lrint/llrint
// (round per current mode, default nearest-even via the f64 core rint),
// lround/llround (round-half-away), roundeven (round-half-to-even, value-
// preserving), and the C23 fromfp/ufromfp/fromfpx/ufromfpx (round-to-integral
// with an explicit rounding-direction enum + result width). Pure no-std; the
// integer results are bit-exact vs host glibc.
use super::basic::{copysign, fabs, floor, isinf, isnan, rint, trunc};

/// # C: long lrint(double) — round to nearest-even (default FP mode), to long
pub(crate) fn lrint(x: f64) -> i64 { rint(x) as i64 }
/// # C: long long llrint(double)
pub(crate) fn llrint(x: f64) -> i64 { rint(x) as i64 }

/// # C: long lround(double) — round-half-away-from-zero, to long
pub(crate) fn lround(x: f64) -> i64 {
    // round-half-away matches C round(); convert to integer afterwards.
    let t = trunc(x);
    let r = if fabs(x - t) >= 0.5 { t + copysign(1.0, x) } else { t };
    r as i64
}
/// # C: long long llround(double)
pub(crate) fn llround(x: f64) -> i64 { lround(x) }

/// # C: double roundeven(double) — round-half-to-even, value-preserving
pub(crate) fn roundeven(x: f64) -> f64 {
    if isnan(x) || isinf(x) { return x; }
    let t = trunc(x);
    let d = fabs(x - t);
    if d < 0.5 { return t; }
    if d > 0.5 { return t + copysign(1.0, x); }
    // exactly halfway: pick the even neighbour
    let up = t + copysign(1.0, x);
    // t and up bracket x; choose the one whose integer value is even.
    if (t as i64) % 2 == 0 { t } else { up }
}

// ---- C23 fromfp/ufromfp: round x to an integer of `width` bits using the
// rounding direction `rnd`, returning the value as intmax_t/uintmax_t. The
// rounded value is clamped (saturated) to the width's range when out of range
// (glibc raises FE_INVALID and returns the boundary); non-finite saturates to
// the max. width 0 → 0; width > 64 is treated as 64. Rounding directions are
// the C23 FP_INT_* set (UPWARD=0 .. TONEAREST=4). ----
const FP_INT_UPWARD: i32 = 0; // toward +inf
const FP_INT_DOWNWARD: i32 = 1; // toward -inf
const FP_INT_TOWARDZERO: i32 = 2;
const FP_INT_TONEARESTFROMZERO: i32 = 3; // round-half-away
const FP_INT_TONEAREST: i32 = 4; // round-half-to-even

fn round_dir(x: f64, rnd: i32) -> f64 {
    match rnd {
        FP_INT_UPWARD => { let t = trunc(x); if x > 0.0 && t != x { t + 1.0 } else { t } } // ceil
        FP_INT_DOWNWARD => floor(x),
        FP_INT_TOWARDZERO => trunc(x),
        FP_INT_TONEARESTFROMZERO => { let t = trunc(x); if fabs(x - t) >= 0.5 { t + copysign(1.0, x) } else { t } }
        _ => roundeven(x), // FP_INT_TONEAREST and any unknown → nearest-even
    }
}

/// # C: intmax_t fromfp(double, int rnd, unsigned width) — signed round-to-integral
pub(crate) fn fromfp(x: f64, rnd: i32, width: u32) -> i64 {
    if width == 0 { return 0; }
    let w = width.min(64);
    // signed range: [-2^(w-1), 2^(w-1) - 1]
    let hi: i64 = if w >= 64 { i64::MAX } else { (1i64 << (w - 1)) - 1 };
    let lo: i64 = if w >= 64 { i64::MIN } else { -(1i64 << (w - 1)) };
    if isnan(x) || isinf(x) { return if isinf(x) && x < 0.0 { lo } else { hi }; }
    let r = round_dir(x, rnd);
    if r >= hi as f64 { return hi; }
    if r <= lo as f64 { return lo; }
    r as i64
}
/// # C: uintmax_t ufromfp(double, int rnd, unsigned width) — unsigned round-to-integral
pub(crate) fn ufromfp(x: f64, rnd: i32, width: u32) -> u64 {
    if width == 0 { return 0; }
    let w = width.min(64);
    let hi: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
    if isnan(x) { return hi; }
    if isinf(x) { return if x < 0.0 { 0 } else { hi }; }
    let r = round_dir(x, rnd);
    if r <= 0.0 { return 0; }
    if r >= hi as f64 { return hi; }
    r as u64
}
/// # C: intmax_t fromfpx(double, int rnd, unsigned width) — fromfp, raises "inexact"
pub(crate) fn fromfpx(x: f64, rnd: i32, width: u32) -> i64 { fromfp(x, rnd, width) }
/// # C: uintmax_t ufromfpx(double, int rnd, unsigned width) — ufromfp, raises "inexact"
pub(crate) fn ufromfpx(x: f64, rnd: i32, width: u32) -> u64 { ufromfp(x, rnd, width) }

#[cfg(feature = "freestanding")]
mod exports {
    // # C: long lrint(double); long long llrint(double)
    #[no_mangle] pub extern "C" fn lrint(x: f64) -> i64 { super::lrint(x) }
    #[no_mangle] pub extern "C" fn llrint(x: f64) -> i64 { super::llrint(x) }
    #[no_mangle] pub extern "C" fn lrintf(x: f32) -> i64 { super::lrint(x as f64) }
    #[no_mangle] pub extern "C" fn llrintf(x: f32) -> i64 { super::llrint(x as f64) }
    // # C: long lround(double); long long llround(double)
    #[no_mangle] pub extern "C" fn lround(x: f64) -> i64 { super::lround(x) }
    #[no_mangle] pub extern "C" fn llround(x: f64) -> i64 { super::llround(x) }
    #[no_mangle] pub extern "C" fn lroundf(x: f32) -> i64 { super::lround(x as f64) }
    #[no_mangle] pub extern "C" fn llroundf(x: f32) -> i64 { super::llround(x as f64) }
    // # C: double roundeven(double); float roundevenf(float)
    #[no_mangle] pub extern "C" fn roundeven(x: f64) -> f64 { super::roundeven(x) }
    #[no_mangle] pub extern "C" fn roundevenf(x: f32) -> f32 { super::roundeven(x as f64) as f32 }
    // # C: intmax_t fromfp(double, int, unsigned); intmax_t fromfpf(float, int, unsigned)
    #[no_mangle] pub extern "C" fn fromfp(x: f64, r: i32, w: u32) -> i64 { super::fromfp(x, r, w) }
    #[no_mangle] pub extern "C" fn fromfpf(x: f32, r: i32, w: u32) -> i64 { super::fromfp(x as f64, r, w) }
    // # C: intmax_t fromfpx(double, int, unsigned); intmax_t fromfpxf(float, int, unsigned)
    #[no_mangle] pub extern "C" fn fromfpx(x: f64, r: i32, w: u32) -> i64 { super::fromfpx(x, r, w) }
    #[no_mangle] pub extern "C" fn fromfpxf(x: f32, r: i32, w: u32) -> i64 { super::fromfpx(x as f64, r, w) }
    // # C: uintmax_t ufromfp(double, int, unsigned); uintmax_t ufromfpf(float, int, unsigned)
    #[no_mangle] pub extern "C" fn ufromfp(x: f64, r: i32, w: u32) -> u64 { super::ufromfp(x, r, w) }
    #[no_mangle] pub extern "C" fn ufromfpf(x: f32, r: i32, w: u32) -> u64 { super::ufromfp(x as f64, r, w) }
    // # C: uintmax_t ufromfpx(double, int, unsigned); uintmax_t ufromfpxf(float, int, unsigned)
    #[no_mangle] pub extern "C" fn ufromfpx(x: f64, r: i32, w: u32) -> u64 { super::ufromfpx(x, r, w) }
    #[no_mangle] pub extern "C" fn ufromfpxf(x: f32, r: i32, w: u32) -> u64 { super::ufromfpx(x as f64, r, w) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rounding_ties() {
        // round-half-to-even (lrint/llrint default mode, roundeven)
        assert_eq!(lrint(2.5), 2);
        assert_eq!(lrint(3.5), 4);
        assert_eq!(lrint(-2.5), -2);
        assert_eq!(lrint(0.5), 0);
        assert_eq!(roundeven(2.5), 2.0);
        assert_eq!(roundeven(3.5), 4.0);
        assert_eq!(roundeven(-0.5), 0.0);
        assert_eq!(roundeven(-1.5), -2.0);
        // round-half-away (lround/llround)
        assert_eq!(lround(2.5), 3);
        assert_eq!(lround(-2.5), -3);
        assert_eq!(lround(0.5), 1);
        assert_eq!(llround(2.5), 3);
    }
    #[test]
    fn fromfp_range() {
        // 8-bit signed: [-128,127], saturating (matches glibc)
        assert_eq!(fromfp(100.4, FP_INT_TONEAREST, 8), 100);
        assert_eq!(fromfp(200.0, FP_INT_TONEAREST, 8), 127); // clamp to max
        assert_eq!(fromfp(-200.0, FP_INT_TONEAREST, 8), -128); // clamp to min
        assert_eq!(fromfp(-128.0, FP_INT_TONEAREST, 8), -128);
        // 8-bit unsigned: [0,255], saturating
        assert_eq!(ufromfp(200.4, FP_INT_DOWNWARD, 8), 200);
        assert_eq!(ufromfp(-1.0, FP_INT_TONEAREST, 8), 0); // clamp to 0
        assert_eq!(ufromfp(300.0, FP_INT_TONEAREST, 8), 255); // clamp to max
        // rounding directions
        assert_eq!(fromfp(2.5, FP_INT_UPWARD, 16), 3);
        assert_eq!(fromfp(2.5, FP_INT_DOWNWARD, 16), 2);
        assert_eq!(fromfp(2.5, FP_INT_TOWARDZERO, 16), 2);
        assert_eq!(fromfp(2.5, FP_INT_TONEARESTFROMZERO, 16), 3);
        assert_eq!(fromfp(2.5, FP_INT_TONEAREST, 16), 2); // even
        // width 0 → 0; non-finite → boundary
        assert_eq!(fromfp(1.0, FP_INT_TONEAREST, 0), 0);
        assert_eq!(fromfp(f64::INFINITY, FP_INT_TONEAREST, 8), 127);
        assert_eq!(fromfp(f64::NEG_INFINITY, FP_INT_TONEAREST, 8), -128);
        assert_eq!(fromfp(f64::NAN, FP_INT_TONEAREST, 8), 127);
    }
}
