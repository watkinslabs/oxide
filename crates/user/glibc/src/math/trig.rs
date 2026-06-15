// math/trig — sin/cos/tan/sincos (docs/59§6 G15). fdlibm polynomial kernels
// on [-π/4, π/4] + a medium-range argument reduction (two-step π/2 in extended
// precision; accurate to ~1 ULP for |x| ≲ 1e6 — full Payne–Hanek for huge args
// is a noted follow-up). Pure no-std; differentially tested vs host libm.
#![allow(clippy::excessive_precision, clippy::approx_constant)]
use super::basic::{fabs, isinf, isnan};

const INV_PIO2: f64 = 6.36619772367581382433e-01; // 2/π
const PIO2_1: f64 = 1.57079632673412561417e+00;
const PIO2_1T: f64 = 6.07710050650619224932e-11;
const PIO2_2: f64 = 6.07710050630396597660e-11;
const PIO2_2T: f64 = 2.02226624879595063154e-21;
const PIO4: f64 = 7.85398163397448278999e-01;
const PIO4LO: f64 = 3.06161699786838301793e-17;

const S1: f64 = -1.66666666666666324348e-01;
const S2: f64 = 8.33333333332248946124e-03;
const S3: f64 = -1.98412698298579493134e-04;
const S4: f64 = 2.75573137070700676789e-06;
const S5: f64 = -2.50507602534068634195e-08;
const S6: f64 = 1.58969099521155010221e-10;

const C1: f64 = 4.16666666666666019037e-02;
const C2: f64 = -1.38888888888741095749e-03;
const C3: f64 = 2.48015872894767294178e-05;
const C4: f64 = -2.75573143513906633035e-07;
const C5: f64 = 2.08757232129817482790e-09;
const C6: f64 = -1.13596475577881948265e-11;

const T: [f64; 13] = [
    3.33333333333334091986e-01, 1.33333333333201242699e-01, 5.39682539762260521377e-02,
    2.18694882948595424599e-02, 8.86323982359930005737e-03, 3.59207910759131235356e-03,
    1.45620945432529025516e-03, 5.88041240820264096874e-04, 2.46463134818469906812e-04,
    7.81794442939557092300e-05, 7.14072491382608190305e-05, -1.85586374855275456654e-05,
    2.59073051863633712884e-05,
];

#[inline]
fn set_lo(x: f64, l: u32) -> f64 { f64::from_bits((x.to_bits() & 0xffff_ffff_0000_0000) | l as u64) }

// Reduce x to (n, y0, y1) with x = n·π/2 + (y0 + y1), |y0+y1| ≤ π/4.
fn rem_pio2(x: f64) -> (i32, f64, f64) {
    let fnum = (x * INV_PIO2 + if x >= 0.0 { 0.5 } else { -0.5 }) as i64 as f64;
    let n = fnum as i32;
    // two-step extended-precision subtraction of n·π/2
    let r = x - fnum * PIO2_1;
    let w = fnum * PIO2_1T;
    let t = r;
    let w2 = fnum * PIO2_2;
    let r2 = t - w2;
    let w3 = fnum * PIO2_2T - ((t - r2) - w2);
    let _ = w;
    let y0 = r2 - w3;
    let y1 = (r2 - y0) - w3;
    (n, y0, y1)
}

fn k_sin(x: f64, y: f64, iy: i32) -> f64 {
    let z = x * x;
    let w = z * z;
    let r = S2 + z * (S3 + z * S4) + z * w * (S5 + z * S6);
    let v = z * x;
    if iy == 0 { x + v * (S1 + z * r) } else { x - ((z * (0.5 * y - v * r) - y) - v * S1) }
}

fn k_cos(x: f64, y: f64) -> f64 {
    let z = x * x;
    let w = z * z;
    let r = z * (C1 + z * (C2 + z * C3)) + w * w * (C4 + z * (C5 + z * C6));
    let hz = 0.5 * z;
    let w2 = 1.0 - hz;
    w2 + (((1.0 - w2) - hz) + (z * r - x * y))
}

fn k_tan(mut x: f64, mut y: f64, iy: i32) -> f64 {
    let big = fabs(x) >= 0.6744; // |x| ~>= 0.6744 → reduce around π/4
    let xneg = x < 0.0;
    if big {
        if xneg { x = -x; y = -y; }
        let z = PIO4 - x;
        let w = PIO4LO - y;
        x = z + w;
        y = 0.0;
    }
    let z = x * x;
    let w = z * z;
    let r = T[1] + w * (T[3] + w * (T[5] + w * (T[7] + w * (T[9] + w * T[11]))));
    let v = z * (T[2] + w * (T[4] + w * (T[6] + w * (T[8] + w * (T[10] + w * T[12])))));
    let s = z * x;
    let mut rr = y + z * (s * (r + v) + y);
    rr += T[0] * s;
    let ww = x + rr;
    if big {
        let vv = iy as f64;
        let sign = if xneg { -1.0 } else { 1.0 };
        return sign * (vv - 2.0 * (x - (ww * ww / (ww + vv) - rr)));
    }
    if iy == 1 {
        ww
    } else {
        // -1/(x+rr) computed to extra precision
        let z2 = set_lo(ww, 0);
        let v2 = rr - (z2 - x);
        let a = -1.0 / ww;
        let t2 = set_lo(a, 0);
        let s2 = 1.0 + t2 * z2;
        t2 + a * (s2 + t2 * v2)
    }
}

/// # C: double sin(double)
pub(crate) fn sin(x: f64) -> f64 {
    if fabs(x) < PIO4 { return if fabs(x) < 1.4901161193847656e-08 { x } else { k_sin(x, 0.0, 0) }; }
    if isnan(x) || isinf(x) { return f64::NAN; }
    let (n, y0, y1) = rem_pio2(x);
    match n & 3 { 0 => k_sin(y0, y1, 1), 1 => k_cos(y0, y1), 2 => -k_sin(y0, y1, 1), _ => -k_cos(y0, y1) }
}

/// # C: double cos(double)
pub(crate) fn cos(x: f64) -> f64 {
    if fabs(x) < PIO4 { return if fabs(x) < 7.450580596923828e-09 { 1.0 } else { k_cos(x, 0.0) }; }
    if isnan(x) || isinf(x) { return f64::NAN; }
    let (n, y0, y1) = rem_pio2(x);
    match n & 3 { 0 => k_cos(y0, y1), 1 => -k_sin(y0, y1, 1), 2 => -k_cos(y0, y1), _ => k_sin(y0, y1, 1) }
}

/// # C: double tan(double)
pub(crate) fn tan(x: f64) -> f64 {
    if fabs(x) < PIO4 { return if fabs(x) < 3.725290298461914e-09 { x } else { k_tan(x, 0.0, 1) }; }
    if isnan(x) || isinf(x) { return f64::NAN; }
    let (n, y0, y1) = rem_pio2(x);
    k_tan(y0, y1, 1 - ((n & 1) << 1))
}

/// # C: void sincos(double, double*, double*)
pub(crate) fn sincos(x: f64) -> (f64, f64) { (sin(x), cos(x)) }

pub(crate) fn sinf(x: f32) -> f32 { sin(x as f64) as f32 }
pub(crate) fn cosf(x: f32) -> f32 { cos(x as f64) as f32 }
pub(crate) fn tanf(x: f32) -> f32 { tan(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    macro_rules! f64_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f64) -> f64 { super::$n(x) } }; }
    macro_rules! f32_1 { ($n:ident) => { #[no_mangle] pub extern "C" fn $n(x: f32) -> f32 { super::$n(x) } }; }
    f64_1!(sin); f64_1!(cos); f64_1!(tan);
    f32_1!(sinf); f32_1!(cosf); f32_1!(tanf);
    // # C: void sincos(double x, double *s, double *c)
    #[no_mangle]
    pub unsafe extern "C" fn sincos(x: f64, s: *mut f64, c: *mut f64) {
        // SAFETY: s and c are writable double out-params per sincos(3).
        let (sv, cv) = super::sincos(x);
        // SAFETY: write each non-null out-param.
        unsafe {
            if !s.is_null() { *s = sv; }
            if !c.is_null() { *c = cv; }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    extern "C" { fn sin(x: f64) -> f64; fn cos(x: f64) -> f64; fn tan(x: f64) -> f64; }
    fn ulp(a: f64, b: f64) -> u64 {
        if a == b || (a.is_nan() && b.is_nan()) { return 0; }
        ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs()
    }

    proptest! {
        #[test]
        fn trig_matches_host(x in -1e6f64..1e6) {
            // SAFETY: host libm, scalar in/out.
            let (hs, hc, ht) = unsafe { (sin(x), cos(x), tan(x)) };
            prop_assert!(ulp(super::sin(x), hs) <= 2, "sin({})", x);
            prop_assert!(ulp(super::cos(x), hc) <= 2, "cos({})", x);
            prop_assert!(ulp(super::tan(x), ht) <= 2, "tan({})", x);
        }
    }

    #[test]
    fn trig_edges() {
        assert_eq!(super::sin(0.0), 0.0);
        assert_eq!(super::cos(0.0), 1.0);
        assert_eq!(super::tan(0.0), 0.0);
        assert!(super::sin(core::f64::consts::PI).abs() < 1e-15);
        assert!(ulp(super::cos(core::f64::consts::PI), -1.0) <= 1);
        assert!(super::sin(f64::INFINITY).is_nan());
    }
}
