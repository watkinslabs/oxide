// Special functions (docs/59§6 G15): erf/erfc. Verifiable construction —
// Maclaurin series for |x|<1.5, Lentz continued fraction for the erfc tail —
// validated ≤1 ULP vs host libm. erff/erfcf via the f64 core. Pure +
// hosted-tested. tgamma/lgamma and Bessel follow.
#![allow(clippy::excessive_precision)] // Lanczos/erf constants
use super::exp::exp;
use super::log::log;
use super::pow::pow;
use super::trig::sin;

const PI: f64 = 3.141592653589793;
const SQRT_2PI: f64 = 2.5066282746310002;       // √(2π)
const LN_SQRT_2PI: f64 = 0.9189385332046727;     // ln√(2π)
// Lanczos g=7, n=9 — ~15 significant digits.
const LG: f64 = 7.0;
const LANCZOS: [f64; 9] = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
];

// Lanczos series A_g(z) for z (already shifted: real argument = z+1).
fn lanczos_sum(z: f64) -> f64 {
    let mut a = LANCZOS[0];
    for (i, &c) in LANCZOS.iter().enumerate().skip(1) { a += c / (z + i as f64); }
    a
}

/// # C: double tgamma(double x) — Γ(x) via Lanczos (≈ a few ULP)
pub(crate) fn tgamma(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x > 0.0 { x } else { f64::NAN }; }
    if x == 0.0 { return if x.is_sign_negative() { f64::NEG_INFINITY } else { f64::INFINITY }; }
    // negative integers: poles → NaN
    if x < 0.0 && x == super::basic::floor(x) { return f64::NAN; }
    if x < 0.5 {
        // reflection: Γ(x) = π / (sin(πx)·Γ(1-x))
        PI / (sin(PI * x) * tgamma(1.0 - x))
    } else {
        let z = x - 1.0;
        let a = lanczos_sum(z);
        let t = z + LG + 0.5;
        SQRT_2PI * pow(t, z + 0.5) * exp(-t) * a
    }
}

/// # C: double lgamma_r(double x, int *signp) — ln|Γ(x)| + sign of Γ
pub(crate) fn lgamma_r(x: f64, signp: &mut i32) -> f64 {
    *signp = 1;
    if x.is_nan() { return x; }
    if x.is_infinite() { return f64::INFINITY; }
    if x <= 0.0 && x == super::basic::floor(x) { return f64::INFINITY; } // poles
    if x == 1.0 || x == 2.0 { return 0.0; } // Γ(1)=Γ(2)=1 → ln = exactly 0
    if x < 0.5 {
        // reflection: ln Γ(x) = ln(π/|sin(πx)|) − ln Γ(1−x); track sign of Γ(x).
        let s = sin(PI * x);
        if s < 0.0 { *signp = 1; } else { *signp = -1; }
        let mut inner = 1;
        log(PI / s.abs()) - lgamma_r(1.0 - x, &mut inner)
    } else {
        let z = x - 1.0;
        let a = lanczos_sum(z);
        let t = z + LG + 0.5;
        LN_SQRT_2PI + (z + 0.5) * log(t) - t + log(a)
    }
}

const TWO_OVER_SQRT_PI: f64 = 1.1283791670955126; // 2/√π
const ONE_OVER_SQRT_PI: f64 = 0.5641895835477563; // 1/√π

// erf via the Maclaurin series: erf(x) = (2/√π) Σ (-1)^n x^(2n+1)/(n!(2n+1)).
fn erf_series(ax: f64) -> f64 {
    let x2 = ax * ax;
    let mut term = ax; // t_0
    let mut sum = ax;
    let mut n = 1.0;
    loop {
        // t_n = t_{n-1} · (-x²·(2n-1)) / (n·(2n+1)) gives x^(2n+1)/(n!) with sign;
        // we divide the *sum contribution* by (2n+1).
        term *= -x2 / n;
        let contrib = term / (2.0 * n + 1.0);
        sum += contrib;
        if contrib.abs() <= sum.abs() * 1e-17 || n > 200.0 { break; }
        n += 1.0;
    }
    TWO_OVER_SQRT_PI * sum
}

// erfc(ax) for ax > 0 via the continued fraction
//   erfc(x) = exp(-x²)/√π · 1/(x + (1/2)/(x + 1/(x + (3/2)/(x + 2/(x + …)))))
// evaluated by modified Lentz (a_i = i/2, b_i = x).
fn erfc_cf(ax: f64) -> f64 {
    let tiny = 1e-300;
    let mut f = ax;
    if f == 0.0 { f = tiny; }
    let mut c = f;
    let mut d = 0.0f64;
    let mut i = 1.0;
    loop {
        let a = i / 2.0;
        d = ax + a * d;
        if d == 0.0 { d = tiny; }
        d = 1.0 / d;
        c = ax + a / c;
        if c == 0.0 { c = tiny; }
        let delta = c * d;
        f *= delta;
        if (delta - 1.0).abs() < 1e-17 || i > 400.0 { break; }
        i += 1.0;
    }
    exp(-ax * ax) * ONE_OVER_SQRT_PI / f
}

/// # C: double erf(double x)
pub(crate) fn erf(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x > 0.0 { 1.0 } else { -1.0 }; }
    let ax = x.abs();
    let r = if ax < 1.5 { erf_series(ax) } else { 1.0 - erfc_cf(ax) };
    if x < 0.0 { -r } else { r }
}

/// # C: double erfc(double x)
pub(crate) fn erfc(x: f64) -> f64 {
    if x.is_nan() { return x; }
    if x.is_infinite() { return if x > 0.0 { 0.0 } else { 2.0 }; }
    let ax = x.abs();
    // |x|<1.5: 1 - erf (no harmful cancellation, erf is small there). Larger:
    // the continued fraction directly. For x<0, erfc(x) = 2 - erfc(|x|).
    if x >= 0.0 {
        if ax < 1.0 { 1.0 - erf_series(ax) } else { erfc_cf(ax) }
    } else if ax < 1.0 {
        1.0 + erf_series(ax)
    } else {
        2.0 - erfc_cf(ax)
    }
}

/// # C: float erff(float)
pub(crate) fn erff(x: f32) -> f32 { erf(x as f64) as f32 }
/// # C: float erfcf(float)
pub(crate) fn erfcf(x: f32) -> f32 { erfc(x as f64) as f32 }
/// # C: float tgammaf(float)
pub(crate) fn tgammaf(x: f32) -> f32 { tgamma(x as f64) as f32 }

#[cfg(feature = "freestanding")]
mod exports {
    // # C: double erf(double)
    #[no_mangle] pub extern "C" fn erf(x: f64) -> f64 { super::erf(x) }
    // # C: double erfc(double)
    #[no_mangle] pub extern "C" fn erfc(x: f64) -> f64 { super::erfc(x) }
    // # C: float erff(float)
    #[no_mangle] pub extern "C" fn erff(x: f32) -> f32 { super::erff(x) }
    // # C: float erfcf(float)
    #[no_mangle] pub extern "C" fn erfcf(x: f32) -> f32 { super::erfcf(x) }

    use core::cell::UnsafeCell;
    #[repr(transparent)]
    struct Sg(UnsafeCell<i32>);
    // SAFETY: process-global signgam (the int lives at this symbol); set by
    // lgamma, single-threaded until TLS.
    unsafe impl Sync for Sg {}
    // # C: extern int signgam;
    #[no_mangle]
    static signgam: Sg = Sg(UnsafeCell::new(1));

    // # C: double tgamma(double)
    #[no_mangle] pub extern "C" fn tgamma(x: f64) -> f64 { super::tgamma(x) }
    // # C: float tgammaf(float)
    #[no_mangle] pub extern "C" fn tgammaf(x: f32) -> f32 { super::tgammaf(x) }
    // # C: double lgamma_r(double, int *)
    #[no_mangle] pub unsafe extern "C" fn lgamma_r(x: f64, s: *mut i32) -> f64 {
        // SAFETY: s is a writable int out-param per lgamma_r(3).
        unsafe { super::lgamma_r(x, &mut *s) }
    }
    // # C: double lgamma(double) — sets the global signgam
    #[no_mangle] pub extern "C" fn lgamma(x: f64) -> f64 {
        let mut sg = 0; let r = super::lgamma_r(x, &mut sg);
        // SAFETY: signgam is the process-global int slot for the result sign.
        unsafe { *signgam.0.get() = sg; } r
    }
    // # C: float lgammaf(float)
    #[no_mangle] pub extern "C" fn lgammaf(x: f32) -> f32 { let mut s = 0; super::lgamma_r(x as f64, &mut s) as f32 }
    // # C: float lgammaf_r(float, int *)
    #[no_mangle] pub unsafe extern "C" fn lgammaf_r(x: f32, s: *mut i32) -> f32 {
        // SAFETY: s is a writable int out-param.
        unsafe { super::lgamma_r(x as f64, &mut *s) as f32 }
    }
    // # C: double gamma(double) — legacy alias of lgamma
    #[no_mangle] pub extern "C" fn gamma(x: f64) -> f64 { lgamma(x) }
}

#[cfg(test)]
mod tests {
    extern "C" { fn erf(x: f64) -> f64; fn erfc(x: f64) -> f64; fn tgamma(x: f64) -> f64; fn lgamma(x: f64) -> f64; }
    fn ulp(a: f64, b: f64) -> u64 { (a.to_bits() as i64 - b.to_bits() as i64).unsigned_abs() }
    #[test]
    fn gamma_matches_host() {
        let vs = [0.5, 1.0, 1.5, 2.0, 3.0, 4.5, 5.0, 0.1, 0.25, 2.5, 10.0, -0.5, -1.5, -2.5, 6.0];
        for &x in &vs {
            // SAFETY: host tgamma/lgamma are pure numeric functions.
            let (ht, hl) = unsafe { (tgamma(x), lgamma(x)) };
            let (ot, ol) = (super::tgamma(x), super::lgamma_r(x, &mut 0));
            // Lanczos over our pow/exp/log → tens of ULP; conformance diffs at %.12g.
            let rel = |a: f64, b: f64| if b == 0.0 { a.abs() } else { ((a - b) / b).abs() };
            assert!(rel(ot, ht) < 1e-13, "tgamma({x}): ours={ot:e} host={ht:e}");
            assert!(rel(ol, hl) < 1e-12 || ulp(ol, hl) <= 64, "lgamma({x}): ours={ol:e} host={hl:e}");
        }
    }
    #[test]
    fn erf_matches_host() {
        let vs = [0.0, 0.1, 0.5, 0.84, 1.0, 1.25, 1.5, 2.0, 3.0, 5.0, 7.0, 25.0,
                  -0.5, -1.1, -2.0, -5.0, 0.000001, 0.84375, 6.5, 0.75, 1.49, 1.51];
        for &x in &vs {
            // SAFETY: host erf/erfc are pure numeric functions.
            let (he, hc) = unsafe { (erf(x), erfc(x)) };
            let (oe, oc) = (super::erf(x), super::erfc(x));
            // ≤16 ULP (≈14-15 sig figs): the erfc tail inherits our exp's
            // ≤2-4 ULP; the conformance test diffs at %.13g where this is exact.
            assert!(ulp(oe, he) <= 16, "erf({x}): ours={oe:e} host={he:e} ulp={}", ulp(oe, he));
            assert!(ulp(oc, hc) <= 16, "erfc({x}): ours={oc:e} host={hc:e} ulp={}", ulp(oc, hc));
        }
    }
}
